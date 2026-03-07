package congestion

import (
	"time"

	"github.com/quic-go/quic-go/internal/monotime"
	"github.com/quic-go/quic-go/internal/protocol"
)

var _ SendAlgorithm = (*BBRv1Sender)(nil)
var _ SendAlgorithmWithDebugInfos = (*BBRv1Sender)(nil)

type ackInfo struct {
	ackedBytes protocol.ByteCount
	recordTime time.Duration
}
type BBRv1Sender struct {
	state            int8
	round            int64
	round_start_time monotime.Time

	startup_last_bw_grow25_round int64
	startup_last_bw              protocol.ByteCount // bandwidth is when startup_last_bw_grow25_round

	pacing_gain float64
	cwnd_gain   float64

	sentTimes map[protocol.PacketNumber]monotime.Time
	// If the latest minrtt has not been updated for more than 10 seconds,
	// it indicates that the historical minrtt has also not been updated for more than 10 seconds.
	// Therefore, only the latest minrtt needs to be tracked.
	lastNewMinRTT      time.Duration
	lastNewMinRTTTime  monotime.Time
	last_probeRTTStart monotime.Time
	maxBandwidth       protocol.ByteCount // byte/s
	delivered          protocol.ByteCount // byte
	ackinfo            []ackInfo
	latelybandwidth    [bw_win]protocol.ByteCount

	nextSendTime    monotime.Time
	maxDatagramSize protocol.ByteCount
	inRecovery      bool
}

const (
	STARTUP int8 = iota
	DRAIN
	PROBE_BW
	PROBE_RTT
)
const bw_win = 16 // maxbandwidth sliding window size.
const min_bdp = 32

var probeBWCycleGain = []float64{1.25, 0.75, 1.0, 1.0, 1.0, 1.0, 1.0, 1.0}

func NewBBRv1Sender(initialMaxDatagramSize protocol.ByteCount) *BBRv1Sender {
	ret := &BBRv1Sender{
		state:             STARTUP,
		maxDatagramSize:   initialMaxDatagramSize,
		pacing_gain:       2.89,
		cwnd_gain:         2.89,
		lastNewMinRTT:     10 * time.Second, // When the first ack arrives, it will be updated to the actual rtt. Set high values to avoid underestimating minrtt.
		round_start_time:  monotime.Now(),
		lastNewMinRTTTime: monotime.Now(),
		sentTimes:         make(map[protocol.PacketNumber]monotime.Time),
	}
	ret.maxBandwidth = ret.min_maxbandwidth()
	return ret
}

func (b *BBRv1Sender) HasPacingBudget(now monotime.Time) bool {
	b.mayExitPROBE_RTT(now)
	if b.state == PROBE_RTT { //in PROBE_RTT, send limit because cwnd.
		return true
	}
	delivery_rate := float64(b.update_lastbandwidth_filter(now))
	return delivery_rate < float64(b.maxBandwidth)*b.pacing_gain
}

func (b *BBRv1Sender) bdp() float64 { //result(byte)
	return max(float64(b.maxBandwidth)*(float64(b.lastNewMinRTT)/float64(time.Second)), float64(min_bdp*b.maxDatagramSize))
}

func (b *BBRv1Sender) cwnd() protocol.ByteCount {
	if b.state == PROBE_RTT {
		return 4 * b.maxDatagramSize
	}
	return protocol.ByteCount(b.bdp() * b.cwnd_gain)
}

func (b *BBRv1Sender) TimeUntilSend(bytesInFlight protocol.ByteCount) monotime.Time {
	return b.nextSendTime
}

func (b *BBRv1Sender) OnPacketSent(sentTime monotime.Time, bytesInFlight protocol.ByteCount, packetNumber protocol.PacketNumber, bytes protocol.ByteCount, isRetransmittable bool) {
	b.sentTimes[packetNumber] = sentTime
	b.nextSendTime = sentTime + monotime.Time(float64(bytes)*float64(time.Second)/(b.pacing_gain*float64(b.maxBandwidth)))
}

func (b *BBRv1Sender) CanSend(bytesInFlight protocol.ByteCount) bool {
	return bytesInFlight < b.cwnd()
}

func (b *BBRv1Sender) mayExitPROBE_RTT(Time monotime.Time) {
	if b.state == PROBE_RTT && Time-b.last_probeRTTStart >= monotime.Time(200*time.Millisecond) {
		b.entry_PROBE_BW()
	}
}

func (b *BBRv1Sender) entry_PROBE_BW() {
	b.state = PROBE_BW
	b.pacing_gain = probeBWCycleGain[b.round%8]
	b.cwnd_gain = 2
}

func (b *BBRv1Sender) min_maxbandwidth() protocol.ByteCount { // min_bdp * rtt, result(byte/s)
	return protocol.ByteCount(float64(min_bdp*b.maxDatagramSize) * (float64(time.Second) / float64(b.lastNewMinRTT)))
}

func (b *BBRv1Sender) update_maxbandwidth_filter() {
	b.maxBandwidth = b.min_maxbandwidth()
	for i := range bw_win {
		b.maxBandwidth = max(b.maxBandwidth, b.latelybandwidth[i])
	}
}

func (b *BBRv1Sender) exit_recover() { //When PROBE_BW, pacing_gain set in OnPacketAcked.
	b.inRecovery = false
	switch b.state {
	case STARTUP:
		b.pacing_gain = 2.89
	case DRAIN:
		b.pacing_gain = 0.345
	case PROBE_RTT:
		b.pacing_gain = 1
	}
}

func (b *BBRv1Sender) update_lastbandwidth_filter(eventTime monotime.Time) (delivery_rate protocol.ByteCount) { //result=byte/s
	keep_start_index, expire_sum := 0, 0
	for i := range b.ackinfo { // delivery_rate of the most recent minRTT obtained via sliding window.
		if time.Duration(eventTime)-b.ackinfo[i].recordTime > b.lastNewMinRTT {
			keep_start_index = i + 1
			expire_sum += int(b.ackinfo[i].ackedBytes)
		}
	}
	b.ackinfo = b.ackinfo[keep_start_index:]
	b.delivered -= protocol.ByteCount(expire_sum)
	return protocol.ByteCount(float64(b.delivered) / (float64(b.lastNewMinRTT) / float64(time.Second)))
}

func (b *BBRv1Sender) OnPacketAcked(number protocol.PacketNumber, ackedBytes protocol.ByteCount, priorInFlight protocol.ByteCount, eventTime monotime.Time) {
	sentTime := b.sentTimes[number]
	rtt := time.Duration(eventTime - sentTime)
	delete(b.sentTimes, number)
	b.mayExitPROBE_RTT(eventTime)
	if rtt < b.lastNewMinRTT && rtt > 0 { //In the local link, rtt may sometimes measure 0 due to timer accuracy.
		b.lastNewMinRTT = rtt
		b.lastNewMinRTTTime = eventTime
	}
	b.delivered += ackedBytes
	b.ackinfo = append(b.ackinfo, ackInfo{ackedBytes: ackedBytes, recordTime: time.Duration(eventTime)})
	if b.state == PROBE_RTT { // When PROBE_RTT, Do not update the round; otherwise, the bandwidth sliding window may be exhausted at low RTT.
		return
	}
	delivery_rate := b.update_lastbandwidth_filter(eventTime)
	if eventTime-b.round_start_time >= monotime.Time(b.lastNewMinRTT) {
		if b.inRecovery {
			b.exit_recover()
		}
		b.latelybandwidth[b.round%bw_win] = delivery_rate
		b.round++
		if b.state == PROBE_BW {
			b.pacing_gain = probeBWCycleGain[b.round%8]
		}
		b.round_start_time = eventTime
		b.update_maxbandwidth_filter()
		if b.state == STARTUP && b.maxBandwidth > b.startup_last_bw && ((float64(b.maxBandwidth)-float64(b.startup_last_bw))/float64(b.startup_last_bw) >= 0.25) {
			b.startup_last_bw = b.maxBandwidth
			b.startup_last_bw_grow25_round = b.round
		}
		if b.state == STARTUP && b.round-b.startup_last_bw_grow25_round >= 3 {
			b.state = DRAIN
			b.pacing_gain = 0.345
			b.cwnd_gain = 1
		}
	}
	if b.state == DRAIN && priorInFlight < protocol.ByteCount(b.bdp()) {
		b.entry_PROBE_BW()
	}
	app_limited := priorInFlight < protocol.ByteCount(b.bdp())
	if (delivery_rate > b.maxBandwidth || (!app_limited && delivery_rate > 0)) && b.state != DRAIN && !b.inRecovery {
		b.maxBandwidth = max(delivery_rate, b.min_maxbandwidth())
	}
	if eventTime-b.lastNewMinRTTTime >= monotime.Time((10*time.Second)) && eventTime-b.last_probeRTTStart >= monotime.Time((10*time.Second)) {
		b.state = PROBE_RTT
		b.pacing_gain = 1
		b.cwnd_gain = 1
		b.lastNewMinRTT = 10 * time.Second
		b.last_probeRTTStart = eventTime
	}
}

func (b *BBRv1Sender) MaybeExitSlowStart() {}

func (b *BBRv1Sender) OnCongestionEvent(number protocol.PacketNumber, lostBytes protocol.ByteCount, priorInFlight protocol.ByteCount) {
	// For AS20473 → AS17816, 2–10% packet loss at night is a natural phenomenon (measured by ping -t).
	// pacing_gain=1 reduces the actual delivery rate; pacing_gain=1.25 is the key mechanism to maintain the rate.
	// TODO: handle this
	// if b.state == STARTUP || b.state == PROBE_RTT {
	// 	return
	// }
	// b.inRecovery = true
	// b.pacing_gain = 1
}

// OnRetransmissionTimeout is called when a retransmission timer expires.
func (b *BBRv1Sender) OnRetransmissionTimeout(packetsRetransmitted bool) {
	if packetsRetransmitted {
		oldlastNewMinRTT, oldlastNewMinRTTTime, oldprobeRTTStart := b.lastNewMinRTT, b.lastNewMinRTTTime, b.last_probeRTTStart
		*b = *NewBBRv1Sender(b.maxDatagramSize)
		b.lastNewMinRTT, b.lastNewMinRTTTime, b.last_probeRTTStart = oldlastNewMinRTT, oldlastNewMinRTTTime, oldprobeRTTStart
	}
}

func (b *BBRv1Sender) SetMaxDatagramSize(maxDatagramSize protocol.ByteCount) {
	b.maxDatagramSize = maxDatagramSize
}

func (b *BBRv1Sender) GetCongestionWindow() protocol.ByteCount {
	return b.cwnd()
}

func (b *BBRv1Sender) InRecovery() bool {
	return b.inRecovery
}

func (b *BBRv1Sender) InSlowStart() bool {
	return b.state == STARTUP
}
