package congestion

import (
	"time"

	"github.com/quic-go/quic-go/internal/monotime"
	"github.com/quic-go/quic-go/internal/protocol"
)

var _ SendAlgorithm = (*BBRv1Sender)(nil)
var _ SendAlgorithmWithDebugInfos = (*BBRv1Sender)(nil)

type minRTTInfo struct {
	minrtt     time.Duration
	recordTime time.Duration
}
type BBRv1Sender struct {
	state            int8
	round            int64
	round_start_time monotime.Time

	st_start_round int64
	st_last_bw     protocol.ByteCount

	pacing_gain float64
	cwnd_gain   float64

	minRTT            func() time.Duration
	historyminRTT     []minRTTInfo
	lastNewMinRTT     time.Duration
	lastNewMinRTTTime monotime.Time
	maxBandwidth      protocol.ByteCount
	latelybandwidth   [bw_win]protocol.ByteCount
	probeRTTStart     monotime.Time

	delivered       protocol.ByteCount
	delivered_time  monotime.Time
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

const bw_win = 16

var probeBWCycleGain = []float64{1.25, 0.75, 1.0, 1.0, 1.0, 1.0, 1.0, 1.0}

func NewBBRv1Sender(initialMaxDatagramSize protocol.ByteCount) *BBRv1Sender {
	return &BBRv1Sender{
		state:             STARTUP,
		maxBandwidth:      32 * initialMaxDatagramSize,
		maxDatagramSize:   initialMaxDatagramSize,
		pacing_gain:       2.89,
		cwnd_gain:         2.89,
		lastNewMinRTT:     10 * time.Second,
		lastNewMinRTTTime: monotime.Now(),
	}
}

func (b *BBRv1Sender) SetMinRTT(f func() time.Duration) {
	b.minRTT = f
	b.lastNewMinRTT = f()
	b.lastNewMinRTTTime = monotime.Now()
}

func (b *BBRv1Sender) HasPacingBudget(now monotime.Time) bool {
	b.mayExitPROBE_RTT(now)
	if b.state == PROBE_RTT {
		return true
	}
	delivery_rate := (b.delivered / max(1, protocol.ByteCount(now-b.delivered_time)/protocol.ByteCount(time.Second)))
	return delivery_rate < (max(32*b.maxDatagramSize, protocol.ByteCount(b.bdp()*b.pacing_gain)))
}

func (b *BBRv1Sender) bdp() float64 {
	return max(float64(b.maxBandwidth)*(float64(b.minRTT())/float64(time.Second)), float64(32*b.maxDatagramSize))
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
	if b.delivered_time == 0 {
		b.delivered_time = sentTime
	}
	b.nextSendTime = sentTime + monotime.Time(float64(bytes)*float64(time.Second)/(b.pacing_gain*float64(b.maxBandwidth)))
}

func (b *BBRv1Sender) CanSend(bytesInFlight protocol.ByteCount) bool {
	return bytesInFlight < b.cwnd()
}

func (b *BBRv1Sender) mayExitPROBE_RTT(Time monotime.Time) {
	if b.state == PROBE_RTT && Time-b.probeRTTStart >= monotime.Time(200*time.Millisecond) {
		b.entry_PROBE_BW()
	}
}

func (b *BBRv1Sender) entry_PROBE_BW() {
	b.state = PROBE_BW
	b.pacing_gain = probeBWCycleGain[b.round%8]
	b.cwnd_gain = 2
}

func (b *BBRv1Sender) update_minrtt_filter() {
	now := time.Duration(monotime.Now())
	if len(b.historyminRTT) > 0 && now-b.historyminRTT[0].recordTime >= 10*time.Second {
		keep_start_index := 0
		for i := range b.historyminRTT {
			if now-b.historyminRTT[i].recordTime < 10*time.Second {
				keep_start_index = i
				break
			}
		}
		if keep_start_index < len(b.historyminRTT) {
			b.historyminRTT = b.historyminRTT[keep_start_index:]
			minrtt, eventTime := time.Duration(0), time.Duration(0)
			for _, h := range b.historyminRTT {
				if h.minrtt < minrtt {
					minrtt = h.minrtt
					eventTime = h.recordTime
				}
			}
			b.lastNewMinRTT = minrtt
			b.lastNewMinRTTTime = monotime.Time(eventTime)
		} else {
			b.historyminRTT = b.historyminRTT[0:0]
			b.lastNewMinRTT = 10 * time.Second
		}
	}
}

func (b *BBRv1Sender) update_bandwidth_filter() {
	b.maxBandwidth = 32 * b.maxDatagramSize
	for i := range bw_win {
		if b.latelybandwidth[i] > b.maxBandwidth {
			b.maxBandwidth = b.latelybandwidth[i]
		}
	}
}

func (b *BBRv1Sender) exit_recover() {
	b.inRecovery = false
	switch b.state {
	case STARTUP:
		b.pacing_gain = 2.89
	case DRAIN:
		b.pacing_gain = 0.345
	case PROBE_BW:
		b.pacing_gain = 1
	case PROBE_RTT:
		b.pacing_gain = 1
	}
}

func (b *BBRv1Sender) OnPacketAcked(number protocol.PacketNumber, ackedBytes protocol.ByteCount, priorInFlight protocol.ByteCount, eventTime monotime.Time) {
	minrtt := b.minRTT()
	b.mayExitPROBE_RTT(eventTime)
	if minrtt < b.lastNewMinRTT {
		b.lastNewMinRTT = minrtt
		b.historyminRTT = append(b.historyminRTT, minRTTInfo{minrtt: minrtt, recordTime: time.Duration(eventTime)})
		b.lastNewMinRTTTime = eventTime
	}
	b.delivered += ackedBytes
	if b.state == PROBE_RTT {
		return
	}
	b.update_minrtt_filter()
	delivery_rate := protocol.ByteCount(float64(b.delivered) / (float64(eventTime-b.delivered_time) / float64(time.Second)))
	if eventTime-b.round_start_time >= monotime.Time(minrtt) {
		if b.inRecovery {
			b.exit_recover()
		}
		b.latelybandwidth[b.round%bw_win] = delivery_rate
		b.round++
		b.round_start_time = eventTime
		b.delivered = 0
		b.delivered_time = eventTime
		b.update_bandwidth_filter()
		if b.state == STARTUP && b.maxBandwidth > b.st_last_bw && ((float64(b.maxBandwidth)-float64(b.st_last_bw))/float64(b.st_last_bw) >= 0.25) {
			b.st_last_bw = b.maxBandwidth
			b.st_start_round = b.round
		}
		if b.state == STARTUP && b.round-b.st_start_round >= 3 {
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
		b.maxBandwidth = delivery_rate
	}
	if eventTime-b.lastNewMinRTTTime >= monotime.Time((10*time.Second)) && eventTime-b.probeRTTStart >= monotime.Time((10*time.Second)) {
		b.state = PROBE_RTT
		b.pacing_gain = 1
		b.cwnd_gain = 1
		b.probeRTTStart = eventTime
	}
}

func (b *BBRv1Sender) MaybeExitSlowStart() {}

func (b *BBRv1Sender) OnCongestionEvent(number protocol.PacketNumber, lostBytes protocol.ByteCount, priorInFlight protocol.ByteCount) {
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
		b.maxBandwidth = 32 * b.maxDatagramSize
		b.state = STARTUP
		b.pacing_gain = 2.89
		b.cwnd_gain = 2.89
		b.inRecovery = false
		b.delivered = 0
		clear(b.latelybandwidth[:])
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
