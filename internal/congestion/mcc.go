package congestion

import (
	"time"

	"github.com/quic-go/quic-go/internal/monotime"
	"github.com/quic-go/quic-go/internal/protocol"
)

var _ SendAlgorithm = (*MCCSender)(nil)
var _ SendAlgorithmWithDebugInfos = (*MCCSender)(nil)

type mccState int8

const (
	mccStart    mccState = iota // do slow start. (pacing_rate grows exponentially every RTT)
	mccStop                     // avoid occupying bandwidth beyond the fair share. (pacing_rate increases by a factor of 1.25 every secnods)
	mccGuard                    // guard its own fair share.
	mccProbeRTT                 // detect the background RTT for which it makes no contribution to congestion.

	// Select a higher initial congestion window at startup to accelerate the startup phase in long-fat pipes,
	// and subsequently choose a higher minimum congestion window to
	// maintain a lower bound on network performance under all circumstances.
	mccMinBdp = 128
)

type mccackInfo struct {
	ackedBytes protocol.ByteCount
	recordTime monotime.Time
}

// Measuring the Contribution to Congestion.
//
// It regards the minimum RTT within 5 seconds as the background RTT to which it contributes no congestion.
//
// If the smoothed RTT minus the background RTT is excessively high,
// which is regarded as possibly exceeding the fair share,
// it will maintain the current delivery rate
// (relying on packet loss caused by preemption of other flows to naturally reduce to the fair share).
//
// After the smoothed RTT minus the background RTT is no longer excessively high,
// it carries out moderate bandwidth growth to achieve the design goal:
// it will pause if its preemption exceeds the fair share,
// and accelerate if other flows preempt beyond the fair share.
//
// The core design philosophy is that each flow maintains its fair share,
// so the whole system naturally converges to fair sharing globally.
//
// It will not be suppressed by aggressive algorithms.
// If other flows continue to seize an excessive share of bandwidth,
// it will maintain the sending rate at which it entered mccStop;
// it will only have the opportunity to adjust its sending rate when other flows yield more than their fair share,
// allowing it to enter mccGuard and then re-enter mccStop.
// Even if it is constrained to a low sending rate, after at most 5.2 seconds,
// the background RTT will be updated to a high value,
// causing the algorithm to determine that its own contribution to congestion is negligible,
// and thus enter mccGuard to accelerate.
// thus converging to a fair share in competition with BBR or CUBIC.
type MCCSender struct {
	maxDatagramSize protocol.ByteCount
	smoothedRTT     time.Duration
	state           mccState
	oldState        mccState

	pacing_rate              protocol.ByteCount
	sentTimes                map[protocol.PacketNumber]monotime.Time
	backGroundRTT            time.Duration // default 5 * time.Second for detect potentially high background RTT.
	lastNewbackGroundRTTTime monotime.Time
	last_probeRTTStart       monotime.Time
	nextSendTime             monotime.Time
	delivered                protocol.ByteCount // byte
	ackinfo                  []mccackInfo
	// Its meaning is to limit the maximum flight data
	// volume to not exceed a specified multiple of bdp.
	// must be greater than 1 to ensure ACK delay.
	bdpLimitFactor   float64
	ackCount         int
	probeRTTSaveRate protocol.ByteCount //delivery_rate, when entry mccProbeRTT
}

// When lowRTTmode = false, the algorithm tends to exhaust the total bandwidth; even if bandwidth allocation is fair, it compromises delay fairness.
// When lowRTTmode = true, the algorithm favors fair allocation of both bandwidth and delay.
func NewMCCSender(initialMaxDatagramSize protocol.ByteCount, lowRTTmode bool) *MCCSender {
	r := &MCCSender{maxDatagramSize: initialMaxDatagramSize, last_probeRTTStart: monotime.Now(), backGroundRTT: 5 * time.Second, sentTimes: make(map[protocol.PacketNumber]monotime.Time)}
	r.pacing_rate = r.min_maxbandwidth()
	r.bdpLimitFactor = 3
	if lowRTTmode {
		r.bdpLimitFactor = 2
	}
	return r
}

func (b *MCCSender) min_maxbandwidth() protocol.ByteCount { // min_bdp * rtt, result(byte/s)
	return protocol.ByteCount(float64(mccMinBdp*b.maxDatagramSize) * (float64(time.Second) / float64(b.backGroundRTT)))
}
func (b *MCCSender) update_lastbandwidth_filter(eventTime monotime.Time) (delivery_rate protocol.ByteCount) { //result=byte/s
	keep_start_index, expire_sum := 0, 0
	for i := range b.ackinfo { // delivery_rate of the most recent smoothedRTT obtained via sliding window.
		if eventTime-b.ackinfo[i].recordTime > monotime.Time(b.smoothedRTT) {
			keep_start_index = i + 1
			expire_sum += int(b.ackinfo[i].ackedBytes)
		}
	}
	b.ackinfo = b.ackinfo[keep_start_index:]
	b.delivered -= protocol.ByteCount(expire_sum)
	return protocol.ByteCount(float64(b.delivered) / (float64(b.smoothedRTT) / float64(time.Second)))
}

func (b *MCCSender) HasPacingBudget(now monotime.Time) bool {
	b.mayExitProbeRTT()
	// To cope with ACK latency, the pacing_rate during comparison needs to be higher.
	return b.update_lastbandwidth_filter(now) < protocol.ByteCount(float64(b.bdpLimitFactor)*float64(b.pacing_rate))
}

func (b *MCCSender) TimeUntilSend(bytesInFlight protocol.ByteCount) monotime.Time {
	return b.nextSendTime
}

func (b *MCCSender) OnPacketSent(sentTime monotime.Time, bytesInFlight protocol.ByteCount, packetNumber protocol.PacketNumber, bytes protocol.ByteCount, isRetransmittable bool) {
	b.sentTimes[packetNumber] = sentTime
	b.nextSendTime = sentTime + monotime.Time(float64(bytes)*float64(time.Second)/(float64(b.bdpLimitFactor)*float64(b.pacing_rate)))
}

func (b *MCCSender) CanSend(bytesInFlight protocol.ByteCount) bool {
	b.mayExitProbeRTT()
	if bytesInFlight < mccMinBdp*b.maxDatagramSize {
		return true
	}
	cwnd_gain := 1.0
	if b.state == mccProbeRTT {
		cwnd_gain = 0.5
		return bytesInFlight < protocol.ByteCount(b.bdpLimitFactor*float64(b.GetCongestionWindow())*cwnd_gain)
	}
	// If the smoothed RTT minus the background RTT is greater than a certain multiple,
	// it indicates that there may indeed be at least the
	// specified multiple of BDP worth of data queued in the network.
	// avoids the issue in BBR v1 where determining the maximum bandwidth requires at least three rtt.
	r := (b.smoothedRTT - b.backGroundRTT) <= time.Duration(b.bdpLimitFactor-1)*b.backGroundRTT
	if !r && b.state != mccStop && b.state != mccProbeRTT {
		b.state = mccStop
		b.pacing_rate = max(b.update_lastbandwidth_filter(monotime.Now()), b.min_maxbandwidth())
		// Avoid underestimating the speed due to mccProbeRTT.
		if monotime.Now()-b.last_probeRTTStart < monotime.Time(b.smoothedRTT) && b.probeRTTSaveRate != 0 {
			b.pacing_rate = max(b.probeRTTSaveRate, b.pacing_rate)
		}
	} else if r && b.state == mccStop {
		b.state = mccGuard
	}
	// When the flow itself contributes excessively to congestion, reduce the maximum allowed in-flight data by 0.5 BDP to slow down the rate.
	return r || bytesInFlight < protocol.ByteCount(float64(b.bdpLimitFactor-0.5)*float64(b.GetCongestionWindow())*cwnd_gain)
}

func (b *MCCSender) OnPacketAcked(number protocol.PacketNumber, ackedBytes protocol.ByteCount, priorInFlight protocol.ByteCount, eventTime monotime.Time) {
	sentTime := b.sentTimes[number]
	delete(b.sentTimes, number)
	rtt := time.Duration(eventTime - sentTime)
	if rtt > 0 {
		if b.smoothedRTT == 0 {
			b.smoothedRTT = rtt
		} else {
			b.smoothedRTT = (3*b.smoothedRTT + rtt) / 4
		}
		if rtt < b.backGroundRTT {
			b.backGroundRTT = rtt
			b.lastNewbackGroundRTTTime = monotime.Now()
		}
	}
	b.mayExitProbeRTT()
	b.delivered += ackedBytes
	b.ackinfo = append(b.ackinfo, mccackInfo{ackedBytes: ackedBytes, recordTime: eventTime})
	if time.Duration(eventTime-b.last_probeRTTStart) > 5*time.Second && time.Duration(eventTime-b.lastNewbackGroundRTTTime) > 5*time.Second {
		b.last_probeRTTStart = monotime.Now()
		b.backGroundRTT = 5 * time.Second
		b.oldState = b.state
		b.state = mccProbeRTT
		b.probeRTTSaveRate = max(b.update_lastbandwidth_filter(eventTime), b.min_maxbandwidth())
	}
	if b.state == mccStart {
		b.pacing_rate += protocol.ByteCount(float64(b.maxDatagramSize) * (float64(time.Second) / float64(b.backGroundRTT)))
	}
	if b.state == mccGuard {
		b.ackCount++
		if b.ackCount%4 == 0 {
			b.pacing_rate += b.maxDatagramSize
		}
	}
}

func (b *MCCSender) mayExitProbeRTT() {
	if b.state == mccProbeRTT && time.Duration(monotime.Now()-b.last_probeRTTStart) >= 200*time.Millisecond {
		b.state = mccGuard
		if b.oldState == mccStart {
			b.state = mccStart
		}
	}
}

func (b *MCCSender) MaybeExitSlowStart() {}

func (b *MCCSender) OnCongestionEvent(number protocol.PacketNumber, lostBytes protocol.ByteCount, priorInFlight protocol.ByteCount) {
	delete(b.sentTimes, number)
}

func (b *MCCSender) OnRetransmissionTimeout(packetsRetransmitted bool) {
	if packetsRetransmitted {
		*b = *NewMCCSender(b.maxDatagramSize, b.bdpLimitFactor == 2)
	}
}

func (b *MCCSender) SetMaxDatagramSize(maxDatagramSize protocol.ByteCount) {
	b.maxDatagramSize = maxDatagramSize
}

func (b *MCCSender) GetCongestionWindow() protocol.ByteCount {
	return protocol.ByteCount(float64(b.pacing_rate) * (float64(b.backGroundRTT) / float64(time.Second)))
}

func (b *MCCSender) InRecovery() bool {
	return b.state == mccStop
}

func (b *MCCSender) InSlowStart() bool {
	return b.state == mccStart
}
