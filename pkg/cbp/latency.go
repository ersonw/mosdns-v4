package cbp

import "time"

// LatencyResult is the result of an ICMP echo probe carried over CBP.
// The raw-IP client owns the probe implementation; the stream client only
// reports the control-path RTT in the same shape.
type LatencyResult struct {
	Count       int           `json:"count"`
	Received    int           `json:"received"`
	Min         time.Duration `json:"min"`
	Avg         time.Duration `json:"avg"`
	Max         time.Duration `json:"max"`
	Last        time.Duration `json:"last"`
	LossPercent float64       `json:"loss_percent"`
}
