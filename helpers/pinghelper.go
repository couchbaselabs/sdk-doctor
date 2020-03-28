package helpers

import "time"

// PingHelper provides a helper for the statistics of pinging
type PingHelper struct {
	count        int
	successCount int
	errorCount   int
	min          time.Duration
	max          time.Duration
	sum          time.Duration
}

// PingState represents the state of a single ping
type PingState time.Time

// StartOne starts one ping
func (ph *PingHelper) StartOne() PingState {
	return PingState(time.Now())
}

// StopOne will stop a ping and add it to the statistics
func (ph *PingHelper) StopOne(state PingState, err error) {
	duration := time.Now().Sub(time.Time(state))

	if err == nil {
		if ph.successCount == 0 {
			ph.min = duration
			ph.max = duration
			ph.sum = duration

			ph.successCount = 1
		} else {
			if duration < ph.min {
				ph.min = duration
			}

			if duration > ph.max {
				ph.max = duration
			}

			ph.sum += duration

			ph.successCount++
		}
	} else {
		ph.errorCount++
	}

	ph.count++
}

// Count returns the number of pings performed
func (ph *PingHelper) Count() int {
	return ph.count
}

// Successes returns the number of successful pings
func (ph *PingHelper) Successes() int {
	return ph.successCount
}

// Errors returns the number of ping errors
func (ph *PingHelper) Errors() int {
	return ph.errorCount
}

// Min returns the minimum duration of a ping
func (ph *PingHelper) Min() time.Duration {
	return ph.min
}

// Max returns the maximum duration of a ping
func (ph *PingHelper) Max() time.Duration {
	return ph.max
}

// Mean returns the average duration of the pings
func (ph *PingHelper) Mean() time.Duration {
	return time.Duration(float64(ph.sum) / float64(ph.successCount))
}
