package helpers

import "time"

type PingHelper struct {
	count        int
	successCount int
	errorCount   int
	min          time.Duration
	max          time.Duration
	sum          time.Duration
}

type PingState time.Time

func (ph *PingHelper) StartOne() PingState {
	return PingState(time.Now())
}

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

func (ph *PingHelper) Count() int {
	return ph.count
}

func (ph *PingHelper) Successes() int {
	return ph.successCount
}

func (ph *PingHelper) Errors() int {
	return ph.errorCount
}

func (ph *PingHelper) Min() time.Duration {
	return ph.min
}

func (ph *PingHelper) Max() time.Duration {
	return ph.max
}

func (ph *PingHelper) Mean() time.Duration {
	return time.Duration(float64(ph.sum) / float64(ph.successCount))
}
