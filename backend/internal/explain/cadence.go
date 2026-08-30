package explain

import (
	"math"
	"sort"
	"time"
)

// Beacon describes regular contact timing to one destination.
type Beacon struct {
	Contacts  int     `json:"contacts"`
	AvgGapMin float64 `json:"avg_gap_min"`
	GapCV     float64 `json:"gap_cv"`
}

// Beaconish reports whether contacts happen at suspiciously regular intervals: at least six
// distinct contact minutes, average gap of two minutes or more, and gaps varying by less than 25 %.
func Beaconish(minutes []time.Time) (Beacon, bool) {
	if len(minutes) < 6 {
		return Beacon{Contacts: len(minutes)}, false
	}
	ms := append([]time.Time(nil), minutes...)
	sort.Slice(ms, func(i, j int) bool { return ms[i].Before(ms[j]) })
	var gaps []float64
	for i := 1; i < len(ms); i++ {
		g := ms[i].Sub(ms[i-1]).Minutes()
		if g > 0 {
			gaps = append(gaps, g)
		}
	}
	if len(gaps) < 5 {
		return Beacon{Contacts: len(ms)}, false
	}
	var sum float64
	for _, g := range gaps {
		sum += g
	}
	mean := sum / float64(len(gaps))
	var sq float64
	for _, g := range gaps {
		sq += (g - mean) * (g - mean)
	}
	cv := math.Sqrt(sq/float64(len(gaps))) / mean
	b := Beacon{Contacts: len(ms), AvgGapMin: math.Round(mean*10) / 10, GapCV: math.Round(cv*100) / 100}
	return b, mean >= 2 && cv < 0.25
}
