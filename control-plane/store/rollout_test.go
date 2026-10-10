package store

import (
	"reflect"
	"testing"
)

func TestWavePlan(t *testing.T) {
	plan := []float64{0, 0.10, 1}
	for n, want := range map[int][]int{
		0: nil, 1: {1}, 2: {1, 2}, 3: {1, 2, 3}, 10: {1, 2, 10}, 25: {1, 3, 25}, 100: {1, 10, 100},
	} {
		if got := WavePlan(n, plan); !reflect.DeepEqual(got, want) {
			t.Errorf("%d nodes: %v, want %v", n, got, want)
		}
	}
	if got := WavePlan(5, []float64{1}); !reflect.DeepEqual(got, []int{5}) {
		t.Errorf("one wave: %v", got)
	}
}
