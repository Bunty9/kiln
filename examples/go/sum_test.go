package main

import "testing"

func TestSum(t *testing.T) {
	tests := []struct {
		a, b, want int
	}{
		{2, 3, 5},
		{0, 0, 0},
		{-1, 1, 0},
		{10, -5, 5},
	}

	for _, tt := range tests {
		got := Sum(tt.a, tt.b)
		if got != tt.want {
			t.Errorf("Sum(%d, %d) = %d, want %d", tt.a, tt.b, got, tt.want)
		}
	}
}
