package api

import (
	"net/http/httptest"
	"testing"
	"time"
)

func TestTimeRange(t *testing.T) {
	tests := []struct {
		query string
		want  time.Duration
		ok    bool
	}{
		{"", 24 * time.Hour, true},
		{"?window=3h", 3 * time.Hour, true},
		{"?window=24h", 24 * time.Hour, true},
		{"?window=7d", 7 * 24 * time.Hour, true},
		{"?window=30d", 30 * 24 * time.Hour, true},
		{"?window=90d", 90 * 24 * time.Hour, true},
		{"?window=6h", 0, false},
	}
	for _, tt := range tests {
		t.Run(tt.query, func(t *testing.T) {
			r := httptest.NewRequest("GET", "/api/v1/sites/site_default/target-statuses"+tt.query, nil)
			got, ok := timeRange(r)
			if got != tt.want || ok != tt.ok {
				t.Fatalf("timeRange() = %s, %v; want %s, %v", got, ok, tt.want, tt.ok)
			}
		})
	}
}
