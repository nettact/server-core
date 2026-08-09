package tsstore

import (
	"context"
	"os"
	"path/filepath"
)

// Stats implements SeriesStore.
func (p *Prom) Stats(ctx context.Context) (Stats, error) {
	var out Stats
	for i, name := range []string{"raw", "m1", "h1", "d1"} {
		ts := TierStats{
			HeadSeries: p.dbs[i].Head().NumSeries(),
			Blocks:     len(p.dbs[i].Blocks()),
			DiskBytes:  dirBytes(filepath.Join(p.dir, name)),
		}
		switch i {
		case instRaw:
			out.Raw = ts
		case instM1:
			out.M1 = ts
		case instH1:
			out.H1 = ts
		default:
			out.D1 = ts
		}
	}
	return out, nil
}

func dirBytes(dir string) int64 {
	var total int64
	_ = filepath.WalkDir(dir, func(_ string, d os.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return nil
		}
		if info, err := d.Info(); err == nil {
			total += info.Size()
		}
		return nil
	})
	return total
}
