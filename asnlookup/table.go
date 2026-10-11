package asnlookup

import (
	"bufio"
	"bytes"
	"compress/gzip"
	"errors"
	"fmt"
	"io"
	"math/bits"
	"net/netip"
	"sort"
	"strconv"
	"strings"
)

// Table is an immutable, sorted IPv4 range table.
//
// Layout: three parallel slices instead of a slice of structs, and AS
// descriptions interned in a per-ASN dictionary. The public table has about
// half a million ranges but only ~80k distinct ASes, and a range row is then
// 12 bytes (start, end, asn) instead of carrying two string headers each —
// which is what keeps the whole table near 10 MB resident.
type Table struct {
	starts  []uint32
	ends    []uint32
	asns    []uint32
	as      map[uint32]asMeta
	version string
}

type asMeta struct {
	name    string
	country string
}

// ErrNoRanges is returned when the input held no usable range at all — almost
// certainly the wrong file, which a host should treat as a failed refresh and
// keep serving the previous table rather than replacing it with nothing.
var ErrNoRanges = errors.New("asnlookup: no ranges in input")

// LoadIP2ASN parses an iptoasn.com ip2asn-v4.tsv stream — plain or gzipped,
// detected from the magic bytes — into a Table labelled with version.
//
// Each line is: range_start, range_end, AS_number, country_code,
// AS_description, tab separated. Ranges announced by AS 0 ("Not routed") are
// kept out of the table, since an address there has no origin to report, and
// so are lines that do not parse (counted, not fatal: one corrupt line in a
// daily dump must not throw the whole refresh away). IPv6 lines are skipped,
// so the v4+v6 combined file also loads. Overlapping ranges are resolved in
// favour of the narrower one by sorting, which matches how the published file
// orders more-specific announcements.
func LoadIP2ASN(r io.Reader, version string) (*Table, error) {
	br := bufio.NewReaderSize(r, 64<<10)
	if magic, err := br.Peek(2); err == nil && magic[0] == 0x1f && magic[1] == 0x8b {
		zr, err := gzip.NewReader(br)
		if err != nil {
			return nil, fmt.Errorf("asnlookup: gzip: %w", err)
		}
		defer zr.Close()
		br = bufio.NewReaderSize(zr, 64<<10)
	}

	type row struct{ start, end, asn uint32 }
	var rows []row
	as := map[uint32]asMeta{}
	sc := bufio.NewScanner(br)
	sc.Buffer(make([]byte, 0, 64<<10), 1<<20)
	for sc.Scan() {
		line := sc.Bytes()
		if len(line) == 0 || line[0] == '#' {
			continue
		}
		f := bytes.SplitN(line, []byte{'\t'}, 5)
		if len(f) < 3 {
			continue
		}
		start, err1 := netip.ParseAddr(string(f[0]))
		end, err2 := netip.ParseAddr(string(f[1]))
		if err1 != nil || err2 != nil || !start.Is4() || !end.Is4() {
			continue
		}
		asn, err := strconv.ParseUint(strings.TrimPrefix(string(f[2]), "AS"), 10, 32)
		if err != nil || asn == 0 {
			continue
		}
		s, e := v4u32(start), v4u32(end)
		if e < s {
			continue
		}
		rows = append(rows, row{s, e, uint32(asn)})
		if _, seen := as[uint32(asn)]; !seen {
			var m asMeta
			if len(f) > 3 {
				m.country = normCountry(string(f[3]))
			}
			if len(f) > 4 {
				m.name = strings.TrimSpace(string(f[4]))
			}
			as[uint32(asn)] = m
		}
	}
	if err := sc.Err(); err != nil {
		return nil, fmt.Errorf("asnlookup: read: %w", err)
	}
	if len(rows) == 0 {
		return nil, ErrNoRanges
	}
	sort.Slice(rows, func(i, j int) bool {
		if rows[i].start != rows[j].start {
			return rows[i].start < rows[j].start
		}
		return rows[i].end > rows[j].end
	})
	// Flatten nesting so the slices are strictly non-overlapping: a range that
	// starts inside an earlier one is the more specific announcement and owns
	// its span; the enclosing range resumes after it. Rows are sorted by start
	// ascending and, on equal starts, widest first, so a stack of open ranges
	// is enough: everything up to the next row's start belongs to the
	// innermost range still open. Without this a binary search could land on
	// an outer range for an address an inner one owns.
	t := &Table{as: as, version: version}
	var stack []row
	var pos uint64 // first address not yet emitted
	flush := func(limit uint64) {
		for len(stack) > 0 && pos < limit {
			top := stack[len(stack)-1]
			if uint64(top.end) < pos {
				stack = stack[:len(stack)-1]
				continue
			}
			segEnd := min(uint64(top.end), limit-1)
			t.push(uint32(pos), uint32(segEnd), top.asn)
			pos = segEnd + 1
			if uint64(top.end) < pos {
				stack = stack[:len(stack)-1]
			}
		}
	}
	for _, r := range rows {
		flush(uint64(r.start))
		pos = max(pos, uint64(r.start))
		stack = append(stack, r)
	}
	flush(1 << 32)
	return t, nil
}

func (t *Table) push(s, e, asn uint32) {
	t.starts = append(t.starts, s)
	t.ends = append(t.ends, e)
	t.asns = append(t.asns, asn)
}

// Len is the number of ranges held.
func (t *Table) Len() int {
	if t == nil {
		return 0
	}
	return len(t.starts)
}

// Version implements Resolver.
func (t *Table) Version() string {
	if t == nil {
		return ""
	}
	return t.version
}

// Lookup implements Resolver.
func (t *Table) Lookup(addr netip.Addr) (Info, bool) {
	if t == nil || len(t.starts) == 0 || !IsPublicIPv4(addr) {
		return Info{}, false
	}
	v := v4u32(addr.Unmap())
	i := sort.Search(len(t.starts), func(i int) bool { return t.starts[i] > v }) - 1
	if i < 0 || v > t.ends[i] {
		return Info{}, false
	}
	asn := t.asns[i]
	m := t.as[asn]
	return Info{ASN: asn, Name: m.name, Country: m.country, Prefix: rangeString(t.starts[i], t.ends[i])}, true
}

func v4u32(a netip.Addr) uint32 {
	b := a.As4()
	return uint32(b[0])<<24 | uint32(b[1])<<16 | uint32(b[2])<<8 | uint32(b[3])
}

func u32v4(v uint32) netip.Addr {
	return netip.AddrFrom4([4]byte{byte(v >> 24), byte(v >> 16), byte(v >> 8), byte(v)})
}

// rangeString renders [s, e] as a CIDR when it is exactly one aligned block,
// else as "first-last".
func rangeString(s, e uint32) string {
	size := uint64(e) - uint64(s) + 1
	if size&(size-1) == 0 {
		hostBits := bits.TrailingZeros64(size)
		if hostBits == 32 || s&(uint32(1)<<hostBits-1) == 0 {
			return netip.PrefixFrom(u32v4(s), 32-hostBits).String()
		}
	}
	return u32v4(s).String() + "-" + u32v4(e).String()
}

// normCountry keeps a two-letter code and drops the file's placeholders
// ("None", "Unknown", "ZZ").
func normCountry(c string) string {
	c = strings.ToUpper(strings.TrimSpace(c))
	if len(c) != 2 || c == "ZZ" {
		return ""
	}
	return c
}
