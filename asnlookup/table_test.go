package asnlookup

import (
	"bytes"
	"compress/gzip"
	"errors"
	"net/netip"
	"os"
	"strings"
	"testing"
)

func loadSample(t *testing.T) *Table {
	t.Helper()
	f, err := os.Open("testdata/ip2asn-v4-sample.tsv")
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	tab, err := LoadIP2ASN(f, "sample-1")
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	return tab
}

func TestLookupAnswersPublicRangesAndRefusesEverythingElse(t *testing.T) {
	tab := loadSample(t)
	cases := []struct {
		ip      string
		ok      bool
		asn     uint32
		country string
		prefix  string
	}{
		{"1.0.0.1", true, 13335, "US", "1.0.0.0/24"},
		{"1.0.0.0", true, 13335, "US", "1.0.0.0/24"},        // first address of a range
		{"1.0.0.255", true, 13335, "US", "1.0.0.0/24"},      // last address of a range
		{"1.0.2.9", false, 0, "", ""},                       // ASN 0: not routed
		{"1.0.5.5", true, 38803, "AU", "1.0.4.0/22"},        //
		{"8.8.4.4", false, 0, "", ""},                       // gap between ranges
		{"10.1.2.3", false, 0, "", ""},                      // private, even though a row covers it
		{"100.100.1.1", false, 0, "", ""},                   // CGNAT shared space
		{"127.0.0.1", false, 0, "", ""},                     // loopback
		{"169.254.1.1", false, 0, "", ""},                   // link-local
		{"224.0.0.5", false, 0, "", ""},                     // multicast
		{"202.97.16.7", true, 4809, "CN", "202.97.16.0/24"}, // nested more-specific wins
		{"202.97.15.1", true, 4134, "CN", "202.97.0.0/20"},
		{"202.97.17.1", true, 4134, "CN", "202.97.17.0-202.97.127.255"}, // outer resumes after inner
		{"59.43.1.1", true, 4809, "CN", "59.43.0.0/16"},                 // "AS" prefix and lower-case country tolerated
		{"255.255.255.255", false, 0, "", ""},
	}
	for _, c := range cases {
		info, ok := tab.Lookup(netip.MustParseAddr(c.ip))
		if ok != c.ok {
			t.Errorf("%s: ok=%v, want %v (%+v)", c.ip, ok, c.ok, info)
			continue
		}
		if !ok {
			continue
		}
		if info.ASN != c.asn || info.Country != c.country || info.Prefix != c.prefix {
			t.Errorf("%s = %+v, want asn %d country %q prefix %q", c.ip, info, c.asn, c.country, c.prefix)
		}
	}
	if info, _ := tab.Lookup(netip.MustParseAddr("8.8.8.8")); info.Name != "GOOGLE" {
		t.Errorf("name = %q", info.Name)
	}
	if _, ok := tab.Lookup(netip.MustParseAddr("2001:db8::1")); ok {
		t.Error("IPv6 address resolved by a v4 table")
	}
	if _, ok := tab.Lookup(netip.MustParseAddr("::ffff:8.8.8.8")); !ok {
		t.Error("a v4-mapped address must resolve as its v4 form")
	}
	if tab.Version() != "sample-1" {
		t.Errorf("version = %q", tab.Version())
	}
}

func TestLoadDetectsGzip(t *testing.T) {
	raw, err := os.ReadFile("testdata/ip2asn-v4-sample.tsv")
	if err != nil {
		t.Fatal(err)
	}
	var buf bytes.Buffer
	zw := gzip.NewWriter(&buf)
	zw.Write(raw)
	zw.Close()
	tab, err := LoadIP2ASN(&buf, "gz")
	if err != nil {
		t.Fatalf("load gz: %v", err)
	}
	if info, ok := tab.Lookup(netip.MustParseAddr("8.8.8.8")); !ok || info.ASN != 15169 {
		t.Errorf("gz lookup = %+v %v", info, ok)
	}
	if tab.Len() != loadSample(t).Len() {
		t.Errorf("gz table has %d ranges, plain %d", tab.Len(), loadSample(t).Len())
	}
}

func TestLoadRefusesAnInputWithNoRanges(t *testing.T) {
	for _, in := range []string{"", "garbage\nmore garbage\n", "1.0.1.0\t1.0.3.255\t0\tNone\tNot routed\n"} {
		if _, err := LoadIP2ASN(strings.NewReader(in), "x"); !errors.Is(err, ErrNoRanges) {
			t.Errorf("LoadIP2ASN(%q) err = %v, want ErrNoRanges", in, err)
		}
	}
}

func TestNilAndEmptyResolversMissQuietly(t *testing.T) {
	var tab *Table
	if _, ok := tab.Lookup(netip.MustParseAddr("8.8.8.8")); ok || tab.Version() != "" || tab.Len() != 0 {
		t.Error("nil table must miss")
	}
	var h Holder
	if _, ok := h.Lookup(netip.MustParseAddr("8.8.8.8")); ok || h.Version() != "" {
		t.Error("zero holder must miss")
	}
	h.Store(loadSample(t))
	if info, ok := h.Lookup(netip.MustParseAddr("8.8.8.8")); !ok || info.ASN != 15169 || h.Version() != "sample-1" {
		t.Errorf("holder after Store = %+v %v %q", info, ok, h.Version())
	}
	h.Store(nil)
	if _, ok := h.Lookup(netip.MustParseAddr("8.8.8.8")); ok {
		t.Error("holder after Store(nil) must miss")
	}
}

func TestIsPublicIPv4(t *testing.T) {
	for ip, want := range map[string]bool{
		"8.8.8.8": true, "192.168.1.1": false, "172.16.0.1": false, "100.64.0.1": false,
		"100.128.0.1": true, "192.0.2.1": false, "198.18.0.1": false, "0.1.2.3": false,
		"240.0.0.1": false, "2001:4860::8888": false,
	} {
		if got := IsPublicIPv4(netip.MustParseAddr(ip)); got != want {
			t.Errorf("IsPublicIPv4(%s) = %v, want %v", ip, got, want)
		}
	}
}
