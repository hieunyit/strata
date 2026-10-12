package et

import (
	"errors"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"github.com/strata/strata/tools/strata-import-signatures/internal/irout"
)

func ids(t *testing.T) *irout.IDs {
	t.Helper()
	i, err := irout.LoadIDs(filepath.Join(t.TempDir(), "ids.txt"), MinID, MaxID)
	if err != nil {
		t.Fatal(err)
	}
	return i
}

const head = `alert http $EXTERNAL_NET any -> $HTTP_SERVERS any (msg:"ET WEB_SPECIFIC_APPS Example SQL Injection"; flow:established,to_server; `

func conv(t *testing.T, opts string, sid int) (irout.Rule, []irout.Test, bool, error) {
	t.Helper()
	r, err := Parse(head + opts + ` classtype:web-application-attack; sid:` + itoa(sid) + `; rev:2; metadata:signature_severity Major, confidence High;)`)
	if err != nil {
		t.Fatal(err)
	}
	return Convert(r, "11308", ids(t))
}

func itoa(n int) string { return strconv.Itoa(n) }

func conds(r irout.Rule) []map[string]any {
	return r["match"].(map[string]any)["all"].([]map[string]any)
}

// Only the BSD part of ET Open (SIDs 2000000-2099999) may be imported.
func TestSIDOutsideTheBSDRangeIsRefused(t *testing.T) {
	for _, sid := range []int{1999999, 2100000, 2800000, 2900001} {
		if _, _, _, err := conv(t, `http.uri; content:"/x.php";`, sid); !errors.Is(err, ErrSID) {
			t.Errorf("sid %d: %v, want ErrSID", sid, err)
		}
	}
	for _, sid := range []int{2000000, 2099999} {
		if _, _, _, err := conv(t, `http.uri; content:"/x.php";`, sid); err != nil {
			t.Errorf("sid %d: %v", sid, err)
		}
	}
}

func TestBuffersModifiersAndSample(t *testing.T) {
	r, tests, loose, err := conv(t, `http.method; content:"POST"; http.uri; content:"/index.php?"; startswith; nocase; content:"page="; distance:0; http.user_agent; content:"sqlmap"; http.request_body; content:"union"; nocase;`, 2012697)
	if err != nil {
		t.Fatal(err)
	}
	if !loose {
		t.Error("distance dropped but the rule is not marked loose")
	}
	c := conds(r)
	if len(c) != 5 || r["stage"] != "request_body" || r["score"] != 60 {
		t.Fatalf("%+v", r)
	}
	op := func(i int) map[string]any { return c[i]["operator"].(map[string]any) }
	if op(1)["type"] != "begins_with" || op(1)["value"] != "/index.php?" ||
		strings.Join(c[1]["transforms"].([]string), ",") != "url_decode,lowercase" {
		t.Errorf("uri condition %+v", c[1])
	}
	if tg := c[3]["targets"].([]map[string]any)[0]; tg["key"] != "User-Agent" {
		t.Errorf("user agent target %+v", tg)
	}
	m := r["metadata"].(map[string]any)
	if m["source"] != "et-open" || m["upstream_id"] != "2012697" || m["license"] != "BSD-3-Clause" || m["author"] == "" {
		t.Errorf("metadata %+v", m)
	}
	if len(tests) != 2 || tests[1].Request["method"] != "POST" || tests[1].Request["uri"] != "/index.php?page=" {
		t.Fatalf("tests %+v", tests)
	}
}

func TestHeaderNamesAndRefusals(t *testing.T) {
	r, tests, _, err := conv(t, `http.uri; content:"/shell?"; startswith; http.header_names; content:!"|0d 0a|Referer|0d 0a|";`, 2025883)
	if err != nil {
		t.Fatal(err)
	}
	c := conds(r)[1]
	if tg := c["targets"].([]map[string]any)[0]; tg["count"] != true || tg["key"] != "Referer" || c["operator"].(map[string]any)["type"] != "eq" {
		t.Fatalf("absent Referer: %+v", c)
	}
	if _, ok := tests[1].Request["headers"].(map[string]any)["Referer"]; ok {
		t.Fatal("sample sends the header the rule wants absent")
	}
	for opts, want := range map[string]string{
		`http.uri; content:"/a"; flowbits:isset,x;`:             "flowbits",
		`http.stat_code; content:"200";`:                        "http.stat_code",
		`content:"/dev/udp/";`:                                  "outside an HTTP buffer",
		`http.uri; content:"/a"; pcre:"/(?<=a)b/U";`:            "not RE2",
		`http.uri; content:!"/a";`:                              "only negated",
		`http.uri; content:"/a"; byte_test:1,>,2,0;`:            "byte_test",
		`http.header_names; content:"|0d 0a|A|0d 0a|B|0d 0a|";`: "across names",
		`http.uri; content:"/a"; isdataat:!1,relative;`:         "isdataat",
		`http.request_header; content:"no-colon";`:              "Name: value",
	} {
		if _, _, _, err := conv(t, opts, 2001000); err == nil || !strings.Contains(err.Error(), want) {
			t.Errorf("%s: %v, want %q", opts, err, want)
		}
	}
	// response direction
	r2, _ := Parse(strings.Replace(head, "to_server", "to_client", 1) + `file.data; content:"x"; sid:2001001;)`)
	if _, _, _, err := Convert(r2, "1", ids(t)); err == nil {
		t.Error("to_client rule accepted")
	}
}

func TestPlusAndBinaryContent(t *testing.T) {
	r, _, _, err := conv(t, `http.uri; content:"/a+b"; http.request_body; content:"|ff d8|JFIF";`, 2001002)
	if err != nil {
		t.Fatal(err)
	}
	c := conds(r)
	if v := c[0]["operator"].(map[string]any)["value"]; v != "/a[+ ]b" {
		t.Errorf("plus in a decoded URI: %v", v)
	}
	if v := c[1]["operator"].(map[string]any)["value"]; v != `\xff\xd8JFIF` {
		t.Errorf("binary content: %v", v)
	}
}
