package corpus

import (
	"encoding/json"
	"fmt"
	"io"
	"math/rand/v2"
	"net/url"
	"strings"

	"github.com/strata/strata/tools/strata-rules/internal/runner"
)

// Benign generates n ordinary API and web requests from seed. It leans on
// what trips naive rules: apostrophes in names, SQL and HTML words in
// prose, punctuation, dots in paths, nested JSON, long cookies.
func Benign(seed uint64, n int, w io.Writer) error {
	r := rand.New(rand.NewPCG(seed, seed^0x5eed))
	pick := func(xs []string) string { return xs[r.IntN(len(xs))] }
	names := []string{"Nguyễn Văn An", "Trần Thị Bình", "O'Brien", "D'Angelo", "Mary-Jane", "Lê Minh Châu", "Zoë Saldaña", "Jean-Luc Picard", "Ngô Thị Ánh"}
	words := []string{"please select your size", "order by date", "union station tickets", "drop me a line", "insert coin",
		"the script was great", "rock & roll", "C:/Program Files is slow", "50% off -- today only", "a <3 b", "x = y + 1",
		"where is my order?", "delete my account please", "update address", "tôi muốn đổi hàng", "giá bao nhiêu?",
		"1/2 cup sugar", "email@example.test", "#hashtag", "it's 5 o'clock", "SELECT the best plan", "javascript tutorial"}
	agents := []string{"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/129.0 Safari/537.36",
		"Mozilla/5.0 (iPhone; CPU iPhone OS 18_0 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/18.0 Mobile/15E148 Safari/604.1",
		"Mozilla/5.0 (X11; Linux x86_64; rv:131.0) Gecko/20100101 Firefox/131.0", "okhttp/4.12.0", "example-mobile-app/3.2.1 (Android 15)",
		"curl/8.5.0", "python-requests/2.32.3"}
	paths := []string{"/", "/v1/users/%d", "/v1/orders/%d/items", "/static/app.%d.min.js", "/static/css/site.css", "/images/logo@2x.png",
		"/v1/products/%d/reviews", "/account/settings", "/docs/getting-started.html", "/v1/search", "/api/v2/payments/%d/status",
		"/fonts/roboto-v30-latin-regular.woff2", "/blog/2026/10/how-to-choose.html", "/v1/files/report-2026.10.pdf"}
	enc := json.NewEncoder(w)
	enc.SetEscapeHTML(false)
	for i := 0; i < n; i++ {
		req := runner.Request{ID: fmt.Sprintf("benign-%05d", i), Headers: map[string]any{
			"Host": "api.example.test", "User-Agent": pick(agents), "Accept": "application/json, text/plain, */*",
			"Accept-Language": pick([]string{"vi-VN,vi;q=0.9,en;q=0.8", "en-US,en;q=0.9"}),
		}}
		if r.IntN(3) == 0 {
			req.Headers["Cookie"] = fmt.Sprintf("sid=%016x; theme=%s; _ga=GA1.2.%d.%d", r.Uint64(), pick([]string{"dark", "light"}), r.IntN(1e9), r.IntN(1e9))
		}
		path := pick(paths)
		if strings.Contains(path, "%d") {
			path = fmt.Sprintf(path, 1+r.IntN(99999))
		}
		switch r.IntN(4) {
		case 0: // GET with a query
			q := url.Values{}
			q.Set("q", pick(words))
			q.Set("page", fmt.Sprint(1+r.IntN(20)))
			if r.IntN(2) == 0 {
				q.Set("sort", pick([]string{"price_asc", "-created_at", "name"}))
			}
			req.URI = path + "?" + q.Encode()
		case 1: // form post
			form := url.Values{}
			form.Set("name", pick(names))
			form.Set("message", pick(words)+". "+pick(words))
			form.Set("email", "user"+fmt.Sprint(r.IntN(1000))+"@example.test")
			req.Method, req.URI, req.Body = "POST", "/contact", form.Encode()
			req.Headers["Content-Type"] = "application/x-www-form-urlencoded"
		case 2: // JSON API call
			body, _ := json.Marshal(map[string]any{
				"customer": map[string]any{"name": pick(names), "note": pick(words)},
				"items":    []map[string]any{{"sku": fmt.Sprintf("SKU-%05d", r.IntN(1e5)), "qty": 1 + r.IntN(5)}},
				"coupon":   pick([]string{"", "AUTUMN-10", "VIP_2026"}),
			})
			req.Method, req.URI, req.Body = pick([]string{"POST", "PUT", "PATCH"}), path, string(body)
			req.Headers["Content-Type"] = "application/json"
		default: // plain GET
			req.URI = path
		}
		if err := enc.Encode(req); err != nil {
			return err
		}
	}
	return nil
}
