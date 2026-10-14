package corpus

import (
	"encoding/json"
	"fmt"
	"io"
	"math/rand/v2"
	"strings"

	"github.com/strata/strata/tools/strata-rules/internal/runner"
)

// Pilot generates n benign requests shaped like the two simulated pilot
// routes (deploy/staging/pilot-traffic.sh, W10-G2-01): POST /v1/verify
// with a JSON identity check and POST /v1/upload with a multipart document.
// W11-S-01 asks for benign traffic taken from the pilot routes, anonymized;
// the routes are simulated, so this corpus is generated from the same
// fields and value shapes the simulated clients send (no real data, nothing
// to anonymize). Real pilot traffic replaces it with RV-Q-03.
func Pilot(seed uint64, n int, w io.Writer) error {
	r := rand.New(rand.NewPCG(seed, seed^0x9170))
	pick := func(xs []string) string { return xs[r.IntN(len(xs))] }
	family := []string{"Nguyễn", "Trần", "Lê", "Phạm", "Hoàng", "Huỳnh", "Phan", "Vũ", "Võ", "Đặng", "Bùi", "Đỗ"}
	given := []string{"Văn An", "Thị Bình", "Minh Châu", "Đức Dũng", "Thu Giang", "Thị Hoa", "Quốc Khánh", "Thùy Linh",
		"Hoàng Nam", "Kim Oanh", "Minh Phương", "Thanh Sơn", "Ngọc Trang", "Thảo Uyên", "Tường Vy"}
	notes := []string{"request from the app, it is ok & fine", "khách hàng đổi CMND sang CCCD", "re-check: photo was blurry",
		"name has a hyphen (Mary-Jane)", "O'Neil, second attempt", "chi nhánh Q.1 - quầy 3", "see ticket #4521",
		"birth date from the old card; please confirm", "verified at 08:30 -- branch staff", "đã gọi lại cho khách: OK"}
	kinds := []string{"id-front", "id-back", "selfie", "proof-of-address"}
	comments := []string{"photo of the front side", "ảnh mặt sau CCCD", "selfie with the card", "electricity bill (May)",
		"scan 300dpi; colour", "re-upload: the first one was cut"}
	agents := []string{"example-mobile/3.4 (Android 14)", "example-mobile/3.4 (iOS 18.0)", "example-web/1.0",
		"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/129.0 Safari/537.36"}
	enc := json.NewEncoder(w)
	enc.SetEscapeHTML(false)
	for i := 0; i < n; i++ {
		req := runner.Request{ID: fmt.Sprintf("pilot-%05d", i), Method: "POST", Headers: map[string]any{
			"Host": "api.example.test", "User-Agent": pick(agents), "Accept": "application/json",
		}}
		name := pick(family) + " " + pick(given)
		if r.IntN(2) == 0 {
			body, _ := json.Marshal(map[string]any{
				"document_id": fmt.Sprintf("%012d", r.Int64N(1e12)),
				"full_name":   name,
				"birth_date":  fmt.Sprintf("19%02d-%02d-%02d", 50+r.IntN(50), 1+r.IntN(12), 1+r.IntN(28)),
				"note":        pick(notes),
				"channel":     pick([]string{"app", "web", "branch"}),
			})
			req.URI, req.Body = "/v1/verify", string(body)
			req.Headers["Content-Type"] = "application/json"
		} else {
			boundary := fmt.Sprintf("----exampleBoundary%016x", r.Uint64())
			var b strings.Builder
			field := func(k, v string) {
				fmt.Fprintf(&b, "--%s\r\nContent-Disposition: form-data; name=%q\r\n\r\n%s\r\n", boundary, k, v)
			}
			field("customer_id", fmt.Sprint(r.IntN(1e6)))
			field("kind", pick(kinds))
			field("comment", pick(comments))
			// a JPEG-like part: header bytes, then printable filler (a JSON
			// string cannot carry raw binary); the rules see what NGINX passes
			fmt.Fprintf(&b, "--%s\r\nContent-Disposition: form-data; name=\"file\"; filename=\"%s.jpg\"\r\nContent-Type: image/jpeg\r\n\r\n",
				boundary, pick(kinds))
			b.WriteString("\xff\xd8\xff\xe0JFIF")
			for j := 0; j < 256+r.IntN(1024); j++ {
				b.WriteByte(byte(0x30 + r.IntN(0x4a)))
			}
			fmt.Fprintf(&b, "\r\n--%s--\r\n", boundary)
			req.URI, req.Body = "/v1/upload", b.String()
			req.Headers["Content-Type"] = "multipart/form-data; boundary=" + boundary
		}
		if err := enc.Encode(req); err != nil {
			return err
		}
	}
	return nil
}
