package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/strata/strata/tools/strata-mutate/internal/mutate"
)

func TestSeedRequestCarriers(t *testing.T) {
	path := seed{ID: "p", Payload: "(alert)(1)", Carrier: "path"}
	r, ok := seedRequest("p/seed", path, mutate.Variant{Value: path.Payload})
	if !ok || r.URI != "/v1/items/%28alert%29%281%29" {
		t.Fatalf("path: %v %+v", ok, r)
	}
	if _, ok := seedRequest("p/split", path, mutate.Variant{Value: "(al", Split: "ert)"}); ok {
		t.Fatal("parameter splitting has no meaning in a path")
	}
	b64 := seed{ID: "b", Payload: "<svg onload=alert(1)>", Carrier: "path", Encoding: "base64url"}
	r, ok = seedRequest("b/seed", b64, mutate.Variant{Value: b64.Payload})
	if !ok || r.URI != "/v1/items/PHN2ZyBvbmxvYWQ9YWxlcnQoMSk-" {
		t.Fatalf("base64url: %v %+v", ok, r)
	}
	if _, ok := seedRequest("b/double", b64, mutate.Variant{Value: "%253C", Encoded: true}); ok {
		t.Fatal("URL encodings of base64 text are not variants")
	}
	form := seed{ID: "f", Payload: "1 or 1=1", Carrier: "form"}
	r, _ = seedRequest("f/seed", form, mutate.Variant{Value: form.Payload})
	if r.Method != "POST" || !strings.Contains(r.Body, "comment=1+or+1%3D1") {
		t.Fatalf("form: %+v", r)
	}
}

func TestLoadSeedsRefusesBadLines(t *testing.T) {
	for name, line := range map[string]string{
		"carrier":  `{"id":"a","payload":"x","carrier":"header"}`,
		"encoding": `{"id":"a","payload":"x","carrier":"path","encoding":"hex"}`,
		"no id":    `{"payload":"x","carrier":"path"}`,
		"twice":    `{"id":"a","payload":"x","carrier":"path"}` + "\n" + `{"id":"a","payload":"y","carrier":"path"}`,
	} {
		dir := t.TempDir()
		if err := os.WriteFile(filepath.Join(dir, "s.jsonl"), []byte(line+"\n"), 0o644); err != nil {
			t.Fatal(err)
		}
		if _, err := loadSeeds(dir); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}

func TestRepositorySeedsLoad(t *testing.T) {
	seeds, err := loadSeeds(filepath.Join("..", "..", "corpus", "regression"))
	if err != nil {
		t.Fatal(err)
	}
	if len(seeds) < 60 {
		t.Fatalf("%d seeds", len(seeds))
	}
}
