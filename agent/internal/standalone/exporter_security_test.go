package standalone

import (
	"os"
	"path/filepath"
	"testing"

	eventv1 "github.com/strata/strata/agent/gen/strata/event/v1"
)

func TestExporterRequiresDestination(t *testing.T) {
	if e, err := NewEventExporter("", "", ""); err == nil {
		_ = e.Close()
		t.Fatal("accepted exporter that silently discards every event")
	}
}

func TestExporterExplicitStdoutIsBorrowed(t *testing.T) {
	for _, name := range []string{"stdout", "-"} {
		e, err := NewEventExporter(name, "", "")
		if err != nil {
			t.Fatal(err)
		}
		if e.file != os.Stdout {
			t.Fatal("stdout destination has no output writer")
		}
		if err := e.Close(); err != nil {
			t.Fatal(err)
		}
		if _, err := os.Stdout.Stat(); err != nil {
			t.Fatal("closed process stdout")
		}
	}
}

func TestExporterRejectsWritesAfterClose(t *testing.T) {
	e, err := NewEventExporter(filepath.Join(t.TempDir(), "events.jsonl"), "", "")
	if err != nil {
		t.Fatal(err)
	}
	if err := e.Close(); err != nil {
		t.Fatal(err)
	}
	if err := e.Export(&eventv1.Event{BlockId: "example-event"}); err == nil {
		t.Fatal("counted an event as exported after closing destination")
	}
	exported, dropped := e.Stats()
	if exported != 0 || dropped != 1 {
		t.Fatalf("exported=%d dropped=%d", exported, dropped)
	}
}
