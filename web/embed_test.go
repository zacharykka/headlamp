package web

import (
	"io/fs"
	"strings"
	"testing"
)

func TestDistFS(t *testing.T) {
	sub, err := DistFS()
	if err != nil {
		t.Fatalf("DistFS() returned error: %v", err)
	}

	raw, err := fs.ReadFile(sub, "index.html")
	if err != nil {
		t.Fatalf("ReadFile(index.html) failed: %v", err)
	}

	html := string(raw)
	if !strings.Contains(html, `<div id="root"></div>`) {
		t.Fatalf("index.html missing root mount point: %s", html)
	}
}
