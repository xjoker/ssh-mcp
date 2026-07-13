package mcpserver

import (
	"testing"

	"github.com/xjoker/ssh-mcp/internal/tools"
)

// TestAnnotations_AllToolsHaveAnnotations verifies every registered tool
// carries a non-nil Annotations struct with a non-empty Title.
func TestAnnotations_AllToolsHaveAnnotations(t *testing.T) {
	for _, tl := range tools.All() {
		if tl.Annotations == nil {
			t.Errorf("tool %q: Annotations is nil", tl.Name)
			continue
		}
		if tl.Annotations.Title == "" {
			t.Errorf("tool %q: Annotations.Title is empty", tl.Name)
		}
	}
}

// TestAnnotations_ReadOnlyMatchesDestructiveSet verifies ReadOnlyHint is the
// exact complement of the dispatch-layer destructiveTools set, and that
// read-only tools never claim DestructiveHint.
func TestAnnotations_ReadOnlyMatchesDestructiveSet(t *testing.T) {
	for _, tl := range tools.All() {
		if tl.Annotations == nil {
			continue
		}
		wantReadOnly := !isDestructive(tl.Name)
		if tl.Annotations.ReadOnlyHint != wantReadOnly {
			t.Errorf("tool %q: ReadOnlyHint=%v, want %v (isDestructive=%v)",
				tl.Name, tl.Annotations.ReadOnlyHint, wantReadOnly, isDestructive(tl.Name))
		}
		if tl.Annotations.ReadOnlyHint && tl.Annotations.DestructiveHint {
			t.Errorf("tool %q: ReadOnlyHint=true but DestructiveHint=true", tl.Name)
		}
	}
}

// TestAnnotations_BuildMCPToolMapsFields spot-checks that the mapping helper
// used by registerOne carries tools.Annotations onto mcp.Tool.Annotations
// faithfully for one destructive and one read-only tool.
func TestAnnotations_BuildMCPToolMapsFields(t *testing.T) {
	find := func(name string) tools.Tool {
		for _, tl := range tools.All() {
			if tl.Name == name {
				return tl
			}
		}
		t.Fatalf("tool %q not found in registry", name)
		return tools.Tool{}
	}

	cases := []string{"ssh_exec", "sftp_list"}
	for _, name := range cases {
		tl := find(name)
		if tl.Annotations == nil {
			t.Fatalf("tool %q: Annotations is nil", name)
		}

		mcpTool := buildMCPTool(tl)
		if mcpTool.Annotations == nil {
			t.Fatalf("tool %q: mcp.Tool.Annotations is nil", name)
		}
		got := mcpTool.Annotations
		want := tl.Annotations
		if got.Title != want.Title {
			t.Errorf("tool %q: Title=%q, want %q", name, got.Title, want.Title)
		}
		if got.ReadOnlyHint != want.ReadOnlyHint {
			t.Errorf("tool %q: ReadOnlyHint=%v, want %v", name, got.ReadOnlyHint, want.ReadOnlyHint)
		}
		if got.DestructiveHint == nil || *got.DestructiveHint != want.DestructiveHint {
			t.Errorf("tool %q: DestructiveHint=%v, want %v", name, got.DestructiveHint, want.DestructiveHint)
		}
		if got.IdempotentHint != want.IdempotentHint {
			t.Errorf("tool %q: IdempotentHint=%v, want %v", name, got.IdempotentHint, want.IdempotentHint)
		}
		if got.OpenWorldHint == nil || *got.OpenWorldHint != want.OpenWorldHint {
			t.Errorf("tool %q: OpenWorldHint=%v, want %v", name, got.OpenWorldHint, want.OpenWorldHint)
		}
	}
}
