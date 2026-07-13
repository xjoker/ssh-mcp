package safety

import "testing"

// ---- CompilePolicy: mode handling -------------------------------------------

func TestCompilePolicy_EmptyMode_ReturnsNilPolicy(t *testing.T) {
	p, err := CompilePolicy("", nil, nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if p != nil {
		t.Fatalf("expected nil Policy for empty mode, got %+v", p)
	}
}

func TestCompilePolicy_UnrestrictedMode_ReturnsNilPolicy(t *testing.T) {
	p, err := CompilePolicy("unrestricted", []string{"^ls"}, nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if p != nil {
		t.Fatalf("expected nil Policy for unrestricted mode, got %+v", p)
	}
}

func TestCompilePolicy_InvalidMode_Errors(t *testing.T) {
	_, err := CompilePolicy("bogus", nil, nil)
	if err == nil {
		t.Fatal("expected error for invalid mode, got nil")
	}
}

func TestCompilePolicy_InvalidAllowRegex_Errors(t *testing.T) {
	_, err := CompilePolicy("restricted", []string{"("}, nil)
	if err == nil {
		t.Fatal("expected error for invalid allow_patterns regex, got nil")
	}
}

func TestCompilePolicy_InvalidDenyRegex_Errors(t *testing.T) {
	_, err := CompilePolicy("restricted", []string{"^ls"}, []string{"("})
	if err == nil {
		t.Fatal("expected error for invalid deny_patterns regex, got nil")
	}
}

// ---- nil Policy: zero-overhead path -----------------------------------------

func TestEvaluateCommand_NilPolicy_AlwaysPermits(t *testing.T) {
	var p *Policy
	if err := p.EvaluateCommand("rm -rf /"); err != nil {
		t.Fatalf("nil Policy must permit everything, got error: %v", err)
	}
}

// ---- restricted mode ---------------------------------------------------------

func TestEvaluateCommand_Restricted_AllowHit_Permits(t *testing.T) {
	p, err := CompilePolicy("restricted", []string{`^docker (ps|logs|inspect) `}, nil)
	if err != nil {
		t.Fatalf("CompilePolicy: %v", err)
	}
	if err := p.EvaluateCommand("docker ps -a"); err != nil {
		t.Fatalf("expected permit, got: %v", err)
	}
}

func TestEvaluateCommand_Restricted_NoAllow_DeniesAll(t *testing.T) {
	p, err := CompilePolicy("restricted", nil, nil)
	if err != nil {
		t.Fatalf("CompilePolicy: %v", err)
	}
	if err := p.EvaluateCommand("ls -la"); err == nil {
		t.Fatal("expected deny when allow_patterns is empty (fail-closed), got permit")
	}
}

func TestEvaluateCommand_Restricted_DenyBeatsAllow(t *testing.T) {
	p, err := CompilePolicy("restricted", []string{`^docker `}, []string{`--force`})
	if err != nil {
		t.Fatalf("CompilePolicy: %v", err)
	}
	if err := p.EvaluateCommand("docker rm --force x"); err == nil {
		t.Fatal("expected deny: DENY must beat ALLOW, got permit")
	}
}

func TestEvaluateCommand_Restricted_MultilineAnyLineDenies(t *testing.T) {
	p, err := CompilePolicy("restricted", []string{`^docker ps`}, nil)
	if err != nil {
		t.Fatalf("CompilePolicy: %v", err)
	}
	if err := p.EvaluateCommand("docker ps\nrm -rf /"); err == nil {
		t.Fatal("expected deny: second line has no allow match")
	}
}

func TestEvaluateCommand_Restricted_MultilineAllLinesAllowed_Permits(t *testing.T) {
	p, err := CompilePolicy("restricted", []string{`^docker ps`, `^docker logs`}, nil)
	if err != nil {
		t.Fatalf("CompilePolicy: %v", err)
	}
	if err := p.EvaluateCommand("docker ps\ndocker logs x"); err != nil {
		t.Fatalf("expected permit, got: %v", err)
	}
}

// ---- readonly mode: built-in allowlist --------------------------------------

func TestEvaluateCommand_Readonly_BuiltinAllow_Permits(t *testing.T) {
	p, err := CompilePolicy("readonly", nil, nil)
	if err != nil {
		t.Fatalf("CompilePolicy: %v", err)
	}
	permitted := []string{
		"ls -la",
		"docker logs x --tail 100",
		"journalctl -u nginx -g err",
		"systemctl status nginx",
		"ip addr",
		"ip addr show",
		"ip route",
		"ip link",
		"ip link show eth0",
	}
	for _, cmd := range permitted {
		if err := p.EvaluateCommand(cmd); err != nil {
			t.Errorf("EvaluateCommand(%q): expected permit, got: %v", cmd, err)
		}
	}
}

func TestEvaluateCommand_Readonly_BuiltinDeny_Denies(t *testing.T) {
	p, err := CompilePolicy("readonly", nil, nil)
	if err != nil {
		t.Fatalf("CompilePolicy: %v", err)
	}
	denied := []string{
		"rm -rf /",
		"sudo ls",
		"docker rm x",
		"systemctl restart nginx",
		"ip link set eth0 down",
		"find / -delete",
		"env rm -rf /",
	}
	for _, cmd := range denied {
		if err := p.EvaluateCommand(cmd); err == nil {
			t.Errorf("EvaluateCommand(%q): expected deny, got permit", cmd)
		}
	}
}

// Hardening: entries that look read-only but carry a write/exec escape.
// rg is excluded entirely (--pre runs an arbitrary preprocessor command);
// hostname/date only pass in their argument-free / format-only read forms;
// journalctl's log-destroying maintenance flags are built-in denied.
func TestEvaluateCommand_Readonly_EscapeHatches_Denied(t *testing.T) {
	p, err := CompilePolicy("readonly", nil, nil)
	if err != nil {
		t.Fatalf("CompilePolicy: %v", err)
	}
	denied := []string{
		"rg --pre 'rm -rf /' pattern file", // arbitrary command execution
		"rg pattern file",                  // rg removed from builtin allowlist
		"hostname evil",                    // sets the hostname
		"hostname -F /tmp/name",            // sets the hostname from file
		"date -s '2000-01-01'",             // sets the system clock
		"date --set='2000-01-01'",
		"journalctl --vacuum-time=1s", // destroys logs
		"journalctl --vacuum-size=1M",
		"journalctl --rotate",
		"journalctl -u nginx --flush",
		"journalctl --setup-keys", // writes FSS sealing keys
		"journalctl --sync",       // forces disk flush
	}
	for _, cmd := range denied {
		if err := p.EvaluateCommand(cmd); err == nil {
			t.Errorf("EvaluateCommand(%q): expected deny, got permit", cmd)
		}
	}
	permitted := []string{
		"hostname",
		"date",
		"date +%s",
		"journalctl -u nginx --since yesterday",
	}
	for _, cmd := range permitted {
		if err := p.EvaluateCommand(cmd); err != nil {
			t.Errorf("EvaluateCommand(%q): expected permit, got: %v", cmd, err)
		}
	}
}

func TestEvaluateCommand_Readonly_UserAllowAppendsToBuiltin(t *testing.T) {
	p, err := CompilePolicy("readonly", []string{`^php artisan `}, nil)
	if err != nil {
		t.Fatalf("CompilePolicy: %v", err)
	}
	if err := p.EvaluateCommand("php artisan queue:work"); err != nil {
		t.Fatalf("expected permit via user allow_patterns, got: %v", err)
	}
	// Built-in allowlist entries must still work alongside the user addition.
	if err := p.EvaluateCommand("ls -la"); err != nil {
		t.Fatalf("expected permit via builtin allowlist, got: %v", err)
	}
}

func TestEvaluateCommand_Readonly_DenyPatternsBeatBuiltinAllow(t *testing.T) {
	p, err := CompilePolicy("readonly", nil, []string{`^ls -la`})
	if err != nil {
		t.Fatalf("CompilePolicy: %v", err)
	}
	if err := p.EvaluateCommand("ls -la"); err == nil {
		t.Fatal("expected deny: deny_patterns must beat the builtin allowlist")
	}
	// Unaffected builtin commands remain permitted.
	if err := p.EvaluateCommand("pwd"); err != nil {
		t.Fatalf("expected permit for unaffected builtin command, got: %v", err)
	}
}

// ---- metacharacter / injection battery (readonly) ---------------------------

func TestEvaluateCommand_Readonly_MetacharBattery_AllDenied(t *testing.T) {
	p, err := CompilePolicy("readonly", nil, nil)
	if err != nil {
		t.Fatalf("CompilePolicy: %v", err)
	}
	battery := []string{
		"ls; rm -rf /",
		"cat /etc/passwd | sh",
		"cat > /etc/x",
		"cat $(rm -rf /)",
		"cat `rm -rf /`",
		"ls && rm x",
		"ls || rm x",
		"cat <(rm x)",
		"'l''s' /",
		"ls\nrm -rf /",
	}
	for _, cmd := range battery {
		if err := p.EvaluateCommand(cmd); err == nil {
			t.Errorf("EvaluateCommand(%q): expected deny (injection battery), got permit", cmd)
		}
	}
}

// ---- DenyNonCommandWrites -----------------------------------------------------

func TestDenyNonCommandWrites_NilPolicy_False(t *testing.T) {
	var p *Policy
	if p.DenyNonCommandWrites() {
		t.Fatal("nil Policy must not deny non-command writes")
	}
}

func TestDenyNonCommandWrites_ReadonlyPolicy_True(t *testing.T) {
	p, err := CompilePolicy("readonly", nil, nil)
	if err != nil {
		t.Fatalf("CompilePolicy: %v", err)
	}
	if !p.DenyNonCommandWrites() {
		t.Fatal("readonly Policy must deny non-command writes")
	}
}

func TestDenyNonCommandWrites_RestrictedPolicy_True(t *testing.T) {
	p, err := CompilePolicy("restricted", []string{"^ls"}, nil)
	if err != nil {
		t.Fatalf("CompilePolicy: %v", err)
	}
	if !p.DenyNonCommandWrites() {
		t.Fatal("restricted Policy must deny non-command writes")
	}
}
