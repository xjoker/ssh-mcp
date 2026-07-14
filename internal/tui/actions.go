package tui

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"reflect"
	"strconv"
	"strings"

	"charm.land/bubbles/v2/textinput"
	tea "charm.land/bubbletea/v2"
	"charm.land/lipgloss/v2"
	gossh "golang.org/x/crypto/ssh"

	"github.com/xjoker/ssh-mcp/internal/auth"
	"github.com/xjoker/ssh-mcp/internal/config"
)

const (
	fieldName = iota
	fieldHost
	fieldUser
	fieldPort
	fieldAuth
	fieldKeyPath
	fieldDefaultDir
	fieldProxyJump
	fieldTags
	fieldDescription
	fieldMode
	fieldAllowPatterns
	fieldDenyPatterns
)

type formState struct {
	editing  bool
	original string
	fields   []textinput.Model
}

type passwordState struct {
	machine string
	fields  []textinput.Model
}

type confirmationKind int

const (
	confirmationDelete confirmationKind = iota
	confirmationTrust
	confirmationPasswordDelete
)

type confirmation struct {
	kind       confirmationKind
	prompt     string
	target     row
	credential config.CredRef
	addr       string
	key        gossh.PublicKey
}

func (form *formState) view(width, height int, errText string) string {
	title := "ADD MACHINE"
	if form.editing {
		title = "EDIT MACHINE"
	}
	if height > 0 && height < 18 {
		index := 0
		visible := form.visibleFields()
		for _, candidate := range visible {
			if form.fields[candidate].Focused() {
				index = candidate
				break
			}
		}
		field := form.fields[index]
		position := 0
		for candidate, visibleIndex := range visible {
			if visibleIndex == index {
				position = candidate
			}
		}
		content := headerStyle.Render(title) + overlayError(errText) + "\n\n" + labelStyle.Render(fmt.Sprintf("FIELD %d OF %d", position+1, len(visible))) + "\n" + form.renderField(index, field) + "\n\n" + subtleStyle.Render("Tab move  ·  Enter continue/save  ·  Esc cancel")
		return placeOverlay(width, height, content)
	}
	var builder strings.Builder
	builder.WriteString(headerStyle.Render(title))
	builder.WriteString(overlayError(errText))
	builder.WriteString("\n\n")
	groups := map[int]string{fieldName: "TARGET", fieldAuth: "AUTHENTICATION", fieldDefaultDir: "ROUTING", fieldTags: "METADATA", fieldMode: "POLICY"}
	for _, index := range form.visibleFields() {
		field := form.fields[index]
		if group := groups[index]; group != "" {
			builder.WriteString(labelStyle.Bold(true).Render(group))
			builder.WriteByte('\n')
		}
		builder.WriteString(form.renderField(index, field))
		builder.WriteByte('\n')
	}
	builder.WriteString("\n" + subtleStyle.Render("Tab/Shift+Tab move  ·  ←/→ change selector  ·  Enter continue/save  ·  Esc cancel"))
	return placeOverlay(width, height, builder.String())
}

func (form *formState) renderField(index int, field textinput.Model) string {
	if index != fieldAuth && index != fieldMode {
		return field.View()
	}
	prefix := "  "
	if field.Focused() {
		prefix = "› "
	}
	label := "Auth"
	if index == fieldMode {
		label = "Mode"
	}
	return prefix + label + "  ‹ " + terminalText(field.Value()) + " ›"
}

func (form *formState) visibleFields() []int {
	authMode := strings.ToLower(strings.TrimSpace(form.fields[fieldAuth].Value()))
	policyMode := strings.ToLower(strings.TrimSpace(form.fields[fieldMode].Value()))
	visible := make([]int, 0, len(form.fields))
	for index := range form.fields {
		if index == fieldKeyPath && authMode != "key" {
			continue
		}
		if (index == fieldAllowPatterns || index == fieldDenyPatterns) && policyMode != "readonly" && policyMode != "restricted" {
			continue
		}
		visible = append(visible, index)
	}
	return visible
}

func (form *passwordState) view(width, height int, errText string) string {
	var builder strings.Builder
	builder.WriteString(headerStyle.Render("MANAGE PASSWORD  "+terminalText(form.machine)) + overlayError(errText) + "\n\n")
	builder.WriteString("Password is stored in the OS keychain. It is never written to config.toml.\n\n")
	for _, field := range form.fields {
		builder.WriteString(field.View())
		builder.WriteByte('\n')
	}
	builder.WriteString("\n" + subtleStyle.Render("Tab moves  ·  Enter stores password  ·  Ctrl+D deletes stored password  ·  Esc cancels"))
	return placeOverlay(width, height, builder.String())
}

func overlayError(errText string) string {
	if errText == "" {
		return ""
	}
	return "\n" + errorStyle.Render("ERROR  "+terminalText(errText))
}

func (m *Model) updateForm(message tea.Msg) (tea.Model, tea.Cmd) {
	if keyMessage, ok := message.(tea.KeyPressMsg); ok {
		switch keyMessage.String() {
		case "esc":
			m.clearForm()
			m.err = ""
			return m, nil
		case "tab", "shift+tab":
			m.moveFormFocus(keyMessage.String() == "shift+tab")
			return m, nil
		case "left", "h":
			if m.focusedField() == fieldAuth {
				m.cycleAuth(-1)
				return m, nil
			}
			if m.focusedField() == fieldMode {
				m.cycleMode(-1)
				return m, nil
			}
		case "right", "l", " ":
			if m.focusedField() == fieldAuth {
				m.cycleAuth(1)
				return m, nil
			}
			if m.focusedField() == fieldMode {
				m.cycleMode(1)
				return m, nil
			}
		case "enter":
			index := m.focusedField()
			visible := m.form.visibleFields()
			if index != visible[len(visible)-1] {
				m.moveFormFocus(false)
				return m, nil
			}
			m.saveForm()
			return m, nil
		}
		if m.focusedField() == fieldAuth || m.focusedField() == fieldMode {
			return m, nil
		}
	}
	index := m.focusedField()
	updated, command := m.form.fields[index].Update(message)
	m.form.fields[index] = updated
	return m, command
}

func (m *Model) focusedField() int {
	for index, field := range m.form.fields {
		if field.Focused() {
			return index
		}
	}
	return 0
}

func (m *Model) moveFormFocus(backward bool) {
	index := m.focusedField()
	m.form.fields[index].Blur()
	visible := m.form.visibleFields()
	position := 0
	for candidate, visibleIndex := range visible {
		if visibleIndex == index {
			position = candidate
			break
		}
	}
	if backward {
		position = (position + len(visible) - 1) % len(visible)
	} else {
		position = (position + 1) % len(visible)
	}
	m.form.fields[visible[position]].Focus()
}

func (m *Model) cycleAuth(delta int) {
	modes := []string{"agent", "key", "password"}
	current := strings.ToLower(strings.TrimSpace(m.form.fields[fieldAuth].Value()))
	index := 0
	for candidate, mode := range modes {
		if mode == current {
			index = candidate
			break
		}
	}
	index = (index + delta + len(modes)) % len(modes)
	m.form.fields[fieldAuth].SetValue(modes[index])
}

func (m *Model) cycleMode(delta int) {
	modes := []string{"unrestricted", "readonly", "restricted"}
	current := strings.ToLower(strings.TrimSpace(m.form.fields[fieldMode].Value()))
	index := 0
	for candidate, mode := range modes {
		if mode == current {
			index = candidate
			break
		}
	}
	index = (index + delta + len(modes)) % len(modes)
	m.form.fields[fieldMode].SetValue(modes[index])
}

func (m *Model) openAdd() {
	m.err, m.message = "", ""
	m.form = newMachineForm(config.ServerConfig{}, "", false)
	m.resizeForm()
}

func (m *Model) openEdit() {
	item, ok := m.currentRow()
	if !ok {
		m.err = "Select a machine first."
		return
	}
	m.err, m.message, m.menuOpen = "", "", false
	m.form = newMachineForm(item.value, item.key, true)
	m.resizeForm()
}

func (m *Model) clearForm() {
	if m.form != nil {
		for index := range m.form.fields {
			m.form.fields[index].SetValue("")
		}
	}
	m.form = nil
}

func (m *Model) openActionMenu() {
	if _, ok := m.currentRow(); !ok {
		m.err = "Select a machine first."
		return
	}
	m.err, m.message, m.menuOpen = "", "", true
}

func (m *Model) updateActionMenu(message tea.Msg) (tea.Model, tea.Cmd) {
	keyMessage, ok := message.(tea.KeyPressMsg)
	if !ok {
		return m, nil
	}
	switch keyMessage.String() {
	case "esc", "enter":
		m.menuOpen = false
	case "t":
		item, ok := m.currentRow()
		m.menuOpen = false
		if ok {
			return m, m.startConnectionTest(item.key)
		}
	case "c":
		m.menuOpen = false
		return m.requestConnect()
	case "e":
		m.openEdit()
	case "p":
		m.menuOpen = false
		m.openPasswordManager()
	case "k":
		item, ok := m.currentRow()
		m.menuOpen = false
		if ok {
			return m, m.startHostKeyPreview(item)
		}
	case "d":
		m.menuOpen = false
		m.openDeleteConfirmation()
	}
	return m, nil
}

func (m *Model) renderActionMenu() string {
	item, _ := m.currentRow()
	credentialHint := "available for password authentication"
	if item.value.Auth != "password" {
		credentialHint = "edit Auth to password first" // #nosec G101 -- UI guidance, not a credential value
	}
	content := headerStyle.Render("MACHINE ACTIONS  "+terminalText(item.key)) + "\n\n" +
		warningStyle.Render("t") + "  Test connection\n" +
		warningStyle.Render("c") + "  Connect shell\n" +
		warningStyle.Render("e") + "  Edit machine\n" +
		warningStyle.Render("p") + "  Manage password  " + subtleStyle.Render("("+credentialHint+")") + "\n" +
		warningStyle.Render("k") + "  Trust host key\n" +
		errorStyle.Render("d") + "  Delete machine\n\n" + subtleStyle.Render("Esc closes this menu")
	return m.centerOverlay(content)
}

func (m *Model) requestConnect() (tea.Model, tea.Cmd) {
	item, ok := m.currentRow()
	if !ok {
		m.err = "Select a machine first."
		return m, nil
	}
	m.connectTarget = item.key
	return m, tea.Quit
}

func (m *Model) startConnectionTest(name string) tea.Cmd {
	m.connectionGenerations[name]++
	generation := m.connectionGenerations[name]
	m.connectionStates[name] = connectionState{phase: connectionTesting, detail: "Opening SSH connection..."}
	cfg := m.config
	test := m.testConnection
	return func() tea.Msg {
		ctx, cancel := context.WithTimeout(context.Background(), connectionTestTimeout)
		defer cancel()
		return connectionResultMsg{name: name, generation: generation, err: test(ctx, name, cfg)}
	}
}

func (m *Model) openPasswordManager() {
	item, ok := m.currentRow()
	if !ok {
		m.err = "Select a machine first."
		return
	}
	if item.value.Auth != "password" {
		m.err = "Password management requires Auth to be set to password. Edit the machine first."
		return
	}
	first := newInput("Password: ", "")
	second := newInput("Confirm password: ", "")
	first.EchoMode, second.EchoMode = textinput.EchoPassword, textinput.EchoPassword
	first.EchoCharacter, second.EchoCharacter = '•', '•'
	first.Focus()
	m.password = &passwordState{machine: item.key, fields: []textinput.Model{first, second}}
	m.err, m.message = "", ""
	m.resizePasswordForm()
}

func (m *Model) updatePassword(message tea.Msg) (tea.Model, tea.Cmd) {
	if keyMessage, ok := message.(tea.KeyPressMsg); ok {
		switch keyMessage.String() {
		case "esc":
			m.clearPasswordForm()
			m.err = ""
			return m, nil
		case "tab", "shift+tab":
			secondFocused := m.password.fields[1].Focused()
			m.password.fields[0].Blur()
			m.password.fields[1].Blur()
			index := 1
			if keyMessage.String() == "shift+tab" || secondFocused {
				index = 0
			}
			m.password.fields[index].Focus()
			return m, nil
		case "ctrl+d":
			m.openPasswordDeleteConfirmation()
			return m, nil
		case "enter":
			if m.password.fields[0].Focused() {
				m.password.fields[0].Blur()
				m.password.fields[1].Focus()
				return m, nil
			}
			m.savePassword()
			return m, nil
		}
	}
	index := 0
	if m.password.fields[1].Focused() {
		index = 1
	}
	updated, command := m.password.fields[index].Update(message)
	m.password.fields[index] = updated
	return m, command
}

func (m *Model) savePassword() {
	if m.password == nil {
		return
	}
	password := m.password.fields[0].Value()
	confirmation := m.password.fields[1].Value()
	if password == "" {
		m.err = "Please enter a password."
		return
	}
	if password != confirmation {
		m.err = "Passwords do not match."
		return
	}
	name := m.password.machine
	latest, err := config.Load(m.options.ConfigPath)
	if err != nil {
		m.err = "Password save failed: " + err.Error()
		return
	}
	machine, ok := latest.Servers[name]
	if !ok {
		m.err = fmt.Sprintf("Password save failed: machine %q no longer exists", name)
		return
	}
	service, account := "ssh-mcp", "ssh-password:"+name
	targetRef, err := config.ParseCredRef("keychain:" + service + ":" + account)
	if err != nil {
		m.err = "Password save failed: " + err.Error()
		return
	}
	if machine.Password.Kind == config.CredRefKeychain {
		service, account, targetRef = machine.Password.Service, machine.Password.Account, machine.Password
	}
	changedRef := machine.Password != targetRef
	secret := []byte(password)
	err = m.credentials.Set(service, account, secret)
	for index := range secret {
		secret[index] = 0
	}
	if err != nil {
		m.err = "Password save failed: " + err.Error()
		return
	}
	if changedRef {
		machine.Password = targetRef
		if err = config.UpsertServer(latest, name, machine); err == nil {
			err = config.Save(m.options.ConfigPath, latest)
		}
		if err != nil {
			m.err = "Password save failed: credential was stored in the OS keychain, but the configuration update was not confirmed: " + err.Error()
			return
		}
	} else {
		current, loadErr := config.Load(m.options.ConfigPath)
		if loadErr != nil {
			m.err = "Password save failed: credential was stored in the OS keychain, but the active configuration could not be confirmed: " + loadErr.Error()
			return
		}
		currentMachine, exists := current.Servers[name]
		if !exists || currentMachine.Password != targetRef {
			m.err = "Password save failed: credential was stored in the OS keychain, but the machine credential reference changed; review the machine and try again."
			return
		}
	}
	m.credentialStates[name] = credentialStored
	delete(m.credentialErrors, name)
	m.invalidateCredentialCheck(name)
	m.connectionGenerations[name]++
	m.connectionStates[name] = connectionState{phase: connectionUntested}
	m.clearPasswordForm()
	m.err, m.message = "", "Password stored in the OS keychain."
	if err := m.refresh(); err != nil {
		m.err, m.message = "Reload failed: "+err.Error(), ""
	}
}

func (m *Model) openPasswordDeleteConfirmation() {
	if m.password == nil {
		return
	}
	latest, err := config.Load(m.options.ConfigPath)
	if err != nil {
		m.err = "Password delete failed: " + err.Error()
		return
	}
	machine, ok := latest.Servers[m.password.machine]
	if !ok {
		m.err = fmt.Sprintf("Password delete failed: machine %q no longer exists", m.password.machine)
		return
	}
	switch machine.Password.Kind {
	case config.CredRefNone:
		m.err = "Password delete failed: password is not stored."
		return
	case config.CredRefEnv, config.CredRefPlaintext:
		m.err = "Password delete failed: password is externally managed and cannot be deleted from the OS keychain."
		return
	case config.CredRefKeychain:
	default:
		m.err = "Password delete failed: password is externally managed."
		return
	}
	m.confirmation = &confirmation{
		kind:       confirmationPasswordDelete,
		prompt:     fmt.Sprintf("Delete the stored password for %q? This cannot be recovered.", m.password.machine),
		credential: machine.Password,
	}
}

func (m *Model) deletePassword(expected config.CredRef) {
	if m.password == nil {
		return
	}
	name := m.password.machine
	latest, err := config.Load(m.options.ConfigPath)
	if err != nil {
		m.err = "Password delete failed: " + err.Error()
		return
	}
	machine, ok := latest.Servers[name]
	if !ok {
		m.err = fmt.Sprintf("Password delete failed: machine %q no longer exists", name)
		return
	}
	ref := machine.Password
	if ref != expected {
		m.err = "Password delete cancelled: the credential reference changed after confirmation. Reopen password management and confirm again."
		return
	}
	switch ref.Kind {
	case config.CredRefNone:
		m.err = "Password delete failed: password is not stored."
		return
	case config.CredRefEnv, config.CredRefPlaintext:
		m.err = "Password delete failed: password is externally managed and cannot be deleted from the OS keychain."
		return
	case config.CredRefKeychain:
		// Delete only the exact credential reference from the latest on-disk
		// configuration; never guess a machine-scoped canonical account.
	default:
		m.err = "Password delete failed: password is externally managed."
		return
	}
	err = m.credentials.Delete(ref.Service, ref.Account)
	if err != nil && !errors.Is(err, auth.ErrKeyNotFound) {
		m.err = "Password delete failed: " + err.Error()
		return
	}
	m.credentialStates[name] = credentialMissing
	delete(m.credentialErrors, name)
	m.invalidateCredentialCheck(name)
	m.connectionGenerations[name]++
	m.connectionStates[name] = connectionState{phase: connectionUntested}
	m.clearPasswordForm()
	m.err, m.message = "", "Stored password deleted."
}

func (m *Model) clearPasswordForm() {
	if m.password != nil {
		for index := range m.password.fields {
			m.password.fields[index].SetValue("")
		}
	}
	m.password = nil
}

func (m *Model) checkSelectedCredential() tea.Cmd {
	item, ok := m.currentRow()
	if !ok || item.value.Auth != "password" {
		return nil
	}
	ref := item.value.Password
	if ref.Kind != config.CredRefKeychain {
		m.invalidateCredentialCheck(item.key)
		m.credentialStates[item.key] = credentialExternal
		delete(m.credentialErrors, item.key)
		return nil
	}
	name, store := item.key, m.credentials
	m.credentialGenerations[name]++
	generation := m.credentialGenerations[name]
	m.credentialStates[name] = credentialChecking
	return func() tea.Msg {
		state, err := store.Status(context.Background(), ref)
		return credentialResultMsg{name: name, generation: generation, state: state, err: err, ref: ref}
	}
}

func (m *Model) invalidateCredentialCheck(name string) {
	m.credentialGenerations[name]++
}

func (m *Model) credentialStatus(item row) credentialState {
	if item.value.Auth != "password" {
		return credentialExternal
	}
	if item.value.Password.Kind != config.CredRefKeychain {
		return credentialExternal
	}
	state := m.credentialStates[item.key]
	if state == "" {
		return credentialChecking
	}
	return state
}

func (m *Model) authLabel(item row) string {
	if item.value.Auth != "password" {
		return defaultString(item.value.Auth, "agent")
	}
	return "password · " + string(m.credentialStatus(item))
}

func (m *Model) openDeleteConfirmation() {
	item, ok := m.currentRow()
	if !ok {
		m.err = "Select a machine first."
		return
	}
	m.err, m.message = "", ""
	m.confirmation = &confirmation{kind: confirmationDelete, prompt: fmt.Sprintf("Delete machine %q? A configuration backup will be created first.", item.key), target: item}
}

func (m *Model) renderConfirmation() string {
	return m.centerOverlay(headerStyle.Render("CONFIRM ACTION") + "\n\n" + terminalText(m.confirmation.prompt) + "\n\n" + warningStyle.Render("y") + " confirm   " + labelStyle.Render("n / Esc cancel"))
}

func (m *Model) updateConfirmation(message tea.Msg) (tea.Model, tea.Cmd) {
	keyMessage, ok := message.(tea.KeyPressMsg)
	if !ok {
		return m, nil
	}
	switch keyMessage.String() {
	case "n", "esc":
		m.confirmation = nil
	case "y":
		confirmation := m.confirmation
		m.confirmation = nil
		m.executeConfirmation(confirmation)
	}
	return m, nil
}

func (m *Model) executeConfirmation(confirmation *confirmation) {
	if confirmation == nil {
		return
	}
	if confirmation.kind == confirmationTrust {
		err := m.commitHostKey(confirmation.addr, confirmation.key)
		if err != nil {
			m.err, m.message = "Trust failed: "+err.Error(), ""
			return
		}
		m.err, m.message, m.pendingHostKey = "", "Host key trusted.", nil
		return
	}
	if confirmation.kind == confirmationPasswordDelete {
		m.deletePassword(confirmation.credential)
		return
	}
	latest, err := config.Load(m.options.ConfigPath)
	retainedCredential := false
	if err == nil {
		machine, exists := latest.Servers[confirmation.target.key]
		if !exists {
			err = fmt.Errorf("machine %q no longer exists", confirmation.target.key)
		} else if !reflect.DeepEqual(machine, confirmation.target.value) {
			err = fmt.Errorf("machine %q changed after confirmation; review it and try again", confirmation.target.key)
		} else {
			retainedCredential = machine.Password.Kind == config.CredRefKeychain
		}
	}
	backupPath := ""
	if err == nil {
		backupPath, err = config.Backup(m.options.ConfigPath)
	}
	if err == nil {
		err = config.RemoveServer(latest, confirmation.target.key)
	}
	if err == nil {
		err = config.Save(m.options.ConfigPath, latest)
	}
	if err != nil {
		m.restoreAfterMutationFailure("Delete failed", err)
		return
	}
	delete(m.connectionStates, confirmation.target.key)
	m.connectionGenerations[confirmation.target.key]++
	delete(m.credentialStates, confirmation.target.key)
	m.invalidateCredentialCheck(confirmation.target.key)
	delete(m.credentialErrors, confirmation.target.key)
	if err := m.refresh(); err != nil {
		m.err, m.message = "Reload failed: "+err.Error(), ""
		return
	}
	m.err, m.message = "", "Machine deleted. Backup: "+backupPath
	if retainedCredential {
		m.message += " Stored credential was retained."
	}
}

func (m *Model) saveForm() {
	form := m.form
	for _, field := range form.fields {
		if containsTerminalControl(field.Value()) {
			m.err = "Machine fields must not contain terminal control characters."
			return
		}
	}
	port, err := strconv.Atoi(strings.TrimSpace(form.fields[fieldPort].Value()))
	if err != nil || port < 1 || port > 65535 {
		m.err = "Port must be an integer from 1 to 65535."
		return
	}
	name := strings.TrimSpace(form.fields[fieldName].Value())
	if form.editing && name != form.original {
		m.err = "A machine name cannot be changed while editing."
		return
	}
	authMode := strings.ToLower(strings.TrimSpace(form.fields[fieldAuth].Value()))
	if authMode != "agent" && authMode != "key" && authMode != "password" {
		m.err = "Authentication must be agent, key, or password."
		return
	}
	policyMode := strings.ToLower(strings.TrimSpace(form.fields[fieldMode].Value()))
	if policyMode != "unrestricted" && policyMode != "readonly" && policyMode != "restricted" {
		m.err = "Policy mode must be unrestricted, readonly, or restricted."
		return
	}
	var allowPatterns, denyPatterns []string
	if policyMode == "readonly" || policyMode == "restricted" {
		allowPatterns, err = parsePatternJSON(form.fields[fieldAllowPatterns].Value())
		if err != nil {
			m.err = "Allow patterns must be a JSON array of strings: " + err.Error()
			return
		}
		denyPatterns, err = parsePatternJSON(form.fields[fieldDenyPatterns].Value())
		if err != nil {
			m.err = "Deny patterns must be a JSON array of strings: " + err.Error()
			return
		}
	}
	latest, err := config.Load(m.options.ConfigPath)
	if err != nil {
		m.restoreAfterMutationFailure("Save failed", err)
		return
	}
	machine, previousAuth := config.ServerConfig{}, ""
	retainedCredential := false
	if form.editing {
		var exists bool
		machine, exists = latest.Servers[form.original]
		if !exists {
			m.restoreAfterMutationFailure("Save failed", fmt.Errorf("machine %q no longer exists", form.original))
			return
		}
		previousAuth = machine.Auth
		retainedCredential = previousAuth == "password" && authMode != "password" && machine.Password.Kind == config.CredRefKeychain
	}
	machine.Host = strings.TrimSpace(form.fields[fieldHost].Value())
	machine.User = strings.TrimSpace(form.fields[fieldUser].Value())
	machine.Port = port
	machine.Auth = authMode
	machine.KeyPath = strings.TrimSpace(form.fields[fieldKeyPath].Value())
	machine.DefaultDir = strings.TrimSpace(form.fields[fieldDefaultDir].Value())
	machine.ProxyJump = strings.ToLower(strings.TrimSpace(form.fields[fieldProxyJump].Value()))
	machine.Tags = splitValues(form.fields[fieldTags].Value())
	machine.Description = strings.TrimSpace(form.fields[fieldDescription].Value())
	if policyMode == "unrestricted" {
		machine.Mode = ""
		machine.AllowPatterns, machine.DenyPatterns = nil, nil
	} else {
		machine.Mode = policyMode
		machine.AllowPatterns = append([]string(nil), allowPatterns...)
		machine.DenyPatterns = append([]string(nil), denyPatterns...)
	}
	switch authMode {
	case "agent":
		machine.KeyPath, machine.KeyPassphrase, machine.Password = "", config.CredRef{}, config.CredRef{}
	case "key":
		if machine.KeyPath == "" {
			m.err = "Key file is required for key authentication."
			return
		}
		machine.Password = config.CredRef{}
		if previousAuth != "key" {
			machine.KeyPassphrase = config.CredRef{}
		}
	case "password":
		machine.KeyPath, machine.KeyPassphrase = "", config.CredRef{}
		if previousAuth != "password" {
			machine.Password = config.CredRef{}
		}
		if machine.Password.IsZero() {
			machine.Password, err = config.ParseCredRef("keychain:ssh-mcp:ssh-password:" + name)
			if err != nil {
				m.err = "Password reference is invalid: " + err.Error()
				return
			}
		}
	}
	if form.editing {
		err = config.UpsertServer(latest, name, machine)
	} else {
		err = config.AddServer(latest, name, machine)
	}
	if err == nil {
		err = config.Save(m.options.ConfigPath, latest)
	}
	if err != nil {
		m.restoreAfterMutationFailure("Save failed", err)
		return
	}
	m.connectionGenerations[name]++
	m.connectionStates[name] = connectionState{phase: connectionUntested}
	m.clearForm()
	m.err, m.message = "", "Machine saved."
	if retainedCredential {
		m.message += " Stored credential was retained."
	}
	if authMode == "password" {
		m.message += " Press Enter, then p, to store its password."
	}
	if err := m.refresh(); err != nil {
		m.err, m.message = "Reload failed: "+err.Error(), ""
	}
}

func newMachineForm(machine config.ServerConfig, name string, editing bool) *formState {
	fields := []textinput.Model{
		newInput("Name: ", name),
		newInput("Host: ", machine.Host),
		newInput("Account: ", machine.User),
		newInput("Port: ", strconv.Itoa(effectivePort(machine.Port))),
		newInput("Auth: ", defaultString(machine.Auth, "agent")),
		newInput("Key file: ", machine.KeyPath),
		newInput("Default directory: ", machine.DefaultDir),
		newInput("Jump host: ", machine.ProxyJump),
		newInput("Tags: ", strings.Join(machine.Tags, ",")),
		newInput("Description: ", machine.Description),
		newInput("Mode: ", defaultString(machine.Mode, "unrestricted")),
		newInput("Allow patterns (JSON): ", formatPatternJSON(machine.AllowPatterns)),
		newInput("Deny patterns (JSON): ", formatPatternJSON(machine.DenyPatterns)),
	}
	fields[0].Focus()
	return &formState{editing: editing, original: name, fields: fields}
}

func formatPatternJSON(patterns []string) string {
	if patterns == nil {
		patterns = []string{}
	}
	encoded, _ := json.Marshal(patterns)
	return string(encoded)
}

func parsePatternJSON(value string) ([]string, error) {
	if strings.TrimSpace(value) == "" {
		return nil, nil
	}
	var patterns []string
	if err := json.Unmarshal([]byte(value), &patterns); err != nil {
		return nil, err
	}
	if patterns == nil {
		return []string{}, nil
	}
	return patterns, nil
}

func newInput(prompt, value string) textinput.Model {
	field := textinput.New()
	field.Prompt = prompt
	field.SetValue(terminalText(value))
	field.SetWidth(58)
	return field
}

func (m *Model) resizeForm() {
	if m.form == nil || m.width <= 0 {
		return
	}
	contentWidth := max(20, m.width-10)
	for index := range m.form.fields {
		promptWidth := lipgloss.Width(m.form.fields[index].Prompt)
		m.form.fields[index].SetWidth(max(4, min(58, contentWidth-promptWidth)))
	}
}

func (m *Model) resizePasswordForm() {
	if m.password == nil || m.width <= 0 {
		return
	}
	for index := range m.password.fields {
		promptWidth := lipgloss.Width(m.password.fields[index].Prompt)
		m.password.fields[index].SetWidth(max(4, min(48, m.width-10-promptWidth)))
	}
}

func splitValues(value string) []string {
	var values []string
	for _, part := range strings.Split(value, ",") {
		if trimmed := strings.TrimSpace(part); trimmed != "" {
			values = append(values, trimmed)
		}
	}
	return values
}

func defaultString(value, fallback string) string {
	if value == "" {
		return fallback
	}
	return value
}
