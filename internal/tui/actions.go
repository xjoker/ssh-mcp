package tui

import (
	"fmt"
	"strconv"
	"strings"

	"charm.land/bubbles/v2/textinput"
	tea "charm.land/bubbletea/v2"
	"charm.land/lipgloss/v2"

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
)

type formState struct {
	editing  bool
	original string
	fields   []textinput.Model
}

type confirmation struct {
	prompt string
	target row
}

func (form *formState) view() string {
	var builder strings.Builder
	if form.editing {
		builder.WriteString("Edit Machine\n\n")
	} else {
		builder.WriteString("Add Machine\n\n")
	}
	for _, field := range form.fields {
		builder.WriteString(field.View())
		builder.WriteByte('\n')
	}
	builder.WriteString("\n[Tab/Shift+Tab] Move  [Enter] Continue/Save  [Esc] Cancel")
	return overlayStyle.Render(builder.String())
}

func (m *Model) updateForm(message tea.Msg) (tea.Model, tea.Cmd) {
	if keyMessage, ok := message.(tea.KeyPressMsg); ok {
		switch keyMessage.String() {
		case "esc":
			m.form = nil
			m.err = ""
			return m, nil
		case "tab", "shift+tab":
			m.moveFormFocus(keyMessage.String() == "shift+tab")
			return m, nil
		case "enter":
			index := m.focusedField()
			if index < len(m.form.fields)-1 {
				m.moveFormFocus(false)
				return m, nil
			}
			m.saveForm()
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
	if backward {
		index = (index + len(m.form.fields) - 1) % len(m.form.fields)
	} else {
		index = (index + 1) % len(m.form.fields)
	}
	m.form.fields[index].Focus()
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
	m.err, m.message = "", ""
	m.form = newMachineForm(item.value, item.key, true)
	m.resizeForm()
}

func (m *Model) openDeleteConfirmation() {
	item, ok := m.currentRow()
	if !ok {
		m.err = "Select a machine first."
		return
	}
	m.err, m.message = "", ""
	m.confirmation = &confirmation{
		prompt: fmt.Sprintf("Delete machine %q? A configuration backup will be created first.", item.key),
		target: item,
	}
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
	latest, err := config.Load(m.options.ConfigPath)
	if err == nil {
		_, exists := latest.Servers[confirmation.target.key]
		if !exists {
			err = fmt.Errorf("machine %q no longer exists", confirmation.target.key)
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
	if err := m.refresh(); err != nil {
		m.err = "Reload failed: " + err.Error()
		m.message = ""
		return
	}
	m.err = ""
	m.message = "Machine deleted. Backup: " + backupPath
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

	latest, err := config.Load(m.options.ConfigPath)
	if err != nil {
		m.restoreAfterMutationFailure("Save failed", err)
		return
	}
	machine := config.ServerConfig{}
	previousAuth := ""
	if form.editing {
		var exists bool
		machine, exists = latest.Servers[form.original]
		if !exists {
			m.restoreAfterMutationFailure("Save failed", fmt.Errorf("machine %q no longer exists", form.original))
			return
		}
		previousAuth = machine.Auth
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

	switch authMode {
	case "agent":
		machine.KeyPath = ""
		machine.KeyPassphrase = config.CredRef{}
		machine.Password = config.CredRef{}
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
		machine.KeyPath = ""
		machine.KeyPassphrase = config.CredRef{}
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
	if err := m.refresh(); err != nil {
		m.err = "Reload failed: " + err.Error()
		return
	}
	m.form = nil
	m.err = ""
	m.message = "Machine saved."
	if authMode == "password" {
		m.message += " Store its password with: ssh-mcp auth set ssh-password:" + name
	}
}

func (m *Model) openDetails() {
	item, ok := m.currentRow()
	if !ok {
		m.err = "Select a machine first."
		return
	}
	m.err, m.message = "", ""
	m.detail = "Machine Details\n\n" + formatMachineDetails(item)
}

func newMachineForm(machine config.ServerConfig, name string, editing bool) *formState {
	fields := []textinput.Model{
		newInput("Name: ", name),
		newInput("Host: ", machine.Host),
		newInput("User: ", machine.User),
		newInput("Port: ", strconv.Itoa(effectivePort(machine.Port))),
		newInput("Auth [agent/key/password]: ", defaultString(machine.Auth, "agent")),
		newInput("Key file: ", machine.KeyPath),
		newInput("Default directory: ", machine.DefaultDir),
		newInput("Jump host: ", machine.ProxyJump),
		newInput("Tags [comma-separated]: ", strings.Join(machine.Tags, ",")),
		newInput("Description: ", machine.Description),
	}
	fields[0].Focus()
	return &formState{editing: editing, original: name, fields: fields}
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
