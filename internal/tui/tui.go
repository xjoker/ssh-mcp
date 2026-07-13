// Package tui provides the local machine configuration manager.
package tui

import (
	"errors"
	"fmt"
	"sort"
	"strings"
	"unicode"

	"charm.land/bubbles/v2/help"
	"charm.land/bubbles/v2/key"
	"charm.land/bubbles/v2/list"
	tea "charm.land/bubbletea/v2"
	"charm.land/lipgloss/v2"

	"github.com/xjoker/ssh-mcp/internal/config"
)

// Options identifies the configuration managed by the TUI.
type Options struct {
	ConfigPath string
}

// Run opens the machine manager.
func Run(options Options) error {
	model, err := New(options)
	if err != nil {
		return err
	}
	_, err = tea.NewProgram(model).Run()
	return err
}

// Model is the Bubble Tea state for the machine manager.
type Model struct {
	options      Options
	config       *config.Config
	list         list.Model
	help         help.Model
	keys         keyMap
	width        int
	height       int
	form         *formState
	confirmation *confirmation
	detail       string
	err          string
	message      string
}

type row struct {
	key         string
	title       string
	description string
	value       config.ServerConfig
}

func (item row) FilterValue() string { return item.title + " " + item.description }
func (item row) Title() string       { return item.title }
func (item row) Description() string { return item.description }

type keyMap struct {
	Quit    key.Binding
	Refresh key.Binding
	Search  key.Binding
	Add     key.Binding
	Edit    key.Binding
	Delete  key.Binding
	Details key.Binding
	Help    key.Binding
}

func defaultKeyMap() keyMap {
	return keyMap{
		Quit:    key.NewBinding(key.WithKeys("q", "ctrl+c"), key.WithHelp("q", "quit")),
		Refresh: key.NewBinding(key.WithKeys("r"), key.WithHelp("r", "reload")),
		Search:  key.NewBinding(key.WithKeys("/"), key.WithHelp("/", "filter")),
		Add:     key.NewBinding(key.WithKeys("a"), key.WithHelp("a", "add")),
		Edit:    key.NewBinding(key.WithKeys("e"), key.WithHelp("e", "edit")),
		Delete:  key.NewBinding(key.WithKeys("d"), key.WithHelp("d", "delete")),
		Details: key.NewBinding(key.WithKeys("enter"), key.WithHelp("enter", "details")),
		Help:    key.NewBinding(key.WithKeys("?"), key.WithHelp("?", "help")),
	}
}

func (keys keyMap) ShortHelp() []key.Binding {
	return []key.Binding{keys.Search, keys.Add, keys.Edit, keys.Details, keys.Help, keys.Quit}
}

func (keys keyMap) FullHelp() [][]key.Binding {
	return [][]key.Binding{{keys.Add, keys.Edit, keys.Delete, keys.Refresh}, {keys.Search, keys.Details, keys.Help, keys.Quit}}
}

// New creates a machine manager from the local configuration.
func New(options Options) (*Model, error) {
	if options.ConfigPath == "" {
		return nil, errors.New("tui: config path is required")
	}

	delegate := list.NewDefaultDelegate()
	delegate.ShowDescription = true
	m := &Model{
		options: options,
		list:    list.New(nil, delegate, 0, 0),
		help:    help.New(),
		keys:    defaultKeyMap(),
	}
	m.list.Title = "Machines"
	m.list.SetStatusBarItemName("machine", "machines")
	m.list.SetShowHelp(false)
	if err := m.refresh(); err != nil {
		return nil, err
	}
	return m, nil
}

func (m *Model) Init() tea.Cmd { return nil }

// Update handles machine navigation and configuration mutations.
func (m *Model) Update(message tea.Msg) (tea.Model, tea.Cmd) {
	if size, ok := message.(tea.WindowSizeMsg); ok {
		m.width, m.height = size.Width, size.Height
		m.resizeList()
		m.resizeForm()
		m.help.SetWidth(size.Width)
		return m, nil
	}
	if m.form != nil {
		return m.updateForm(message)
	}
	if m.help.ShowAll {
		if keyMessage, ok := message.(tea.KeyPressMsg); ok && (key.Matches(keyMessage, m.keys.Help) || keyMessage.String() == "esc") {
			m.help.ShowAll = false
		}
		return m, nil
	}
	if m.detail != "" {
		if keyMessage, ok := message.(tea.KeyPressMsg); ok && (keyMessage.String() == "esc" || key.Matches(keyMessage, m.keys.Details)) {
			m.detail = ""
		}
		return m, nil
	}
	if m.confirmation != nil {
		return m.updateConfirmation(message)
	}

	switch message := message.(type) {
	case tea.KeyPressMsg:
		if m.list.SettingFilter() {
			break
		}
		switch {
		case key.Matches(message, m.keys.Quit):
			return m, tea.Quit
		case key.Matches(message, m.keys.Help):
			m.help.ShowAll = true
			return m, nil
		case key.Matches(message, m.keys.Refresh):
			m.reload()
			return m, nil
		case key.Matches(message, m.keys.Add):
			m.openAdd()
			return m, nil
		case key.Matches(message, m.keys.Edit):
			m.openEdit()
			return m, nil
		case key.Matches(message, m.keys.Delete):
			m.openDeleteConfirmation()
			return m, nil
		case key.Matches(message, m.keys.Details):
			m.openDetails()
			return m, nil
		}
	}

	updated, command := m.list.Update(message)
	m.list = updated
	return m, command
}

func (m *Model) View() tea.View {
	content := m.renderHeader() + "\n" + m.renderBody()
	if m.err != "" {
		content += "\n" + errorStyle.Render(terminalText(m.err))
	} else if m.message != "" {
		content += "\n" + messageStyle.Render(terminalText(m.message))
	}
	content += "\n" + m.help.View(m.keys)

	if m.confirmation != nil {
		content = overlayStyle.Render(terminalText(m.confirmation.prompt) + "\n\n[y] Confirm  [n/Esc] Cancel")
	}
	if m.detail != "" {
		content = overlayStyle.Render(m.detail + "\n\n[Enter/Esc] Close")
	}
	if m.help.ShowAll {
		content = overlayStyle.Render("Keyboard Help\n\n" + m.help.View(m.keys) + "\n\n[?/Esc] Close")
	}
	if m.form != nil {
		content = m.form.view()
	}

	view := tea.NewView(content)
	view.AltScreen = true
	view.WindowTitle = "ssh-mcp Machine Manager"
	return view
}

var (
	headerStyle  = lipgloss.NewStyle().Bold(true).Foreground(lipgloss.Color("63"))
	panelStyle   = lipgloss.NewStyle().Border(lipgloss.RoundedBorder()).Padding(0, 1)
	errorStyle   = lipgloss.NewStyle().Foreground(lipgloss.Color("9"))
	messageStyle = lipgloss.NewStyle().Foreground(lipgloss.Color("10"))
	overlayStyle = lipgloss.NewStyle().Border(lipgloss.RoundedBorder()).Padding(1, 2).Margin(1)
)

func (m *Model) renderHeader() string {
	return headerStyle.Render("ssh-mcp Machine Manager") + "\n" + "Config: " + terminalText(m.options.ConfigPath)
}

func (m *Model) renderBody() string {
	if m.width < 86 {
		return m.list.View()
	}
	leftWidth := max(38, m.width*45/100)
	rightWidth := max(32, m.width-leftWidth-2)
	details := panelStyle.Width(rightWidth - 2).Height(max(4, m.height-7)).Render(m.selectedSummary())
	return lipgloss.JoinHorizontal(lipgloss.Top, m.list.View(), " ", details)
}

func (m *Model) selectedSummary() string {
	item, ok := m.currentRow()
	if !ok {
		return headerStyle.Render("Machine Details") + "\n\nNo machine selected."
	}
	return headerStyle.Render("Machine Details") + "\n\n" + formatMachineDetails(item)
}

func (m *Model) resizeList() {
	width := m.width
	if width >= 86 {
		width = max(38, width*45/100)
	}
	m.list.SetSize(width, max(6, m.height-6))
}

func (m *Model) reload() {
	if err := m.refresh(); err != nil {
		m.err = err.Error()
		m.message = ""
		return
	}
	m.err = ""
	m.message = "Configuration reloaded."
}

func (m *Model) restoreAfterMutationFailure(prefix string, mutationErr error) {
	m.err = prefix + ": " + mutationErr.Error()
	m.message = ""
	if err := m.refresh(); err != nil {
		m.err += "; reloading the on-disk configuration also failed: " + err.Error()
	}
}

func (m *Model) refresh() error {
	cfg, err := config.Load(m.options.ConfigPath)
	if err != nil {
		return fmt.Errorf("tui: load config: %w", err)
	}
	m.config = cfg
	filterState := m.list.FilterState()
	filterValue := m.list.FilterValue()
	m.list.SetItems(m.machineItems())
	if filterState != list.Unfiltered {
		m.list.SetFilterText(filterValue)
		if filterState == list.Filtering {
			m.list.SetFilterState(list.Filtering)
		}
	}
	return nil
}

func (m *Model) machineItems() []list.Item {
	names := make([]string, 0, len(m.config.Servers))
	for name := range m.config.Servers {
		names = append(names, name)
	}
	sort.Strings(names)
	items := make([]list.Item, 0, len(names))
	for _, name := range names {
		machine := m.config.Servers[name]
		items = append(items, row{
			key:         name,
			title:       terminalText(name),
			description: terminalText(fmt.Sprintf("%s@%s:%d  •  %s", machine.User, machine.Host, effectivePort(machine.Port), machine.Auth)),
			value:       machine,
		})
	}
	return items
}

func (m *Model) currentRow() (row, bool) {
	item := m.list.SelectedItem()
	entry, ok := item.(row)
	return entry, ok
}

func formatMachineDetails(item row) string {
	machine := item.value
	lines := []string{
		"Name: " + terminalText(item.key),
		terminalText(fmt.Sprintf("Address: %s:%d", machine.Host, effectivePort(machine.Port))),
		"User: " + terminalText(machine.User),
		"Authentication: " + terminalText(machine.Auth),
		"Key file: " + valueOrDash(machine.KeyPath),
		"Default directory: " + valueOrDash(machine.DefaultDir),
		"Jump host: " + valueOrDash(machine.ProxyJump),
		"Tags: " + valueOrDash(strings.Join(machine.Tags, ", ")),
		"Description: " + valueOrDash(machine.Description),
	}
	return strings.Join(lines, "\n")
}

func effectivePort(port int) int {
	if port == 0 {
		return 22
	}
	return port
}

func valueOrDash(value string) string {
	if value == "" {
		return "—"
	}
	return terminalText(value)
}

func terminalText(value string) string {
	return strings.Map(func(character rune) rune {
		if unicode.IsControl(character) {
			return '�'
		}
		return character
	}, value)
}

func containsTerminalControl(value string) bool {
	return strings.IndexFunc(value, unicode.IsControl) >= 0
}
