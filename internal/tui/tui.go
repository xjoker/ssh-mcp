// Package tui provides the local SSH operations console.
package tui

import (
	"context"
	"errors"
	"fmt"
	"sort"
	"strings"
	"unicode"

	"charm.land/bubbles/v2/key"
	"charm.land/bubbles/v2/list"
	tea "charm.land/bubbletea/v2"
	"charm.land/lipgloss/v2"
	gossh "golang.org/x/crypto/ssh"

	"github.com/xjoker/ssh-mcp/internal/config"
)

// Options identifies the configuration managed by the TUI.
type Options struct {
	ConfigPath string
}

// Run opens the operations console. Interactive shells leave the alternate
// screen, run against the selected machine, then return to a fresh console.
func Run(options Options) error {
	for {
		model, err := New(options)
		if err != nil {
			return err
		}
		result, err := tea.NewProgram(model).Run()
		if err != nil {
			return err
		}
		finished, ok := result.(*Model)
		if !ok || finished.connectTarget == "" {
			return nil
		}
		if err := connectInteractive(options.ConfigPath, finished.connectTarget); err != nil {
			fmt.Printf("\n%s\nPress Enter to return to ssh-mcp...", connectionClosedMessage(err))
			_, _ = fmt.Scanln()
		}
	}
}

func connectionClosedMessage(err error) string {
	return "Connection closed: " + terminalText(err.Error())
}

type connectionPhase string

const (
	connectionUntested connectionPhase = "Untested"
	connectionTesting  connectionPhase = "Testing"
	connectionReady    connectionPhase = "Ready"
	connectionFailed   connectionPhase = "Failed"
)

type connectionState struct {
	phase  connectionPhase
	detail string
}

type credentialState string

const (
	credentialChecking    credentialState = "Checking"
	credentialStored      credentialState = "Stored"
	credentialMissing     credentialState = "Missing"
	credentialUnavailable credentialState = "Unavailable"
	credentialExternal    credentialState = "External"
)

type credentialStore interface {
	Status(context.Context, config.CredRef) (credentialState, error)
	Set(service, account string, secret []byte) error
	Delete(service, account string) error
}

type testConnectionFunc func(context.Context, string, *config.Config) error
type fetchHostKeyFunc func(string) (gossh.PublicKey, error)
type commitHostKeyFunc func(string, gossh.PublicKey) error

// Model is the Bubble Tea state for the operations console.
type Model struct {
	options Options
	config  *config.Config
	list    list.Model
	keys    keyMap
	width   int
	height  int

	form         *formState
	password     *passwordState
	confirmation *confirmation
	menuOpen     bool
	helpOpen     bool
	err          string
	message      string

	credentials           credentialStore
	credentialStates      map[string]credentialState
	credentialErrors      map[string]string
	credentialGenerations map[string]uint64
	connectionStates      map[string]connectionState
	connectionGenerations map[string]uint64
	hostKeyGeneration     uint64
	testConnection        testConnectionFunc
	fetchHostKey          fetchHostKeyFunc
	commitHostKey         commitHostKeyFunc
	pendingHostKey        gossh.PublicKey
	connectTarget         string
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
	Navigate key.Binding
	Quit     key.Binding
	Refresh  key.Binding
	Search   key.Binding
	Add      key.Binding
	Actions  key.Binding
	Help     key.Binding
}

func defaultKeyMap() keyMap {
	return keyMap{
		Navigate: key.NewBinding(key.WithKeys("j", "k", "up", "down"), key.WithHelp("j/k", "navigate")),
		Quit:     key.NewBinding(key.WithKeys("q", "ctrl+c"), key.WithHelp("q", "quit")),
		Refresh:  key.NewBinding(key.WithKeys("r"), key.WithHelp("r", "reload")),
		Search:   key.NewBinding(key.WithKeys("/"), key.WithHelp("/", "search")),
		Add:      key.NewBinding(key.WithKeys("a"), key.WithHelp("a", "add")),
		Actions:  key.NewBinding(key.WithKeys("enter"), key.WithHelp("enter", "actions")),
		Help:     key.NewBinding(key.WithKeys("h", "?"), key.WithHelp("h", "help")),
	}
}

func (keys keyMap) shortHelp() []key.Binding {
	return []key.Binding{keys.Search, keys.Add, keys.Refresh, keys.Actions, keys.Help, keys.Quit}
}

// New creates an operations console from the local configuration.
func New(options Options) (*Model, error) {
	if options.ConfigPath == "" {
		return nil, errors.New("tui: config path is required")
	}
	delegate := list.NewDefaultDelegate()
	m := &Model{
		options:               options,
		list:                  list.New(nil, delegate, 0, 0),
		keys:                  defaultKeyMap(),
		credentials:           osCredentialStore{},
		credentialStates:      make(map[string]credentialState),
		credentialErrors:      make(map[string]string),
		credentialGenerations: make(map[string]uint64),
		connectionStates:      make(map[string]connectionState),
		connectionGenerations: make(map[string]uint64),
		testConnection:        defaultConnectionTest,
		fetchHostKey:          defaultFetchHostKey,
		commitHostKey:         defaultCommitHostKey,
	}
	m.list.SetShowTitle(false)
	m.list.SetShowStatusBar(false)
	m.list.SetShowPagination(false)
	m.list.SetShowHelp(false)
	if err := m.refresh(); err != nil {
		return nil, err
	}
	return m, nil
}

func (m *Model) Init() tea.Cmd { return m.checkSelectedCredential() }

// Update handles navigation, overlays, connection state and mutations.
func (m *Model) Update(message tea.Msg) (tea.Model, tea.Cmd) {
	if size, ok := message.(tea.WindowSizeMsg); ok {
		m.width, m.height = size.Width, size.Height
		m.resizeList()
		m.resizeForm()
		m.resizePasswordForm()
		return m, nil
	}
	switch message := message.(type) {
	case connectionResultMsg:
		if message.generation != m.connectionGenerations[message.name] {
			return m, nil
		}
		if _, exists := m.config.Servers[message.name]; !exists {
			return m, nil
		}
		state := connectionState{phase: connectionReady, detail: "Connection succeeded."}
		if message.err != nil {
			state = connectionState{phase: connectionFailed, detail: terminalText(message.err.Error())}
		}
		m.connectionStates[message.name] = state
		return m, nil
	case credentialResultMsg:
		if message.generation != m.credentialGenerations[message.name] {
			return m, nil
		}
		machine, exists := m.config.Servers[message.name]
		if !exists || machine.Password != message.ref {
			return m, nil
		}
		if message.err != nil {
			m.credentialStates[message.name] = credentialUnavailable
			m.credentialErrors[message.name] = sanitizeCredentialError(message.err, message.ref)
		} else {
			m.credentialStates[message.name] = message.state
			delete(m.credentialErrors, message.name)
		}
		return m, nil
	case hostKeyResultMsg:
		if !m.acceptHostKeyResult(message) {
			return m, nil
		}
		m.handleHostKeyResult(message)
		return m, nil
	}
	if m.confirmation != nil {
		return m.updateConfirmation(message)
	}
	if m.form != nil {
		return m.updateForm(message)
	}
	if m.password != nil {
		return m.updatePassword(message)
	}
	if m.menuOpen {
		return m.updateActionMenu(message)
	}
	if m.helpOpen {
		if keyMessage, ok := message.(tea.KeyPressMsg); ok && (keyMessage.String() == "esc" || key.Matches(keyMessage, m.keys.Help)) {
			m.helpOpen = false
		}
		return m, nil
	}

	previous, _ := m.currentRow()
	if keyMessage, ok := message.(tea.KeyPressMsg); ok && !m.list.SettingFilter() {
		switch {
		case key.Matches(keyMessage, m.keys.Quit):
			return m, tea.Quit
		case key.Matches(keyMessage, m.keys.Help):
			m.helpOpen = true
			return m, nil
		case key.Matches(keyMessage, m.keys.Refresh):
			m.reload()
			return m, m.checkSelectedCredential()
		case key.Matches(keyMessage, m.keys.Add):
			m.openAdd()
			return m, nil
		case key.Matches(keyMessage, m.keys.Actions):
			m.openActionMenu()
			return m, nil
		case keyMessage.String() == "e":
			m.openEdit()
			return m, nil
		case keyMessage.String() == "c":
			return m.requestConnect()
		}
	}

	updated, command := m.list.Update(message)
	m.list = updated
	current, _ := m.currentRow()
	if current.key != "" && current.key != previous.key {
		return m, tea.Batch(command, m.checkSelectedCredential())
	}
	return m, command
}

func (m *Model) View() tea.View {
	content := m.renderHeader() + "\n" + m.renderBody() + "\n" + m.renderStatus() + "\n" + m.renderFooter()
	switch {
	case m.confirmation != nil:
		content = m.renderConfirmation()
	case m.menuOpen:
		content = m.renderActionMenu()
	case m.helpOpen:
		content = m.renderHelp()
	case m.form != nil:
		content = m.form.view(m.width, m.height, m.err)
	case m.password != nil:
		content = m.password.view(m.width, m.height, m.err)
	}
	if m.width > 0 && m.height > 0 {
		content = canvasStyle.Width(m.width).Height(m.height).MaxWidth(m.width).MaxHeight(m.height).Render(content)
	}
	view := tea.NewView(content)
	view.AltScreen = true
	view.WindowTitle = "ssh-mcp Operations Console"
	return view
}

var (
	canvasStyle   = lipgloss.NewStyle().Foreground(lipgloss.Color("#F0F0F0")).Background(lipgloss.Color("#181818"))
	headerStyle   = lipgloss.NewStyle().Bold(true).Foreground(lipgloss.Color("#64D2FF")).Background(lipgloss.Color("#181818"))
	subtleStyle   = lipgloss.NewStyle().Foreground(lipgloss.Color("#787878")).Background(lipgloss.Color("#181818"))
	labelStyle    = lipgloss.NewStyle().Foreground(lipgloss.Color("#B4B4B4")).Background(lipgloss.Color("#181818"))
	selectedStyle = lipgloss.NewStyle().Bold(true).Foreground(lipgloss.Color("#F0F0F0")).Background(lipgloss.Color("#373741"))
	panelStyle    = lipgloss.NewStyle().Border(lipgloss.NormalBorder()).BorderForeground(lipgloss.Color("#508CDC")).Background(lipgloss.Color("#181818")).Padding(0, 1)
	errorStyle    = lipgloss.NewStyle().Foreground(lipgloss.Color("#FF5A5A")).Background(lipgloss.Color("#181818"))
	messageStyle  = lipgloss.NewStyle().Foreground(lipgloss.Color("#50DC78")).Background(lipgloss.Color("#181818"))
	warningStyle  = lipgloss.NewStyle().Foreground(lipgloss.Color("#FFDC50")).Background(lipgloss.Color("#181818"))
	overlayStyle  = lipgloss.NewStyle().Border(lipgloss.NormalBorder()).BorderForeground(lipgloss.Color("#508CDC")).Background(lipgloss.Color("#181818")).Padding(1, 2)
)

func (m *Model) renderHeader() string {
	title := headerStyle.Render("SSH-MCP  /  OPERATIONS CONSOLE")
	pathWidth := max(12, m.width-8)
	path := subtleStyle.Render("Config  " + truncate(terminalText(m.options.ConfigPath), pathWidth))
	return title + "\n" + path
}

func (m *Model) renderBody() string {
	if len(m.list.VisibleItems()) == 0 && !m.list.SettingFilter() {
		return panelStyle.Width(max(20, m.width-2)).Render("No machines yet. Press a to add one.")
	}
	if m.width >= 96 {
		leftWidth := max(60, m.width*64/100)
		rightWidth := max(30, m.width-leftWidth-1)
		left := m.renderMachineTable(leftWidth)
		right := panelStyle.Width(rightWidth - 3).Height(max(7, m.height-8)).Render(m.selectedSummary())
		return lipgloss.JoinHorizontal(lipgloss.Top, left, " ", right)
	}
	table := m.renderMachineTable(max(20, m.width))
	if m.width >= 64 && m.height >= 22 {
		return table + "\n" + panelStyle.Width(max(20, m.width-3)).Render(m.selectedSummaryCompact())
	}
	return table
}

func (m *Model) renderMachineTable(width int) string {
	if m.list.SettingFilter() || m.list.FilterState() != list.Unfiltered {
		filter := m.list.FilterInput.View()
		if filter != "" {
			filter = warningStyle.Render("SEARCH  ") + filter + "\n"
		}
		return filter + m.renderRows(width)
	}
	return m.renderRows(width)
}

func (m *Model) renderRows(width int) string {
	columns := tableColumnsFor(width)
	var lines []string
	lines = append(lines, labelStyle.Bold(true).Render(formatColumns(columns, []string{"NAME", "ADDRESS", "AUTH", "POLICY", "STATE"})))
	lines = append(lines, subtleStyle.Render(strings.Repeat("─", max(1, width-1))))
	items := m.list.VisibleItems()
	limit := max(1, m.height-9)
	if m.width < 64 {
		limit = max(1, m.height-7)
	}
	start := 0
	if selected := m.list.Index(); selected >= limit {
		start = selected - limit + 1
	}
	end := min(len(items), start+limit)
	for index := start; index < end; index++ {
		item := items[index].(row)
		values := []string{item.key, fmt.Sprintf("%s@%s:%d", item.value.User, item.value.Host, effectivePort(item.value.Port)), m.authLabel(item), policyLabel(item.value), string(m.connectionPhase(item.key))}
		line := formatColumns(columns, values)
		if index == m.list.Index() {
			line = selectedStyle.Width(max(1, width-1)).Render("› " + truncate(line, max(1, width-3)))
		} else {
			line = "  " + truncate(line, max(1, width-3))
		}
		lines = append(lines, line)
	}
	return strings.Join(lines, "\n")
}

func tableColumnsFor(width int) []int {
	switch {
	case width >= 76:
		return []int{16, max(14, width-57), 14, 12, 11}
	case width >= 52:
		return []int{14, max(18, width-40), 12, 0, 10}
	default:
		return []int{max(10, width/3), max(14, width-width/3-3), 0, 0, 0}
	}
}

func formatColumns(widths []int, values []string) string {
	parts := make([]string, 0, len(widths))
	for index, width := range widths {
		if width <= 0 {
			continue
		}
		value := ""
		if index < len(values) {
			value = terminalText(values[index])
		}
		parts = append(parts, fmt.Sprintf("%-*s", width, truncate(value, width)))
	}
	return strings.TrimRight(strings.Join(parts, " "), " ")
}

func truncate(value string, width int) string {
	if width <= 0 {
		return ""
	}
	if lipgloss.Width(value) <= width {
		return value
	}
	if width == 1 {
		return "…"
	}
	runes := []rune(value)
	for len(runes) > 0 && lipgloss.Width(string(runes))+1 > width {
		runes = runes[:len(runes)-1]
	}
	return string(runes) + "…"
}

func (m *Model) selectedSummary() string {
	item, ok := m.currentRow()
	if !ok {
		return headerStyle.Render("MACHINE") + "\n\nNo machine selected."
	}
	details := formatMachineDetails(item, m.credentialStatus(item))
	if credentialError := m.credentialErrors[item.key]; credentialError != "" {
		details += "\nCredential error  " + credentialError
	}
	return headerStyle.Render("MACHINE  "+terminalText(item.key)) + "\n\n" + details + "\n\n" + subtleStyle.Render("Enter opens machine actions")
}

func (m *Model) selectedSummaryCompact() string {
	item, ok := m.currentRow()
	if !ok {
		return "No machine selected."
	}
	return fmt.Sprintf("%s  %s@%s:%d  Auth %s  State %s", terminalText(item.key), terminalText(item.value.User), terminalText(item.value.Host), effectivePort(item.value.Port), m.authLabel(item), m.connectionPhase(item.key))
}

func (m *Model) renderStatus() string {
	if m.err != "" {
		return errorStyle.Render("ERROR  " + terminalText(m.err))
	}
	if m.message != "" {
		return messageStyle.Render("DONE   " + terminalText(m.message))
	}
	item, ok := m.currentRow()
	if ok {
		state := m.connectionStates[item.key]
		if state.detail != "" {
			return subtleStyle.Render(string(state.phase) + "  " + terminalText(state.detail))
		}
	}
	return subtleStyle.Render("Ready")
}

func (m *Model) renderFooter() string {
	bindings := m.keys.shortHelp()
	if m.width > 0 && m.width < 60 {
		bindings = []key.Binding{m.keys.Navigate, m.keys.Actions, m.keys.Quit}
	}
	parts := make([]string, 0, len(bindings))
	for _, binding := range bindings {
		help := binding.Help()
		parts = append(parts, warningStyle.Render(help.Key)+" "+labelStyle.Render(help.Desc))
	}
	return strings.Join(parts, subtleStyle.Render("  │  "))
}

func (m *Model) renderHelp() string {
	return m.centerOverlay("KEYBOARD HELP\n\n↑/k, ↓/j  Navigate machines\n/          Search\na          Add machine\ne          Edit selected machine\nEnter      Open machine actions\nr          Reload configuration\nh or ?     Open this help\nq          Quit\n\nEsc closes any panel.")
}

func (m *Model) centerOverlay(content string) string {
	return placeOverlay(m.width, m.height, content)
}

func placeOverlay(width, height int, content string) string {
	contentWidth := min(72, max(20, width-6))
	style := overlayStyle
	if height > 0 && height < 16 {
		style = lipgloss.NewStyle().Border(lipgloss.NormalBorder()).BorderForeground(lipgloss.Color("#508CDC")).Background(lipgloss.Color("#181818")).Padding(0, 1)
		contentWidth = min(72, max(20, width-4))
	}
	box := style.Width(contentWidth).MaxWidth(max(1, width)).MaxHeight(max(1, height)).Render(content)
	if width <= 0 || height <= 0 {
		return box
	}
	return lipgloss.Place(width, height, lipgloss.Center, lipgloss.Center, box, lipgloss.WithWhitespaceStyle(canvasStyle))
}

func (m *Model) resizeList() {
	width := m.width
	if width >= 96 {
		width = max(60, width*64/100)
	}
	m.list.SetSize(max(20, width), max(4, m.height-7))
}

func (m *Model) reload() {
	if err := m.refresh(); err != nil {
		m.err, m.message = err.Error(), ""
		return
	}
	m.err, m.message = "", "Configuration reloaded."
}

func (m *Model) restoreAfterMutationFailure(prefix string, mutationErr error) {
	m.err, m.message = prefix+": "+mutationErr.Error(), ""
	if err := m.refresh(); err != nil {
		m.err += "; reloading the on-disk configuration also failed: " + err.Error()
	}
}

func (m *Model) refresh() error {
	cfg, err := config.Load(m.options.ConfigPath)
	if err != nil {
		return fmt.Errorf("tui: load config: %w", err)
	}
	previous := m.config
	m.config = cfg
	filterState, filterValue := m.list.FilterState(), m.list.FilterValue()
	m.list.SetItems(m.machineItems())
	if filterState != list.Unfiltered {
		m.list.SetFilterText(filterValue)
		if filterState == list.Filtering {
			m.list.SetFilterState(list.Filtering)
		}
	}
	if previous != nil {
		for name := range previous.Servers {
			m.connectionGenerations[name]++
			delete(m.connectionStates, name)
		}
	}
	for name := range cfg.Servers {
		if previous != nil {
			if _, existed := previous.Servers[name]; !existed {
				m.connectionGenerations[name]++
			}
		}
		m.connectionStates[name] = connectionState{phase: connectionUntested}
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
		items = append(items, row{key: name, title: terminalText(name), description: terminalText(fmt.Sprintf("%s@%s:%d %s", machine.User, machine.Host, effectivePort(machine.Port), machine.Auth)), value: machine})
	}
	return items
}

func (m *Model) currentRow() (row, bool) {
	entry, ok := m.list.SelectedItem().(row)
	return entry, ok
}

func formatMachineDetails(item row, credential credentialState) string {
	machine := item.value
	return strings.Join([]string{
		"Address       " + terminalText(fmt.Sprintf("%s:%d", machine.Host, effectivePort(machine.Port))),
		"Account       " + valueOrDash(machine.User),
		"Auth          " + valueOrDash(machine.Auth),
		"Credential    " + string(credential),
		"Key file      " + valueOrDash(machine.KeyPath),
		"Policy        " + policyLabel(machine),
		"Default dir   " + valueOrDash(machine.DefaultDir),
		"Jump host     " + valueOrDash(machine.ProxyJump),
		"Tags          " + valueOrDash(strings.Join(machine.Tags, ", ")),
		"Description   " + valueOrDash(machine.Description),
	}, "\n")
}

func policyLabel(machine config.ServerConfig) string {
	return defaultString(machine.Mode, "unrestricted")
}
func (m *Model) connectionPhase(name string) connectionPhase {
	state, ok := m.connectionStates[name]
	if !ok || state.phase == "" {
		return connectionUntested
	}
	return state.phase
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
