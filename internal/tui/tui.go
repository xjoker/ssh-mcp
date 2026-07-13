// Package tui provides the local terminal management console.
package tui

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"charm.land/bubbles/v2/help"
	"charm.land/bubbles/v2/key"
	"charm.land/bubbles/v2/list"
	tea "charm.land/bubbletea/v2"
	"charm.land/lipgloss/v2"

	"github.com/xjoker/ssh-mcp/internal/audit"
	"github.com/xjoker/ssh-mcp/internal/config"
	"github.com/xjoker/ssh-mcp/internal/knownhosts"
	"github.com/xjoker/ssh-mcp/internal/store"
)

const liveTTL = 9 * time.Second

type tab int

const (
	serversTab tab = iota
	auditTab
	liveTab
	trustTab
	credentialsTab
)

// Options identifies local state used by the management console.
type Options struct {
	ConfigPath     string
	AuditDir       string
	KnownHostsPath string
}

// Run opens the management console.
func Run(options Options) error {
	model, err := New(options)
	if err != nil {
		return err
	}
	_, err = tea.NewProgram(model).Run()
	return err
}

// Model is the Bubble Tea state for the management console.
type Model struct {
	options      Options
	config       *config.Config
	tab          tab
	list         list.Model
	help         help.Model
	keys         keyMap
	width        int
	height       int
	selected     map[string]bool
	auditStatus  string
	auditBefore  *audit.Cursor
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
	value       any
}

func (item row) FilterValue() string { return item.title + " " + item.description }
func (item row) Title() string       { return item.title }
func (item row) Description() string { return item.description }

type keyMap struct {
	Quit    key.Binding
	NextTab key.Binding
	Refresh key.Binding
	Search  key.Binding
	Add     key.Binding
	Edit    key.Binding
	Delete  key.Binding
	Revoke  key.Binding
	Select  key.Binding
	Details key.Binding
	Help    key.Binding
	Next    key.Binding
	Filter  key.Binding
}

func defaultKeyMap() keyMap {
	return keyMap{
		Quit:    key.NewBinding(key.WithKeys("q", "ctrl+c"), key.WithHelp("q", "退出")),
		NextTab: key.NewBinding(key.WithKeys("tab"), key.WithHelp("tab", "切换页")),
		Refresh: key.NewBinding(key.WithKeys("r"), key.WithHelp("r", "刷新本地数据")),
		Search:  key.NewBinding(key.WithKeys("/"), key.WithHelp("/", "搜索")),
		Add:     key.NewBinding(key.WithKeys("n"), key.WithHelp("n", "新增/写入")),
		Edit:    key.NewBinding(key.WithKeys("e"), key.WithHelp("e", "编辑")),
		Delete:  key.NewBinding(key.WithKeys("d"), key.WithHelp("d", "删除")),
		Revoke:  key.NewBinding(key.WithKeys("x"), key.WithHelp("x", "吊销信任")),
		Select:  key.NewBinding(key.WithKeys("space"), key.WithHelp("space", "多选")),
		Details: key.NewBinding(key.WithKeys("enter"), key.WithHelp("enter", "详情")),
		Help:    key.NewBinding(key.WithKeys("?"), key.WithHelp("?", "帮助")),
		Next:    key.NewBinding(key.WithKeys("n"), key.WithHelp("n", "下一页")),
		Filter:  key.NewBinding(key.WithKeys("f"), key.WithHelp("f", "状态筛选")),
	}
}

func (keys keyMap) ShortHelp() []key.Binding {
	return []key.Binding{keys.NextTab, keys.Search, keys.Refresh, keys.Details, keys.Help, keys.Quit}
}

func (keys keyMap) FullHelp() [][]key.Binding {
	return [][]key.Binding{{keys.Add, keys.Edit, keys.Delete, keys.Revoke, keys.Select}, {keys.Filter, keys.Next, keys.Refresh, keys.Quit}}
}

type tickMsg time.Time

func tick() tea.Cmd {
	return tea.Tick(3*time.Second, func(now time.Time) tea.Msg { return tickMsg(now) })
}

// New creates a management model from local state only.
func New(options Options) (*Model, error) {
	if options.ConfigPath == "" {
		return nil, errors.New("tui: config path is required")
	}
	if options.KnownHostsPath == "" {
		return nil, errors.New("tui: known_hosts path is required")
	}

	delegate := list.NewDefaultDelegate()
	delegate.ShowDescription = true
	items := make([]list.Item, 0)
	m := &Model{
		options:  options,
		list:     list.New(items, delegate, 0, 0),
		help:     help.New(),
		keys:     defaultKeyMap(),
		selected: make(map[string]bool),
	}
	m.list.SetShowHelp(false)
	if err := m.refresh(); err != nil {
		return nil, err
	}
	return m, nil
}

func (m *Model) Init() tea.Cmd { return tick() }

// Update handles local state navigation and core-backed mutations.
func (m *Model) Update(message tea.Msg) (tea.Model, tea.Cmd) {
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
	case tea.WindowSizeMsg:
		m.width, m.height = message.Width, message.Height
		m.list.SetSize(message.Width, max(4, message.Height-5))
		m.help.SetWidth(message.Width)
		return m, nil
	case tickMsg:
		if m.tab == liveTab {
			m.refreshWithMessage()
		}
		return m, tick()
	case tea.KeyPressMsg:
		switch {
		case key.Matches(message, m.keys.Quit):
			return m, tea.Quit
		case key.Matches(message, m.keys.Help):
			m.help.ShowAll = true
			return m, nil
		case key.Matches(message, m.keys.NextTab):
			m.tab = (m.tab + 1) % 5
			m.auditBefore = nil
			m.selected = make(map[string]bool)
			m.refreshWithMessage()
			return m, nil
		case message.String() >= "1" && message.String() <= "5":
			m.tab = tab(message.String()[0] - '1')
			m.auditBefore = nil
			m.selected = make(map[string]bool)
			m.refreshWithMessage()
			return m, nil
		case key.Matches(message, m.keys.Refresh):
			m.refreshWithMessage()
			return m, nil
		case key.Matches(message, m.keys.Select):
			m.toggleSelection()
			return m, nil
		case key.Matches(message, m.keys.Details):
			m.openDetails()
			return m, nil
		case key.Matches(message, m.keys.Next) && m.tab == auditTab:
			m.nextAuditPage()
			return m, nil
		case key.Matches(message, m.keys.Add) && m.tab != auditTab:
			m.openAdd()
			return m, nil
		case key.Matches(message, m.keys.Edit):
			m.openEdit()
			return m, nil
		case key.Matches(message, m.keys.Delete):
			m.openDeleteConfirmation()
			return m, nil
		case key.Matches(message, m.keys.Revoke) && m.tab == trustTab:
			m.openTrustConfirmation("revoke")
			return m, nil
		case key.Matches(message, m.keys.Filter) && m.tab == auditTab:
			m.nextAuditStatus()
			return m, nil
		}
	}

	updated, command := m.list.Update(message)
	m.list = updated
	return m, command
}

func (m *Model) View() tea.View {
	content := m.renderHeader()
	if m.width > 0 && m.width < 60 {
		content += "\n终端过窄：请至少使用 60 列宽度。\n"
	} else {
		content += "\n" + m.list.View()
	}
	if m.err != "" {
		content += "\n" + errorStyle.Render(m.err)
	} else if m.message != "" {
		content += "\n" + messageStyle.Render(m.message)
	}
	content += "\n" + m.help.View(m.keys)
	if m.confirmation != nil {
		content = overlayStyle.Render(m.confirmation.prompt + "\n\n[y] 确认  [n/esc] 取消")
	}
	if m.detail != "" {
		content = overlayStyle.Render(m.detail + "\n\n[enter/esc] 关闭")
	}
	if m.help.ShowAll {
		content = overlayStyle.Render("帮助\n\n" + m.help.View(m.keys) + "\n\n[?/esc] 关闭")
	}
	if m.form != nil {
		content = m.form.view()
	}
	view := tea.NewView(content)
	view.AltScreen = true
	view.WindowTitle = "ssh-mcp 管理台"
	return view
}

var (
	headerStyle  = lipgloss.NewStyle().Bold(true).Foreground(lipgloss.Color("63"))
	errorStyle   = lipgloss.NewStyle().Foreground(lipgloss.Color("9"))
	messageStyle = lipgloss.NewStyle().Foreground(lipgloss.Color("10"))
	overlayStyle = lipgloss.NewStyle().Border(lipgloss.RoundedBorder()).Padding(1, 2).Margin(1)
)

func (m *Model) renderHeader() string {
	tabs := []string{"1 服务器", "2 审计", "3 实时", "4 Trust", "5 凭据"}
	for index := range tabs {
		if tab(index) == m.tab {
			tabs[index] = "[" + tabs[index] + "]"
		}
	}
	return headerStyle.Render("ssh-mcp 管理台") + "\n" + strings.Join(tabs, "  ")
}

func (m *Model) refreshWithMessage() {
	if err := m.refresh(); err != nil {
		m.err = err.Error()
		return
	}
	m.err = ""
	m.message = "已刷新本地数据"
}

func (m *Model) refresh() error {
	cfg, err := config.Load(m.options.ConfigPath)
	if err != nil {
		return fmt.Errorf("tui: load config: %w", err)
	}
	m.config = cfg
	items, title, err := m.itemsForTab()
	if err != nil {
		return err
	}
	m.list.Title = title
	_ = m.list.SetItems(items)
	return nil
}

func (m *Model) itemsForTab() ([]list.Item, string, error) {
	switch m.tab {
	case serversTab:
		return m.serverItems(), "服务器", nil
	case auditTab:
		return m.auditItems()
	case liveTab:
		return m.liveItems()
	case trustTab:
		return m.trustItems()
	case credentialsTab:
		return m.credentialItems(), "凭据引用（不会显示凭据内容）", nil
	default:
		return nil, "", errors.New("tui: unknown tab")
	}
}

func (m *Model) serverItems() []list.Item {
	names := make([]string, 0, len(m.config.Servers))
	for name := range m.config.Servers {
		names = append(names, name)
	}
	sort.Strings(names)
	items := make([]list.Item, 0, len(names))
	for _, name := range names {
		server := m.config.Servers[name]
		prefix := selectionPrefix(m.selected[name])
		items = append(items, row{key: name, title: prefix + name, description: fmt.Sprintf("%s@%s:%d · %s · %s", server.User, server.Host, server.Port, server.Auth, policyMode(server.Mode)), value: server})
	}
	return items
}

func (m *Model) auditItems() ([]list.Item, string, error) {
	if _, err := os.Stat(m.options.AuditDir); errors.Is(err, os.ErrNotExist) {
		return nil, "审计（无本地记录）", nil
	} else if err != nil {
		return nil, "", fmt.Errorf("tui: stat audit directory: %w", err)
	}
	reader, err := audit.NewReader(m.options.AuditDir)
	if err != nil {
		return nil, "", fmt.Errorf("tui: open audit: %w", err)
	}
	defer reader.Close()
	entries, err := reader.Query(audit.Filter{Status: m.auditStatus, Before: m.auditBefore, Limit: 100})
	if err != nil {
		return nil, "", fmt.Errorf("tui: query audit: %w", err)
	}
	items := make([]list.Item, 0, len(entries))
	for _, entry := range entries {
		key := fmt.Sprintf("audit-%d", entry.ID)
		items = append(items, row{key: key, title: fmt.Sprintf("%s · %s", entry.Timestamp.Local().Format("2006-01-02 15:04:05"), entry.Tool), description: fmt.Sprintf("%s · %s · %s", entry.Server, entry.Status, entry.ErrorCode), value: entry})
	}
	status := m.auditStatus
	if status == "" {
		status = "全部"
	}
	return items, "审计（状态：" + status + "）", nil
}

func (m *Model) liveItems() ([]list.Item, string, error) {
	dbPath := filepath.Join(m.options.AuditDir, "ssh-mcp.db")
	if _, err := os.Stat(dbPath); errors.Is(err, os.ErrNotExist) {
		return nil, "实时状态（无本地记录）", nil
	} else if err != nil {
		return nil, "", fmt.Errorf("tui: stat live database: %w", err)
	}
	data, err := store.OpenReadOnly(dbPath)
	if err != nil {
		return nil, "", fmt.Errorf("tui: open live database: %w", err)
	}
	defer data.Close()
	entries, err := data.ListLive(time.Now().UTC().Add(-liveTTL))
	if err != nil {
		return nil, "", fmt.Errorf("tui: list live state: %w", err)
	}
	items := make([]list.Item, 0, len(entries))
	for _, entry := range entries {
		items = append(items, row{key: string(entry.ResourceType) + ":" + entry.ResourceID, title: fmt.Sprintf("%s · %s", entry.ResourceType, entry.Server), description: fmt.Sprintf("%s · PID %d · 心跳 %s", entry.Kind, entry.PID, entry.LastHeartbeat.Local().Format("15:04:05")), value: entry})
	}
	return items, "实时状态（仅 SQLite 心跳，不探测远端）", nil
}

func (m *Model) trustItems() ([]list.Item, string, error) {
	entries, err := knownhosts.List(m.options.KnownHostsPath)
	if err != nil {
		return nil, "", fmt.Errorf("tui: list known_hosts: %w", err)
	}
	items := make([]list.Item, 0, len(entries))
	for index, entry := range entries {
		key := fmt.Sprintf("trust-%d", index)
		state := "已信任"
		if entry.Revoked {
			state = "已吊销"
		}
		items = append(items, row{key: key, title: selectionPrefix(m.selected[key]) + strings.Join(entry.Hosts, ","), description: fmt.Sprintf("%s · %s · %s", entry.KeyType, entry.Fingerprint, state), value: entry})
	}
	return items, "Trust（先预览指纹，再确认写入）", nil
}

type credentialRef struct {
	Service string
	Account string
}

func (m *Model) credentialItems() []list.Item {
	references := make(map[string]credentialRef)
	add := func(reference config.CredRef) {
		if reference.Kind != config.CredRefKeychain {
			return
		}
		key := reference.Service + "\x00" + reference.Account
		references[key] = credentialRef{Service: reference.Service, Account: reference.Account}
	}
	for _, server := range m.config.Servers {
		add(server.Password)
		add(server.KeyPassphrase)
	}
	for _, proxy := range m.config.Proxies {
		add(proxy.Password)
	}
	keys := make([]string, 0, len(references))
	for entryKey := range references {
		keys = append(keys, entryKey)
	}
	sort.Strings(keys)
	items := make([]list.Item, 0, len(keys))
	for _, entryKey := range keys {
		reference := references[entryKey]
		items = append(items, row{key: entryKey, title: reference.Account, description: "keychain 服务：" + reference.Service + "（内容隐藏）", value: reference})
	}
	return items
}

func selectionPrefix(selected bool) string {
	if selected {
		return "[x] "
	}
	return "[ ] "
}

func policyMode(mode string) string {
	if mode == "" {
		return "unrestricted"
	}
	return mode
}
