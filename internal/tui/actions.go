package tui

import (
	"fmt"
	"strconv"
	"strings"

	"charm.land/bubbles/v2/textinput"
	tea "charm.land/bubbletea/v2"
	gossh "golang.org/x/crypto/ssh"

	"github.com/xjoker/ssh-mcp/internal/audit"
	"github.com/xjoker/ssh-mcp/internal/auth"
	"github.com/xjoker/ssh-mcp/internal/config"
	"github.com/xjoker/ssh-mcp/internal/knownhosts"
)

type formKind int

const (
	serverForm formKind = iota
	trustForm
	credentialForm
)

type formState struct {
	kind     formKind
	editing  bool
	original string
	fields   []textinput.Model
}

type confirmation struct {
	prompt string
	action string
	target []row
	host   string
	key    gossh.PublicKey
}

func (form *formState) view() string {
	var builder strings.Builder
	builder.WriteString("编辑\n\n")
	for _, field := range form.fields {
		builder.WriteString(field.View())
		builder.WriteByte('\n')
	}
	builder.WriteString("\n[tab] 下一项  [enter] 确认  [esc] 取消")
	return overlayStyle.Render(builder.String())
}

func (m *Model) updateForm(message tea.Msg) (tea.Model, tea.Cmd) {
	if keyMessage, ok := message.(tea.KeyPressMsg); ok {
		switch keyMessage.String() {
		case "esc":
			m.form = nil
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
	switch m.tab {
	case serversTab:
		m.form = newServerForm(config.ServerConfig{}, "", false)
	case trustTab:
		m.form = newTrustForm()
	case credentialsTab:
		m.err = "选择一个配置引用后按 e 设置凭据"
	}
}

func (m *Model) openEdit() {
	item, ok := m.currentRow()
	if !ok {
		m.err = "请选择一项"
		return
	}
	m.err, m.message = "", ""
	switch m.tab {
	case serversTab:
		server, ok := item.value.(config.ServerConfig)
		if !ok {
			m.err = "服务器数据无效"
			return
		}
		m.form = newServerForm(server, item.key, true)
	case credentialsTab:
		m.form = newCredentialForm(item.key)
	default:
		m.openDetails()
	}
}

func (m *Model) openDeleteConfirmation() {
	items := m.targetRows()
	if len(items) == 0 {
		m.err = "请选择一项"
		return
	}
	switch m.tab {
	case serversTab:
		m.confirmation = &confirmation{prompt: fmt.Sprintf("删除 %d 个服务器前会先创建配置备份。继续？", len(items)), action: "delete-server", target: items}
	case trustTab:
		m.confirmation = &confirmation{prompt: fmt.Sprintf("删除 %d 个主机密钥条目？", len(items)), action: "delete-trust", target: items}
	case credentialsTab:
		m.confirmation = &confirmation{prompt: fmt.Sprintf("删除 %d 个 keychain 凭据？", len(items)), action: "delete-credential", target: items}
	default:
		m.err = "此页面没有删除操作"
	}
}

func (m *Model) openTrustConfirmation(action string) {
	items := m.targetRows()
	if len(items) == 0 {
		m.err = "请选择一项"
		return
	}
	m.confirmation = &confirmation{prompt: fmt.Sprintf("吊销 %d 个主机密钥条目？", len(items)), action: action + "-trust", target: items}
}

func (m *Model) updateConfirmation(message tea.Msg) (tea.Model, tea.Cmd) {
	keyMessage, ok := message.(tea.KeyPressMsg)
	if !ok {
		return m, nil
	}
	switch keyMessage.String() {
	case "n", "esc":
		m.confirmation = nil
		return m, nil
	case "y":
		confirmation := m.confirmation
		m.confirmation = nil
		m.executeConfirmation(confirmation)
	}
	return m, nil
}

func (m *Model) executeConfirmation(confirmation *confirmation) {
	var err error
	switch confirmation.action {
	case "delete-server":
		_, err = config.Backup(m.options.ConfigPath)
		if err == nil {
			for _, item := range confirmation.target {
				err = config.RemoveServer(m.config, item.key)
				if err != nil {
					break
				}
			}
		}
		if err == nil {
			err = config.Save(m.options.ConfigPath, m.config)
		}
	case "delete-trust":
		for _, item := range confirmation.target {
			entry, ok := item.value.(knownhosts.Entry)
			if !ok {
				err = fmt.Errorf("invalid trust entry")
				break
			}
			err = knownhosts.Remove(m.options.KnownHostsPath, entry)
			if err != nil {
				break
			}
		}
	case "revoke-trust":
		for _, item := range confirmation.target {
			entry, ok := item.value.(knownhosts.Entry)
			if !ok {
				err = fmt.Errorf("invalid trust entry")
				break
			}
			err = knownhosts.Revoke(m.options.KnownHostsPath, entry)
			if err != nil {
				break
			}
		}
	case "delete-credential":
		for _, item := range confirmation.target {
			reference, ok := item.value.(credentialRef)
			if !ok {
				err = fmt.Errorf("invalid credential reference")
				break
			}
			err = auth.DeleteKeychain(reference.Service, reference.Account)
			if err != nil {
				break
			}
		}
	case "append-trust":
		if confirmation.key == nil {
			err = fmt.Errorf("invalid host key")
			break
		}
		err = knownhosts.Append(m.options.KnownHostsPath, confirmation.host, confirmation.key)
	}
	if err != nil {
		m.err = "操作失败：" + err.Error()
		return
	}
	m.selected = make(map[string]bool)
	m.message = "操作已完成"
	m.err = ""
	m.refreshWithMessage()
}

func (m *Model) saveForm() {
	form := m.form
	switch form.kind {
	case serverForm:
		m.saveServerForm(form)
	case trustForm:
		host := strings.TrimSpace(form.fields[0].Value())
		key, err := knownhosts.FetchHostKey(host)
		if err != nil {
			m.err = "获取主机密钥失败：" + err.Error()
			return
		}
		m.form = nil
		m.confirmation = &confirmation{prompt: fmt.Sprintf("确认写入 %s 的主机密钥？\n%s", host, knownhostsFingerprint(key)), action: "append-trust", host: host, key: key}
	case credentialForm:
		m.saveCredentialForm(form)
	}
}

func (m *Model) saveServerForm(form *formState) {
	port, err := strconv.Atoi(strings.TrimSpace(form.fields[3].Value()))
	if err != nil {
		m.err = "端口必须是整数"
		return
	}
	server := config.ServerConfig{
		Host:          strings.TrimSpace(form.fields[1].Value()),
		User:          strings.TrimSpace(form.fields[2].Value()),
		Port:          port,
		Auth:          strings.TrimSpace(form.fields[4].Value()),
		Mode:          strings.TrimSpace(form.fields[5].Value()),
		AllowPatterns: splitPatterns(form.fields[6].Value()),
		DenyPatterns:  splitPatterns(form.fields[7].Value()),
		Description:   strings.TrimSpace(form.fields[8].Value()),
	}
	name := strings.TrimSpace(form.fields[0].Value())
	if form.editing {
		current := m.config.Servers[form.original]
		server.Password = current.Password
		server.KeyPassphrase = current.KeyPassphrase
		server.KeyPath = current.KeyPath
		server.DefaultDir = current.DefaultDir
		server.ProxyJump = current.ProxyJump
		server.ProxyChain = current.ProxyChain
		server.AllowedPaths = current.AllowedPaths
		server.Tags = current.Tags
		if name != form.original {
			m.err = "编辑时不能更改服务器名称"
			return
		}
	}
	if form.editing {
		err = config.UpsertServer(m.config, name, server)
	} else {
		err = config.AddServer(m.config, name, server)
	}
	if err == nil {
		err = config.Save(m.options.ConfigPath, m.config)
	}
	if err != nil {
		m.err = "保存服务器失败：" + err.Error()
		return
	}
	m.form = nil
	m.message = "服务器已保存"
	m.err = ""
	m.refreshWithMessage()
}

func (m *Model) saveCredentialForm(form *formState) {
	item, ok := m.currentRow()
	if !ok {
		m.err = "凭据引用已不在列表中"
		return
	}
	reference, ok := item.value.(credentialRef)
	if !ok {
		m.err = "凭据引用无效"
		return
	}
	secret := []byte(form.fields[0].Value())
	if len(secret) == 0 {
		m.err = "凭据不能为空"
		return
	}
	if err := auth.SetKeychain(reference.Service, reference.Account, secret); err != nil {
		m.err = "保存凭据失败：" + err.Error()
		return
	}
	for index := range secret {
		secret[index] = 0
	}
	m.form = nil
	m.message = "凭据已写入 keychain"
	m.err = ""
}

func (m *Model) toggleSelection() {
	item, ok := m.currentRow()
	if !ok {
		return
	}
	m.selected[item.key] = !m.selected[item.key]
	m.refreshWithMessage()
}

func (m *Model) currentRow() (row, bool) {
	item := m.list.SelectedItem()
	entry, ok := item.(row)
	return entry, ok
}

func (m *Model) targetRows() []row {
	items := make([]row, 0)
	for _, item := range m.list.Items() {
		entry, ok := item.(row)
		if ok && m.selected[entry.key] {
			items = append(items, entry)
		}
	}
	if len(items) > 0 {
		return items
	}
	if item, ok := m.currentRow(); ok {
		return []row{item}
	}
	return nil
}

func (m *Model) openDetails() {
	item, ok := m.currentRow()
	if !ok {
		return
	}
	switch value := item.value.(type) {
	case config.ServerConfig:
		m.detail = fmt.Sprintf("服务器：%s\n主机：%s:%d\n用户：%s\n认证：%s\n策略：%s\n允许：%s\n拒绝：%s", item.key, value.Host, value.Port, value.User, value.Auth, policyMode(value.Mode), strings.Join(value.AllowPatterns, ", "), strings.Join(value.DenyPatterns, ", "))
	case audit.Entry:
		m.detail = fmt.Sprintf("时间：%s\n工具：%s\n服务器：%s\n状态：%s\n错误码：%s\n退出码：%d\n耗时：%dms", value.Timestamp.Local().Format("2006-01-02 15:04:05"), value.Tool, value.Server, value.Status, value.ErrorCode, value.ExitCode, value.DurationMs)
	case knownhosts.Entry:
		m.detail = fmt.Sprintf("主机：%s\n密钥类型：%s\n指纹：%s\n状态：%s", strings.Join(value.Hosts, ","), value.KeyType, value.Fingerprint, trustState(value.Revoked))
	case credentialRef:
		m.detail = fmt.Sprintf("账号：%s\n服务：%s\n凭据内容始终隐藏", value.Account, value.Service)
	default:
		m.detail = item.title + "\n" + item.description
	}
}

func (m *Model) nextAuditStatus() {
	statuses := []string{"", "pending", "completed", "failed"}
	for index, status := range statuses {
		if status == m.auditStatus {
			m.auditStatus = statuses[(index+1)%len(statuses)]
			break
		}
	}
	m.auditBefore = nil
	m.refreshWithMessage()
}

func (m *Model) nextAuditPage() {
	items := m.list.Items()
	if len(items) == 0 {
		return
	}
	item, ok := items[len(items)-1].(row)
	if !ok {
		return
	}
	entry, ok := item.value.(audit.Entry)
	if !ok {
		return
	}
	m.auditBefore = &audit.Cursor{Timestamp: entry.Timestamp, ID: entry.ID}
	m.refreshWithMessage()
}

func newServerForm(server config.ServerConfig, name string, editing bool) *formState {
	fields := []textinput.Model{
		newInput("名称: ", name, false),
		newInput("主机: ", server.Host, false),
		newInput("用户: ", server.User, false),
		newInput("端口: ", strconv.Itoa(server.Port), false),
		newInput("认证(agent/key/password): ", defaultString(server.Auth, "agent"), false),
		newInput("策略(unrestricted/readonly/restricted): ", policyMode(server.Mode), false),
		newInput("允许模式（逗号分隔）: ", strings.Join(server.AllowPatterns, ","), false),
		newInput("拒绝模式（逗号分隔）: ", strings.Join(server.DenyPatterns, ","), false),
		newInput("说明: ", server.Description, false),
	}
	fields[0].Focus()
	return &formState{kind: serverForm, editing: editing, original: name, fields: fields}
}

func newTrustForm() *formState {
	field := newInput("主机地址（如 host:22）: ", "", false)
	field.Focus()
	return &formState{kind: trustForm, fields: []textinput.Model{field}}
}

func newCredentialForm(original string) *formState {
	field := newInput("新凭据: ", "", true)
	field.Focus()
	return &formState{kind: credentialForm, original: original, fields: []textinput.Model{field}}
}

func newInput(prompt, value string, secret bool) textinput.Model {
	field := textinput.New()
	field.Prompt = prompt
	field.SetValue(value)
	field.SetWidth(60)
	if secret {
		field.EchoMode = textinput.EchoPassword
		field.EchoCharacter = '•'
	}
	return field
}

func splitPatterns(value string) []string {
	var patterns []string
	for _, part := range strings.Split(value, ",") {
		if trimmed := strings.TrimSpace(part); trimmed != "" {
			patterns = append(patterns, trimmed)
		}
	}
	return patterns
}

func defaultString(value, fallback string) string {
	if value == "" {
		return fallback
	}
	return value
}

func trustState(revoked bool) string {
	if revoked {
		return "已吊销"
	}
	return "已信任"
}

func knownhostsFingerprint(key gossh.PublicKey) string {
	return gossh.FingerprintSHA256(key)
}
