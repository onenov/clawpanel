/**
 * 聊天页面 - 完整版，对接 OpenClaw Gateway
 * 支持：流式响应、Markdown 渲染、会话管理、Agent 选择、快捷指令
 */
import { api } from '../lib/tauri-api.js'
import { navigate } from '../router.js'
import { wsClient, uuid } from '../lib/ws-client.js'
import { renderMarkdown } from '../lib/markdown.js'
import { saveMessage, saveMessages, getLocalMessages, isStorageAvailable } from '../lib/message-db.js'
import { toast } from '../components/toast.js'
import { showModal, showConfirm } from '../components/modal.js'

const RENDER_THROTTLE = 30
const STORAGE_SESSION_KEY = 'clawpanel-last-session'

const COMMANDS = [
  { title: '会话', commands: [
    { cmd: '/new', desc: '新建会话', action: 'exec' },
    { cmd: '/reset', desc: '重置当前会话', action: 'exec' },
    { cmd: '/stop', desc: '停止生成', action: 'exec' },
  ]},
  { title: '模型', commands: [
    { cmd: '/model ', desc: '切换模型（输入模型名）', action: 'fill' },
    { cmd: '/model list', desc: '查看可用模型', action: 'exec' },
    { cmd: '/model status', desc: '当前模型状态', action: 'exec' },
  ]},
  { title: '思考模式', commands: [
    { cmd: '/think off', desc: '关闭深度思考', action: 'exec' },
    { cmd: '/think low', desc: '轻度思考', action: 'exec' },
    { cmd: '/think medium', desc: '中度思考', action: 'exec' },
    { cmd: '/think high', desc: '深度思考', action: 'exec' },
  ]},
  { title: '信息', commands: [
    { cmd: '/help', desc: '帮助信息', action: 'exec' },
    { cmd: '/status', desc: '系统状态', action: 'exec' },
    { cmd: '/context', desc: '上下文信息', action: 'exec' },
  ]},
]

let _sessionKey = null, _page = null, _messagesEl = null, _textarea = null
let _sendBtn = null, _statusDot = null, _typingEl = null, _scrollBtn = null
let _sessionListEl = null, _cmdPanelEl = null, _attachPreviewEl = null, _fileInputEl = null
let _currentAiBubble = null, _currentAiText = '', _currentRunId = null
let _isStreaming = false, _isSending = false, _messageQueue = []
let _lastRenderTime = 0, _renderPending = false, _lastHistoryHash = ''
let _streamSafetyTimer = null, _unsubEvent = null, _unsubReady = null, _unsubStatus = null
let _pageActive = false
let _errorTimer = null, _lastErrorMsg = null
let _attachments = []

export async function render() {
  const page = document.createElement('div')
  page.className = 'page chat-page'
  _pageActive = true
  _page = page

  page.innerHTML = `
    <div class="chat-sidebar" id="chat-sidebar">
      <div class="chat-sidebar-header">
        <span>会话列表</span>
        <button class="chat-sidebar-btn" id="btn-new-session" title="新建会话">
          <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" width="16" height="16"><line x1="12" y1="5" x2="12" y2="19"/><line x1="5" y1="12" x2="19" y2="12"/></svg>
        </button>
      </div>
      <div class="chat-session-list" id="chat-session-list"></div>
    </div>
    <div class="chat-main">
      <div class="chat-header">
        <div class="chat-status">
          <button class="chat-toggle-sidebar" id="btn-toggle-sidebar" title="会话列表">
            <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" width="18" height="18"><line x1="3" y1="6" x2="21" y2="6"/><line x1="3" y1="12" x2="21" y2="12"/><line x1="3" y1="18" x2="21" y2="18"/></svg>
          </button>
          <span class="status-dot" id="chat-status-dot"></span>
          <span class="chat-title" id="chat-title">聊天</span>
        </div>
        <div class="chat-header-actions">
          <button class="btn btn-sm btn-ghost" id="btn-cmd" title="快捷指令">
            <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" width="16" height="16"><path d="M18 3a3 3 0 00-3 3v12a3 3 0 003 3 3 3 0 003-3 3 3 0 00-3-3H6a3 3 0 00-3 3 3 3 0 003 3 3 3 0 003-3V6a3 3 0 00-3-3 3 3 0 00-3 3 3 3 0 003 3h12a3 3 0 003-3 3 3 0 00-3-3z"/></svg>
          </button>
          <button class="btn btn-sm btn-ghost" id="btn-reset-session" title="重置会话">
            <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" width="16" height="16"><polyline points="1 4 1 10 7 10"/><path d="M3.51 15a9 9 0 102.13-9.36L1 10"/></svg>
          </button>
        </div>
      </div>
      <div class="chat-messages" id="chat-messages">
        <div class="typing-indicator" id="typing-indicator" style="display:none">
          <span></span><span></span><span></span>
        </div>
      </div>
      <button class="chat-scroll-btn" id="chat-scroll-btn" style="display:none">↓</button>
      <div class="chat-cmd-panel" id="chat-cmd-panel" style="display:none"></div>
      <div class="chat-attachments-preview" id="chat-attachments-preview" style="display:none"></div>
      <div class="chat-input-area">
        <input type="file" id="chat-file-input" accept="image/*" multiple style="display:none">
        <button class="chat-attach-btn" id="chat-attach-btn" title="上传图片">
          <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" width="18" height="18"><path d="M21.44 11.05l-9.19 9.19a6 6 0 01-8.49-8.49l9.19-9.19a4 4 0 015.66 5.66l-9.2 9.19a2 2 0 01-2.83-2.83l8.49-8.48"/></svg>
        </button>
        <div class="chat-input-wrapper">
          <textarea id="chat-input" rows="1" placeholder="输入消息，Enter 发送，/ 打开指令"></textarea>
        </div>
        <button class="chat-send-btn" id="chat-send-btn" disabled>
          <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" width="20" height="20"><line x1="22" y1="2" x2="11" y2="13"/><polygon points="22 2 15 22 11 13 2 9 22 2"/></svg>
        </button>
      </div>
      <div class="chat-disconnect-bar" id="chat-disconnect-bar" style="display:none">连接已断开，正在重连...</div>
    </div>
  `

  _messagesEl = page.querySelector('#chat-messages')
  _textarea = page.querySelector('#chat-input')
  _sendBtn = page.querySelector('#chat-send-btn')
  _statusDot = page.querySelector('#chat-status-dot')
  _typingEl = page.querySelector('#typing-indicator')
  _scrollBtn = page.querySelector('#chat-scroll-btn')
  _sessionListEl = page.querySelector('#chat-session-list')
  _cmdPanelEl = page.querySelector('#chat-cmd-panel')
  _attachPreviewEl = page.querySelector('#chat-attachments-preview')
  _fileInputEl = page.querySelector('#chat-file-input')

  bindEvents(page)
  // 非阻塞：先返回 DOM，后台连接 Gateway
  connectGateway()
  return page
}

// ── 事件绑定 ──

function bindEvents(page) {
  _textarea.addEventListener('input', () => {
    _textarea.style.height = 'auto'
    _textarea.style.height = Math.min(_textarea.scrollHeight, 150) + 'px'
    updateSendState()
    // 输入 / 时显示指令面板
    if (_textarea.value === '/') showCmdPanel()
    else if (!_textarea.value.startsWith('/')) hideCmdPanel()
  })

  _textarea.addEventListener('keydown', (e) => {
    if (e.key === 'Enter' && !e.shiftKey) { e.preventDefault(); sendMessage() }
    if (e.key === 'Escape') hideCmdPanel()
  })

  _sendBtn.addEventListener('click', () => {
    if (_isStreaming) stopGeneration()
    else sendMessage()
  })

  page.querySelector('#btn-toggle-sidebar').addEventListener('click', () => {
    page.querySelector('#chat-sidebar').classList.toggle('open')
  })
  page.querySelector('#btn-new-session').addEventListener('click', () => showNewSessionDialog())
  page.querySelector('#btn-cmd').addEventListener('click', () => toggleCmdPanel())
  page.querySelector('#btn-reset-session').addEventListener('click', () => resetCurrentSession())

  // 文件上传
  page.querySelector('#chat-attach-btn').addEventListener('click', () => _fileInputEl.click())
  _fileInputEl.addEventListener('change', handleFileSelect)
  // 粘贴图片（Ctrl+V）
  _textarea.addEventListener('paste', handlePaste)

  _messagesEl.addEventListener('scroll', () => {
    const { scrollTop, scrollHeight, clientHeight } = _messagesEl
    _scrollBtn.style.display = (scrollHeight - scrollTop - clientHeight < 80) ? 'none' : 'flex'
  })
  _scrollBtn.addEventListener('click', () => scrollToBottom())
  _messagesEl.addEventListener('click', () => hideCmdPanel())
}

// ── 文件上传 ──

async function handleFileSelect(e) {
  const files = Array.from(e.target.files || [])
  if (!files.length) return

  for (const file of files) {
    if (!file.type.startsWith('image/')) {
      toast('仅支持图片文件', 'warning')
      continue
    }
    if (file.size > 5 * 1024 * 1024) {
      toast(`${file.name} 超过 5MB 限制`, 'warning')
      continue
    }

    try {
      const base64 = await fileToBase64(file)
      _attachments.push({
        type: 'image',
        mimeType: file.type,
        fileName: file.name,
        content: base64,
      })
      renderAttachments()
    } catch (e) {
      toast(`读取 ${file.name} 失败`, 'error')
    }
  }
  _fileInputEl.value = ''
}

async function handlePaste(e) {
  const items = Array.from(e.clipboardData?.items || [])
  const imageItems = items.filter(item => item.type.startsWith('image/'))
  if (!imageItems.length) return
  e.preventDefault()
  for (const item of imageItems) {
    const file = item.getAsFile()
    if (!file) continue
    if (file.size > 5 * 1024 * 1024) { toast('粘贴的图片超过 5MB 限制', 'warning'); continue }
    try {
      const base64 = await fileToBase64(file)
      _attachments.push({ type: 'image', mimeType: file.type || 'image/png', fileName: `paste-${Date.now()}.png`, content: base64 })
      renderAttachments()
    } catch (_) { toast('读取粘贴图片失败', 'error') }
  }
}

function fileToBase64(file) {
  return new Promise((resolve, reject) => {
    const reader = new FileReader()
    reader.onload = () => {
      const dataUrl = reader.result
      const match = /^data:[^;]+;base64,(.+)$/.exec(dataUrl)
      if (!match) { reject(new Error('无效的数据 URL')); return }
      resolve(match[1])
    }
    reader.onerror = reject
    reader.readAsDataURL(file)
  })
}

function renderAttachments() {
  if (!_attachments.length) {
    _attachPreviewEl.style.display = 'none'
    return
  }
  _attachPreviewEl.style.display = 'flex'
  _attachPreviewEl.innerHTML = _attachments.map((att, idx) => `
    <div class="chat-attachment-item">
      <img src="data:${att.mimeType};base64,${att.content}" alt="${att.fileName}">
      <button class="chat-attachment-del" data-idx="${idx}">×</button>
    </div>
  `).join('')

  _attachPreviewEl.querySelectorAll('.chat-attachment-del').forEach(btn => {
    btn.addEventListener('click', () => {
      const idx = parseInt(btn.dataset.idx)
      _attachments.splice(idx, 1)
      renderAttachments()
    })
  })
  updateSendState()
}

// ── Gateway 连接 ──

async function connectGateway() {
  try {
    // 订阅状态变化（订阅式，返回 unsub）
    _unsubStatus = wsClient.onStatusChange((status, errorMsg) => {
      if (!_pageActive) return
      updateStatusDot(status)
      const bar = document.getElementById('chat-disconnect-bar')
      if (!bar) return
      if (status === 'reconnecting' || status === 'disconnected') {
        bar.textContent = '连接已断开，正在重连...'
        bar.style.display = 'flex'
      } else if (status === 'error') {
        bar.textContent = errorMsg || '连接错误'
        bar.style.display = 'flex'
      } else {
        bar.style.display = 'none'
      }
    })

    _unsubReady = wsClient.onReady((hello, sessionKey, err) => {
      if (!_pageActive) return
      if (err?.error) { toast(err.message || '连接失败', 'error'); return }
      showTyping(false)  // Gateway 就绪后关闭加载动画
      // 重连后恢复：保留当前 sessionKey，不重复加载历史
      if (!_sessionKey) {
        const saved = localStorage.getItem(STORAGE_SESSION_KEY)
        _sessionKey = saved || sessionKey
        updateSessionTitle()
        loadHistory()
      }
      // 始终刷新会话列表（无论是否有 sessionKey）
      refreshSessionList()
    })

    _unsubEvent = wsClient.onEvent((msg) => {
      if (!_pageActive) return
      handleEvent(msg)
    })

    // 如果已连接且 Gateway 就绪，直接复用
    if (wsClient.connected && wsClient.gatewayReady) {
      const saved = localStorage.getItem(STORAGE_SESSION_KEY)
      _sessionKey = saved || wsClient.sessionKey
      updateStatusDot('ready')
      showTyping(false)  // 确保关闭加载动画
      updateSessionTitle()
      loadHistory()
      refreshSessionList()
      return
    }

    // 如果正在连接中（重连等），等待 onReady 回调即可
    if (wsClient.connected) return

    // 未连接，发起新连接
    const config = await api.readOpenclawConfig()
    const gw = config?.gateway || {}
    const host = `127.0.0.1:${gw.port || 18789}`
    const token = gw.auth?.token || gw.authToken || ''
    wsClient.connect(host, token)
  } catch (e) {
    toast('读取配置失败: ' + e.message, 'error')
  }
}

// ── 会话管理 ──

async function refreshSessionList() {
  if (!_sessionListEl || !wsClient.gatewayReady) return
  try {
    const result = await wsClient.sessionsList(50)
    const sessions = result?.sessions || result || []
    renderSessionList(sessions)
  } catch (e) {
    console.error('[chat] refreshSessionList error:', e)
  }
}

function renderSessionList(sessions) {
  if (!_sessionListEl) return
  if (!sessions.length) {
    _sessionListEl.innerHTML = '<div class="chat-session-empty">暂无会话</div>'
    return
  }
  sessions.sort((a, b) => (b.updatedAt || b.lastActivity || 0) - (a.updatedAt || a.lastActivity || 0))
  _sessionListEl.innerHTML = sessions.map(s => {
    const key = s.sessionKey || s.key || ''
    const active = key === _sessionKey ? ' active' : ''
    const label = parseSessionLabel(key)
    return `<div class="chat-session-item${active}" data-key="${key}">
      <span class="chat-session-label">${label}</span>
      <button class="chat-session-del" data-del="${key}" title="删除">×</button>
    </div>`
  }).join('')

  _sessionListEl.onclick = (e) => {
    const delBtn = e.target.closest('[data-del]')
    if (delBtn) { e.stopPropagation(); deleteSession(delBtn.dataset.del); return }
    const item = e.target.closest('[data-key]')
    if (item) switchSession(item.dataset.key)
  }
}

function parseSessionLabel(key) {
  const parts = (key || '').split(':')
  if (parts.length < 3) return key || '未知'
  const agent = parts[1] || 'main'
  const channel = parts.slice(2).join(':')
  if (agent === 'main' && channel === 'main') return '主会话'
  if (agent === 'main') return channel
  return `${agent} / ${channel}`
}

function switchSession(newKey) {
  if (newKey === _sessionKey) return
  _sessionKey = newKey
  localStorage.setItem(STORAGE_SESSION_KEY, newKey)
  _lastHistoryHash = ''
  resetStreamState()
  updateSessionTitle()
  clearMessages()
  loadHistory()
  refreshSessionList()
  _page?.querySelector('#chat-sidebar')?.classList.remove('open')
}

async function showNewSessionDialog() {
  const defaultAgent = wsClient.snapshot?.sessionDefaults?.defaultAgentId || 'main'

  // 先用默认选项立即显示弹窗
  const initialOptions = [
    { value: 'main', label: 'main (默认)' },
    { value: '__new__', label: '+ 新建 Agent' }
  ]

  showModal({
    title: '新建会话',
    fields: [
      { name: 'name', label: '会话名称', value: '', placeholder: '例如：翻译助手' },
      { name: 'agent', label: '智能体', type: 'select', value: defaultAgent, options: initialOptions },
    ],
    onConfirm: (result) => {
      const name = (result.name || '').trim()
      if (!name) { toast('请输入会话名称', 'warning'); return }
      const agent = result.agent || defaultAgent
      if (agent === '__new__') {
        navigate('/agents')
        toast('请在 Agent 管理页面创建新 Agent', 'info')
        return
      }
      switchSession(`agent:${agent}:${name}`)
      toast('会话已创建', 'success')
    }
  })

  // 异步加载完整 Agent 列表并更新下拉框
  try {
    const agents = await api.listAgents()
    const agentOptions = agents.map(a => ({
      value: a.id,
      label: `${a.id}${a.isDefault ? ' (默认)' : ''}${a.identityName ? ' — ' + a.identityName.split(',')[0] : ''}`
    }))
    agentOptions.push({ value: '__new__', label: '+ 新建 Agent' })

    // 更新弹窗中的下拉框选项
    const selectEl = document.querySelector('.modal-overlay [data-name="agent"]')
    if (selectEl) {
      const currentValue = selectEl.value
      selectEl.innerHTML = agentOptions.map(o =>
        `<option value="${o.value}" ${o.value === currentValue ? 'selected' : ''}>${o.label}</option>`
      ).join('')
    }
  } catch (e) {
    console.warn('[chat] 加载 Agent 列表失败:', e)
  }
}

async function deleteSession(key) {
  const mainKey = wsClient.snapshot?.sessionDefaults?.mainSessionKey || 'agent:main:main'
  if (key === mainKey) { toast('主会话不能删除', 'warning'); return }
  const label = parseSessionLabel(key)
  const yes = await showConfirm(`确定删除会话「${label}」？`)
  if (!yes) return
  try {
    await wsClient.sessionsDelete(key)
    toast('会话已删除', 'success')
    if (key === _sessionKey) switchSession(mainKey)
    else refreshSessionList()
  } catch (e) {
    toast('删除失败: ' + e.message, 'error')
  }
}

async function resetCurrentSession() {
  if (!_sessionKey) return
  try {
    await wsClient.sessionsReset(_sessionKey)
    clearMessages()
    _lastHistoryHash = ''
    appendSystemMessage('会话已重置')
    toast('会话已重置', 'success')
  } catch (e) {
    toast('重置失败: ' + e.message, 'error')
  }
}

function updateSessionTitle() {
  const el = _page?.querySelector('#chat-title')
  if (el) el.textContent = parseSessionLabel(_sessionKey)
}

// ── 快捷指令面板 ──

function showCmdPanel() {
  if (!_cmdPanelEl) return
  let html = ''
  for (const group of COMMANDS) {
    html += `<div class="cmd-group-title">${group.title}</div>`
    for (const c of group.commands) {
      html += `<div class="cmd-item" data-cmd="${c.cmd}" data-action="${c.action}">
        <span class="cmd-name">${c.cmd}</span>
        <span class="cmd-desc">${c.desc}</span>
      </div>`
    }
  }
  _cmdPanelEl.innerHTML = html
  _cmdPanelEl.style.display = 'block'
  _cmdPanelEl.onclick = (e) => {
    const item = e.target.closest('.cmd-item')
    if (!item) return
    hideCmdPanel()
    if (item.dataset.action === 'fill') {
      _textarea.value = item.dataset.cmd
      _textarea.focus()
      updateSendState()
    } else {
      _textarea.value = item.dataset.cmd
      sendMessage()
    }
  }
}

function hideCmdPanel() {
  if (_cmdPanelEl) _cmdPanelEl.style.display = 'none'
}

function toggleCmdPanel() {
  if (_cmdPanelEl?.style.display === 'block') hideCmdPanel()
  else { _textarea.value = '/'; showCmdPanel(); _textarea.focus() }
}

// ── 消息发送 ──

function sendMessage() {
  const text = _textarea.value.trim()
  if (!text && !_attachments.length) return
  hideCmdPanel()
  _textarea.value = ''
  _textarea.style.height = 'auto'
  updateSendState()
  const attachments = [..._attachments]
  _attachments = []
  renderAttachments()
  if (_isSending || _isStreaming) { _messageQueue.push({ text, attachments }); return }
  doSend(text, attachments)
}

async function doSend(text, attachments = []) {
  appendUserMessage(text, attachments)
  saveMessage({ id: uuid(), sessionKey: _sessionKey, role: 'user', content: text, timestamp: Date.now() })
  showTyping(true)
  _isSending = true
  try {
    await wsClient.chatSend(_sessionKey, text, attachments.length ? attachments : undefined)
  } catch (err) {
    showTyping(false)
    appendSystemMessage('发送失败: ' + err.message)
  } finally {
    _isSending = false
    updateSendState()
  }
}

function processMessageQueue() {
  if (_messageQueue.length === 0 || _isSending || _isStreaming) return
  const msg = _messageQueue.shift()
  if (typeof msg === 'string') doSend(msg, [])
  else doSend(msg.text, msg.attachments || [])
}

function stopGeneration() {
  if (_currentRunId) wsClient.chatAbort(_sessionKey, _currentRunId).catch(() => {})
}

// ── 事件处理（参照 clawapp 实现） ──

function handleEvent(msg) {
  const { event, payload } = msg
  if (!payload) return

  if (event === 'chat') handleChatEvent(payload)
}

function handleChatEvent(payload) {
  // sessionKey 过滤
  if (payload.sessionKey && payload.sessionKey !== _sessionKey && _sessionKey) return

  const { state } = payload

  if (state === 'delta') {
    const c = extractChatContent(payload.message)
    if (c?.text && c.text.length > _currentAiText.length) {
      showTyping(false)
      if (!_currentAiBubble) {
        _currentAiBubble = createStreamBubble()
        _currentRunId = payload.runId
        _isStreaming = true
        updateSendState()
      }
      _currentAiText = c.text
      throttledRender()
    }
    return
  }

  if (state === 'final') {
    const c = extractChatContent(payload.message)
    const finalText = c?.text || ''
    // 忽略空 final（Gateway 会为一条消息触发多个 run，部分是空 final）
    if (!_currentAiBubble && !finalText) return
    showTyping(false)
    // 如果流式阶段没有创建 bubble，从 final message 中提取
    if (!_currentAiBubble && finalText) {
      _currentAiBubble = createStreamBubble()
      _currentAiText = finalText
    }
    if (_currentAiBubble && _currentAiText) {
      _currentAiBubble.innerHTML = renderMarkdown(_currentAiText)
    }
    if (_currentAiText) {
      saveMessage({ id: payload.runId || uuid(), sessionKey: _sessionKey, role: 'assistant', content: _currentAiText, timestamp: Date.now() })
    }
    resetStreamState()
    processMessageQueue()
    return
  }

  if (state === 'aborted') {
    showTyping(false)
    if (_currentAiBubble && _currentAiText) {
      _currentAiBubble.innerHTML = renderMarkdown(_currentAiText)
    }
    appendSystemMessage('生成已停止')
    resetStreamState()
    processMessageQueue()
    return
  }

  if (state === 'error') {
    const errMsg = payload.errorMessage || payload.error?.message || '未知错误'

    // 防抖：如果是相同错误且在 2 秒内，忽略（避免重复显示）
    const now = Date.now()
    if (_lastErrorMsg === errMsg && _errorTimer && (now - _errorTimer < 2000)) {
      console.warn('[chat] 忽略重复错误:', errMsg)
      return
    }
    _lastErrorMsg = errMsg
    _errorTimer = now

    // 如果正在流式输出，说明消息已经部分成功，不显示错误
    if (_isStreaming || _currentAiBubble) {
      console.warn('[chat] 流式中收到错误，但消息已部分成功，忽略错误提示:', errMsg)
      return
    }

    showTyping(false)
    appendSystemMessage('错误: ' + errMsg)
    resetStreamState()
    processMessageQueue()
    return
  }
}

/** 从 Gateway message 对象提取文本（参照 clawapp extractContent） */
function extractChatContent(message) {
  if (!message || typeof message !== 'object') return null
  const content = message.content
  if (typeof content === 'string') return { text: content }
  if (Array.isArray(content)) {
    const texts = []
    for (const block of content) {
      if (block.type === 'text' && typeof block.text === 'string') texts.push(block.text)
    }
    const text = texts.length ? texts.join('\n') : ''
    if (text) return { text }
  }
  if (typeof message.text === 'string') return { text: message.text }
  return null
}

/** 创建流式 AI 气泡 */
function createStreamBubble() {
  showTyping(false)
  const wrap = document.createElement('div')
  wrap.className = 'msg msg-ai'
  const bubble = document.createElement('div')
  bubble.className = 'msg-bubble'
  bubble.innerHTML = '<span class="stream-cursor"></span>'
  wrap.appendChild(bubble)
  _messagesEl.insertBefore(wrap, _typingEl)
  scrollToBottom()
  return bubble
}

// ── 流式渲染（节流） ──

function throttledRender() {
  if (_renderPending) return
  const now = performance.now()
  if (now - _lastRenderTime >= RENDER_THROTTLE) {
    doRender()
  } else {
    _renderPending = true
    requestAnimationFrame(() => { _renderPending = false; doRender() })
  }
}

function doRender() {
  _lastRenderTime = performance.now()
  if (_currentAiBubble && _currentAiText) {
    _currentAiBubble.innerHTML = renderMarkdown(_currentAiText)
    scrollToBottom()
  }
}

// ensureAiBubble 已被 createStreamBubble 替代

function resetStreamState() {
  clearTimeout(_streamSafetyTimer)
  if (_currentAiBubble && _currentAiText) {
    _currentAiBubble.innerHTML = renderMarkdown(_currentAiText)
  }
  _renderPending = false
  _lastRenderTime = 0
  _currentAiBubble = null
  _currentAiText = ''
  _currentRunId = null
  _isStreaming = false
  _lastErrorMsg = null
  _errorTimer = null
  showTyping(false)
  updateSendState()
}

// ── 历史消息加载 ──

async function loadHistory() {
  if (!_sessionKey) return
  if (isStorageAvailable()) {
    const local = await getLocalMessages(_sessionKey, 200)
    if (local.length) {
      clearMessages()
      local.forEach(msg => {
        if (msg.role === 'user') appendUserMessage(msg.content || '')
        else appendAiMessage(msg.content || '')
      })
      scrollToBottom()
    }
  }
  if (!wsClient.gatewayReady) return
  try {
    const result = await wsClient.chatHistory(_sessionKey, 200)
    if (!result?.messages?.length) {
      if (!_messagesEl.querySelector('.msg')) appendSystemMessage('还没有消息，开始聊天吧')
      return
    }
    const deduped = dedupeHistory(result.messages)
    const hash = deduped.map(m => `${m.role}:${(m.text || '').length}`).join('|')
    if (hash === _lastHistoryHash && _messagesEl.querySelector('.msg')) return
    _lastHistoryHash = hash
    clearMessages()
    deduped.forEach(msg => {
      if (msg.role === 'user') appendUserMessage(msg.text)
      else if (msg.role === 'assistant') appendAiMessage(msg.text)
    })
    saveMessages(result.messages.map(m => {
      const c = extractContent(m)
      return { id: m.id || uuid(), sessionKey: _sessionKey, role: m.role, content: c || '', timestamp: m.timestamp || Date.now() }
    }))
    scrollToBottom()
  } catch (e) {
    console.error('[chat] loadHistory error:', e)
    if (!_messagesEl.querySelector('.msg')) appendSystemMessage('加载历史失败: ' + e.message)
  }
}

function dedupeHistory(messages) {
  const deduped = []
  for (const msg of messages) {
    if (msg.role === 'toolResult') continue
    const text = extractContent(msg)
    if (!text) continue
    const last = deduped[deduped.length - 1]
    if (last && last.role === msg.role) {
      if (msg.role === 'user' && last.text === text) continue
      if (msg.role === 'assistant') {
        last.text = [last.text, text].filter(Boolean).join('\n')
        continue
      }
    }
    deduped.push({ role: msg.role, text, timestamp: msg.timestamp })
  }
  return deduped
}

function extractContent(msg) {
  if (typeof msg.text === 'string') return msg.text
  if (typeof msg.content === 'string') return msg.content
  if (Array.isArray(msg.content)) {
    return msg.content.filter(c => c.type === 'text').map(c => c.text).join('\n')
  }
  return ''
}

// ── DOM 操作 ──

function appendUserMessage(text, attachments = []) {
  const wrap = document.createElement('div')
  wrap.className = 'msg msg-user'
  const bubble = document.createElement('div')
  bubble.className = 'msg-bubble'

  if (attachments.length > 0) {
    const imgContainer = document.createElement('div')
    imgContainer.style.cssText = 'display:flex;gap:4px;margin-bottom:8px;flex-wrap:wrap'
    attachments.forEach(att => {
      const img = document.createElement('img')
      img.src = `data:${att.mimeType};base64,${att.content}`
      img.style.cssText = 'max-width:200px;max-height:200px;border-radius:4px'
      imgContainer.appendChild(img)
    })
    bubble.appendChild(imgContainer)
  }

  if (text) {
    const textNode = document.createElement('div')
    textNode.textContent = text
    bubble.appendChild(textNode)
  }

  wrap.appendChild(bubble)
  _messagesEl.insertBefore(wrap, _typingEl)
  scrollToBottom()
}

function appendAiMessage(text) {
  const wrap = document.createElement('div')
  wrap.className = 'msg msg-ai'
  const bubble = document.createElement('div')
  bubble.className = 'msg-bubble'
  bubble.innerHTML = renderMarkdown(text)
  wrap.appendChild(bubble)
  _messagesEl.insertBefore(wrap, _typingEl)
  scrollToBottom()
}

function appendSystemMessage(text) {
  const wrap = document.createElement('div')
  wrap.className = 'msg msg-system'
  wrap.textContent = text
  _messagesEl.insertBefore(wrap, _typingEl)
  scrollToBottom()
}

function clearMessages() {
  _messagesEl.querySelectorAll('.msg').forEach(m => m.remove())
}

function showTyping(show) {
  if (_typingEl) _typingEl.style.display = show ? 'flex' : 'none'
  if (show) scrollToBottom()
}

function scrollToBottom() {
  if (!_messagesEl) return
  requestAnimationFrame(() => { _messagesEl.scrollTop = _messagesEl.scrollHeight })
}

function updateSendState() {
  if (!_sendBtn || !_textarea) return
  if (_isStreaming) {
    _sendBtn.disabled = false
    _sendBtn.innerHTML = '<svg viewBox="0 0 24 24" fill="currentColor" width="20" height="20"><rect x="6" y="6" width="12" height="12" rx="2"/></svg>'
    _sendBtn.title = '停止生成'
  } else {
    _sendBtn.disabled = !_textarea.value.trim() && !_attachments.length
    _sendBtn.innerHTML = '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" width="20" height="20"><line x1="22" y1="2" x2="11" y2="13"/><polygon points="22 2 15 22 11 13 2 9 22 2"/></svg>'
    _sendBtn.title = '发送'
  }
}

function updateStatusDot(status) {
  if (!_statusDot) return
  _statusDot.className = 'status-dot'
  if (status === 'ready' || status === 'connected') _statusDot.classList.add('online')
  else if (status === 'connecting' || status === 'reconnecting') _statusDot.classList.add('connecting')
  else _statusDot.classList.add('offline')
}

// ── 页面离开清理 ──

export function cleanup() {
  _pageActive = false
  if (_unsubEvent) { _unsubEvent(); _unsubEvent = null }
  if (_unsubReady) { _unsubReady(); _unsubReady = null }
  if (_unsubStatus) { _unsubStatus(); _unsubStatus = null }
  clearTimeout(_streamSafetyTimer)
  // 不断开 wsClient —— 它是全局单例，保持连接供下次进入复用
  _sessionKey = null
  _page = null
  _messagesEl = null
  _textarea = null
  _sendBtn = null
  _statusDot = null
  _typingEl = null
  _scrollBtn = null
  _sessionListEl = null
  _cmdPanelEl = null
  _currentAiBubble = null
  _currentAiText = ''
  _currentRunId = null
  _isStreaming = false
  _isSending = false
  _messageQueue = []
  _lastHistoryHash = ''
}
