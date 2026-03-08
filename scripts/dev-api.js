/**
 * ClawPanel 开发模式 API 插件
 * 在 Vite 开发服务器上提供真实 API 端点，替代 mock 数据
 * 使浏览器模式能真正管理 OpenClaw 实例
 */
import fs from 'fs'
import path from 'path'
import os from 'os'
import { homedir, networkInterfaces } from 'os'
import { execSync, spawn } from 'child_process'
import { fileURLToPath } from 'url'
import net from 'net'
import http from 'http'
import crypto from 'crypto'

const OPENCLAW_DIR = path.join(homedir(), '.openclaw')
const CONFIG_PATH = path.join(OPENCLAW_DIR, 'openclaw.json')
const MCP_CONFIG_PATH = path.join(OPENCLAW_DIR, 'mcp.json')
const LOGS_DIR = path.join(OPENCLAW_DIR, 'logs')
const BACKUPS_DIR = path.join(OPENCLAW_DIR, 'backups')
const DEVICE_KEY_FILE = path.join(OPENCLAW_DIR, 'clawpanel-device-key.json')
const DEVICES_DIR = path.join(OPENCLAW_DIR, 'devices')
const PAIRED_PATH = path.join(DEVICES_DIR, 'paired.json')
const isWindows = process.platform === 'win32'
const isMac = process.platform === 'darwin'
const isLinux = process.platform === 'linux'
const SCOPES = ['operator.admin', 'operator.approvals', 'operator.pairing', 'operator.read', 'operator.write']
const PANEL_CONFIG_PATH = path.join(OPENCLAW_DIR, 'clawpanel.json')
const DOCKER_NODES_PATH = path.join(OPENCLAW_DIR, 'docker-nodes.json')
const INSTANCES_PATH = path.join(OPENCLAW_DIR, 'instances.json')
const DOCKER_SOCKET = process.platform === 'win32' ? '//./pipe/docker_engine' : '/var/run/docker.sock'
const OPENCLAW_IMAGE = 'ghcr.io/qingchencloud/openclaw'

// 语义化版本比较
function versionGe(a, b) {
  const pa = a.split('.').map(Number), pb = b.split('.').map(Number)
  for (let i = 0; i < Math.max(pa.length, pb.length); i++) {
    if ((pa[i] || 0) > (pb[i] || 0)) return true
    if ((pa[i] || 0) < (pb[i] || 0)) return false
  }
  return true
}
function versionGt(a, b) {
  const pa = a.split('.').map(Number), pb = b.split('.').map(Number)
  for (let i = 0; i < Math.max(pa.length, pb.length); i++) {
    if ((pa[i] || 0) > (pb[i] || 0)) return true
    if ((pa[i] || 0) < (pb[i] || 0)) return false
  }
  return false
}

// === 访问密码 & Session 管理 ===

const _sessions = new Map() // token → { expires }
const SESSION_TTL = 24 * 60 * 60 * 1000 // 24h
const AUTH_EXEMPT = new Set(['auth_check', 'auth_login', 'auth_logout'])

// 登录限速：防暴力破解（IP 级别，5次失败后锁定60秒）
const _loginAttempts = new Map() // ip → { count, lockedUntil }
const MAX_LOGIN_ATTEMPTS = 5
const LOCKOUT_DURATION = 60 * 1000 // 60s

function checkLoginRateLimit(ip) {
  const now = Date.now()
  const record = _loginAttempts.get(ip)
  if (!record) return null
  if (record.lockedUntil && now < record.lockedUntil) {
    const remaining = Math.ceil((record.lockedUntil - now) / 1000)
    return `登录失败次数过多，请 ${remaining} 秒后再试`
  }
  if (record.lockedUntil && now >= record.lockedUntil) {
    _loginAttempts.delete(ip)
  }
  return null
}

function recordLoginFailure(ip) {
  const record = _loginAttempts.get(ip) || { count: 0, lockedUntil: null }
  record.count++
  if (record.count >= MAX_LOGIN_ATTEMPTS) {
    record.lockedUntil = Date.now() + LOCKOUT_DURATION
    record.count = 0
  }
  _loginAttempts.set(ip, record)
}

function clearLoginAttempts(ip) {
  _loginAttempts.delete(ip)
}

// 配置缓存：避免每次请求同步读磁盘（TTL 2秒，写入时立即失效）
let _panelConfigCache = null
let _panelConfigCacheTime = 0
const CONFIG_CACHE_TTL = 2000 // 2s

function readPanelConfig() {
  const now = Date.now()
  if (_panelConfigCache && (now - _panelConfigCacheTime) < CONFIG_CACHE_TTL) {
    return JSON.parse(JSON.stringify(_panelConfigCache))
  }
  try {
    if (fs.existsSync(PANEL_CONFIG_PATH)) {
      _panelConfigCache = JSON.parse(fs.readFileSync(PANEL_CONFIG_PATH, 'utf8'))
      _panelConfigCacheTime = now
      return JSON.parse(JSON.stringify(_panelConfigCache))
    }
  } catch {}
  return {}
}

function invalidateConfigCache() {
  _panelConfigCache = null
  _panelConfigCacheTime = 0
}

function getAccessPassword() {
  return readPanelConfig().accessPassword || ''
}

function parseCookies(req) {
  const obj = {}
  ;(req.headers.cookie || '').split(';').forEach(pair => {
    const [k, ...v] = pair.trim().split('=')
    if (k) obj[k] = decodeURIComponent(v.join('='))
  })
  return obj
}

function isAuthenticated(req) {
  const pw = getAccessPassword()
  if (!pw) return true // 未设密码，放行
  const cookies = parseCookies(req)
  const token = cookies.clawpanel_session
  if (!token) return false
  const session = _sessions.get(token)
  if (!session || Date.now() > session.expires) {
    _sessions.delete(token)
    return false
  }
  return true
}

function checkPasswordStrength(pw) {
  if (!pw || pw.length < 6) return '密码至少 6 位'
  if (pw.length > 64) return '密码不能超过 64 位'
  if (/^\d+$/.test(pw)) return '密码不能是纯数字'
  const weak = ['123456', '654321', 'password', 'admin', 'qwerty', 'abc123', '111111', '000000', 'letmein', 'welcome', 'clawpanel', 'openclaw']
  if (weak.includes(pw.toLowerCase())) return '密码太常见，请换一个更安全的密码'
  return null // 通过
}

function isUnsafePath(p) {
  return !p || p.includes('..') || p.includes('\0') || path.isAbsolute(p)
}

const MAX_BODY_SIZE = 1024 * 1024 // 1MB

function readBody(req) {
  return new Promise((resolve) => {
    let body = ''
    let size = 0
    req.on('data', chunk => {
      size += chunk.length
      if (size > MAX_BODY_SIZE) { req.destroy(); resolve({}); return }
      body += chunk
    })
    req.on('end', () => {
      try { resolve(JSON.parse(body || '{}')) }
      catch { resolve({}) }
    })
  })
}

function getUid() {
  if (!isMac) return 0
  return execSync('id -u').toString().trim()
}

function stripUiFields(config) {
  const providers = config?.models?.providers
  if (!providers) return config
  for (const p of Object.values(providers)) {
    if (!Array.isArray(p.models)) continue
    for (const m of p.models) {
      if (typeof m !== 'object') continue
      delete m.lastTestAt
      delete m.latency
      delete m.testStatus
      delete m.testError
      if (!m.name && m.id) m.name = m.id
    }
  }
  return config
}

// === Ed25519 设备密钥管理 ===

function getOrCreateDeviceKey() {
  if (fs.existsSync(DEVICE_KEY_FILE)) {
    const data = JSON.parse(fs.readFileSync(DEVICE_KEY_FILE, 'utf8'))
    // 从存储的 hex 密钥重建 Node.js KeyObject
    const privDer = Buffer.concat([
      Buffer.from('302e020100300506032b657004220420', 'hex'), // PKCS8 Ed25519 header
      Buffer.from(data.secretKey, 'hex'),
    ])
    const privateKey = crypto.createPrivateKey({ key: privDer, format: 'der', type: 'pkcs8' })
    return { deviceId: data.deviceId, publicKey: data.publicKey, privateKey }
  }
  // 生成新密钥对
  const keyPair = crypto.generateKeyPairSync('ed25519')
  const pubDer = keyPair.publicKey.export({ type: 'spki', format: 'der' })
  const privDer = keyPair.privateKey.export({ type: 'pkcs8', format: 'der' })
  const pubRaw = pubDer.slice(-32)
  const privRaw = privDer.slice(-32)
  const deviceId = crypto.createHash('sha256').update(pubRaw).digest('hex')
  const publicKey = Buffer.from(pubRaw).toString('base64url')
  const secretHex = Buffer.from(privRaw).toString('hex')
  const keyData = { deviceId, publicKey, secretKey: secretHex }
  if (!fs.existsSync(OPENCLAW_DIR)) fs.mkdirSync(OPENCLAW_DIR, { recursive: true })
  fs.writeFileSync(DEVICE_KEY_FILE, JSON.stringify(keyData, null, 2))
  return { deviceId, publicKey, privateKey: keyPair.privateKey }
}

function getLocalIps() {
  const ips = []
  const ifaces = networkInterfaces()
  for (const name in ifaces) {
    for (const iface of ifaces[name]) {
      if (iface.family === 'IPv4' && !iface.internal) ips.push(iface.address)
    }
  }
  return ips
}

function patchGatewayOrigins() {
  if (!fs.existsSync(CONFIG_PATH)) return false
  const config = JSON.parse(fs.readFileSync(CONFIG_PATH, 'utf8'))
  const origins = [
    'tauri://localhost',
    'https://tauri.localhost',
    'http://localhost',
    'http://localhost:1420',
    'http://127.0.0.1:1420',
  ]
  for (const ip of getLocalIps()) {
    origins.push(`http://${ip}:1420`)
  }
  const existing = config?.gateway?.controlUi?.allowedOrigins || []
  // 合并：保留用户已有的 origins，只追加 ClawPanel 需要的
  const merged = [...new Set([...existing, ...origins])]
  // 幂等：已包含所有需要的 origin 时跳过写入
  if (origins.every(o => existing.includes(o))) return false
  if (!config.gateway) config.gateway = {}
  if (!config.gateway.controlUi) config.gateway.controlUi = {}
  config.gateway.controlUi.allowedOrigins = merged
  fs.copyFileSync(CONFIG_PATH, CONFIG_PATH + '.bak')
  fs.writeFileSync(CONFIG_PATH, JSON.stringify(config, null, 2))
  return true
}

// === macOS 服务管理 ===

function macCheckService(label) {
  try {
    const uid = getUid()
    const output = execSync(`launchctl print gui/${uid}/${label} 2>&1`).toString()
    let state = '', pid = null
    for (const line of output.split('\n')) {
      if (!line.startsWith('\t') || line.startsWith('\t\t')) continue
      const trimmed = line.trim()
      if (trimmed.startsWith('pid = ')) pid = parseInt(trimmed.slice(6)) || null
      if (trimmed.startsWith('state = ')) state = trimmed.slice(8).trim()
    }
    // 有 PID 则用 kill -0 验证进程是否存活（比 state 字符串更可靠）
    if (pid) {
      try { execSync(`kill -0 ${pid} 2>&1`); return { running: true, pid } } catch {}
    }
    // 无 PID 时 fallback 到 pgrep（launchctl 可能还没刷出 PID）
    if (state === 'running' || state === 'waiting') {
      try {
        const pgrepOut = execSync(`pgrep -f "openclaw.*gateway" 2>/dev/null`).toString().trim()
        if (pgrepOut) {
          const fallbackPid = parseInt(pgrepOut.split('\n')[0]) || null
          if (fallbackPid) return { running: true, pid: fallbackPid }
        }
      } catch {}
    }
    return { running: state === 'running', pid }
  } catch {
    return { running: false, pid: null }
  }
}

function macStartService(label) {
  const uid = getUid()
  const plistPath = path.join(homedir(), `Library/LaunchAgents/${label}.plist`)
  if (!fs.existsSync(plistPath)) throw new Error(`plist 不存在: ${plistPath}`)
  try { execSync(`launchctl bootstrap gui/${uid} "${plistPath}" 2>&1`) } catch {}
  try { execSync(`launchctl kickstart gui/${uid}/${label} 2>&1`) } catch {}
}

function macStopService(label) {
  const uid = getUid()
  try { execSync(`launchctl bootout gui/${uid}/${label} 2>&1`) } catch {}
}

function macRestartService(label) {
  const uid = getUid()
  const plistPath = path.join(homedir(), `Library/LaunchAgents/${label}.plist`)
  try { execSync(`launchctl bootout gui/${uid}/${label} 2>&1`) } catch {}
  // 等待进程退出
  for (let i = 0; i < 15; i++) {
    const { running } = macCheckService(label)
    if (!running) break
    execSync('sleep 0.2')
  }
  try { execSync(`launchctl bootstrap gui/${uid} "${plistPath}" 2>&1`) } catch {}
  try { execSync(`launchctl kickstart -k gui/${uid}/${label} 2>&1`) } catch {}
}

// === Windows 服务管理 ===

function winStartGateway() {
  // 确保日志目录存在
  if (!fs.existsSync(LOGS_DIR)) fs.mkdirSync(LOGS_DIR, { recursive: true })
  const logPath = path.join(LOGS_DIR, 'gateway.log')
  const errPath = path.join(LOGS_DIR, 'gateway.err.log')
  const out = fs.openSync(logPath, 'a')
  const err = fs.openSync(errPath, 'a')

  // 写入启动标记到日志
  const timestamp = new Date().toISOString()
  fs.appendFileSync(logPath, `\n[${timestamp}] [ClawPanel] Starting Gateway on Windows...\n`)

  // 用 cmd.exe /c 启动，不用 shell: true（避免额外 cmd.exe 进程链导致终端闪烁）
  const child = spawn('cmd.exe', ['/c', 'openclaw', 'gateway'], {
    detached: true,
    stdio: ['ignore', out, err],
    windowsHide: true,
    cwd: homedir(),
  })
  child.unref()
}

async function winStopGateway() {
  const { running } = await winCheckGateway()
  if (!running) throw new Error('Gateway 未运行')
  try {
    execSync('taskkill /F /IM node.exe /FI "WINDOWTITLE eq openclaw*"', { timeout: 5000, windowsHide: true })
  } catch {
    try {
      execSync('taskkill /F /IM node.exe', { timeout: 5000, windowsHide: true })
    } catch (e) {
      throw new Error('停止失败: ' + (e.message || e))
    }
  }
}

// TCP 探测 Gateway 端口（纯异步，零子进程，不会闪终端）
function winCheckGateway() {
  const port = readGatewayPort()
  return new Promise(resolve => {
    const sock = new net.Socket()
    sock.setTimeout(300)
    sock.once('connect', () => {
      sock.destroy()
      resolve({ running: true, pid: null })
    })
    sock.once('error', () => {
      sock.destroy()
      resolve({ running: false, pid: null })
    })
    sock.once('timeout', () => {
      sock.destroy()
      resolve({ running: false, pid: null })
    })
    sock.connect(port, '127.0.0.1')
  })
}

function readGatewayPort() {
  try {
    const config = JSON.parse(fs.readFileSync(CONFIG_PATH, 'utf8'))
    return config?.gateway?.port || 18789
  } catch {
    return 18789
  }
}

// === Linux 服务管理 ===

/**
 * 扫描常见 Node 版本管理器路径查找 openclaw 二进制文件。
 * 解决 systemd 服务环境中 PATH 不含 nvm/volta/fnm 路径的问题。
 */
function findOpenclawBin() {
  try {
    return execSync('which openclaw 2>/dev/null', { stdio: 'pipe' }).toString().trim()
  } catch {}

  const home = homedir()
  const candidates = [
    '/usr/local/bin/openclaw',
    '/usr/bin/openclaw',
    '/snap/bin/openclaw',
    path.join(home, '.local/bin/openclaw'),
  ]

  // nvm
  const nvmDir = process.env.NVM_DIR || path.join(home, '.nvm')
  const nvmVersions = path.join(nvmDir, 'versions/node')
  if (fs.existsSync(nvmVersions)) {
    try {
      for (const entry of fs.readdirSync(nvmVersions)) {
        candidates.push(path.join(nvmVersions, entry, 'bin/openclaw'))
      }
    } catch {}
  }

  // volta
  candidates.push(path.join(home, '.volta/bin/openclaw'))

  // nodenv
  candidates.push(path.join(home, '.nodenv/shims/openclaw'))

  // fnm
  const fnmDir = process.env.FNM_DIR || path.join(home, '.local/share/fnm')
  const fnmVersions = path.join(fnmDir, 'node-versions')
  if (fs.existsSync(fnmVersions)) {
    try {
      for (const entry of fs.readdirSync(fnmVersions)) {
        candidates.push(path.join(fnmVersions, entry, 'installation/bin/openclaw'))
      }
    } catch {}
  }

  // /usr/local/lib/nodejs（手动安装的 Node.js）
  const nodejsLib = '/usr/local/lib/nodejs'
  if (fs.existsSync(nodejsLib)) {
    try {
      for (const entry of fs.readdirSync(nodejsLib)) {
        candidates.push(path.join(nodejsLib, entry, 'bin/openclaw'))
      }
    } catch {}
  }

  for (const p of candidates) {
    if (fs.existsSync(p)) return p
  }
  return null
}

function linuxCheckGateway() {
  const port = readGatewayPort()
  // ss 查端口监听
  try {
    const out = execSync(`ss -tlnp 'sport = :${port}' 2>/dev/null`, { timeout: 3000 }).toString().trim()
    const pidMatch = out.match(/pid=(\d+)/)
    if (pidMatch) return { running: true, pid: parseInt(pidMatch[1]) }
    if (out.includes(`:${port}`)) return { running: true, pid: null }
  } catch {}
  // fallback: lsof
  try {
    const out = execSync(`lsof -i :${port} -t 2>/dev/null`, { timeout: 3000 }).toString().trim()
    if (out) {
      const pid = parseInt(out.split('\n')[0]) || null
      return { running: !!pid, pid }
    }
  } catch {}
  // fallback: /proc/net/tcp
  try {
    const hexPort = port.toString(16).toUpperCase().padStart(4, '0')
    const tcp = fs.readFileSync('/proc/net/tcp', 'utf8')
    if (tcp.includes(`:${hexPort}`)) return { running: true, pid: null }
  } catch {}
  return { running: false, pid: null }
}

function linuxStartGateway() {
  if (!fs.existsSync(LOGS_DIR)) fs.mkdirSync(LOGS_DIR, { recursive: true })
  const logPath = path.join(LOGS_DIR, 'gateway.log')
  const errPath = path.join(LOGS_DIR, 'gateway.err.log')
  const out = fs.openSync(logPath, 'a')
  const err = fs.openSync(errPath, 'a')

  const timestamp = new Date().toISOString()
  fs.appendFileSync(logPath, `\n[${timestamp}] [ClawPanel] Starting Gateway on Linux...\n`)

  const bin = findOpenclawBin() || 'openclaw'
  const child = spawn(bin, ['gateway'], {
    detached: true,
    stdio: ['ignore', out, err],
    shell: false,
    cwd: homedir(),
  })
  child.unref()
}

function linuxStopGateway() {
  const { running, pid } = linuxCheckGateway()
  if (!running || !pid) throw new Error('Gateway 未运行')
  try {
    process.kill(pid, 'SIGTERM')
  } catch (e) {
    try { process.kill(pid, 'SIGKILL') } catch {}
    throw new Error('停止失败: ' + (e.message || e))
  }
}

// === Docker Socket 通信 ===

function dockerRequest(method, apiPath, body = null, endpoint = null) {
  return new Promise((resolve, reject) => {
    const opts = { path: apiPath, method, headers: { 'Content-Type': 'application/json' } }
    if (endpoint && endpoint.startsWith('tcp://')) {
      const url = new URL(endpoint.replace('tcp://', 'http://'))
      opts.hostname = url.hostname
      opts.port = parseInt(url.port) || 2375
    } else {
      opts.socketPath = endpoint || DOCKER_SOCKET
    }
    const req = http.request(opts, (res) => {
      let data = ''
      res.on('data', chunk => data += chunk)
      res.on('end', () => {
        try { resolve({ status: res.statusCode, data: JSON.parse(data) }) }
        catch { resolve({ status: res.statusCode, data }) }
      })
    })
    req.on('error', (e) => reject(new Error('Docker 连接失败: ' + e.message)))
    req.setTimeout(30000, () => { req.destroy(); reject(new Error('Docker API 超时')) })
    if (body) req.write(JSON.stringify(body))
    req.end()
  })
}

function readDockerNodes() {
  if (!fs.existsSync(DOCKER_NODES_PATH)) {
    return [{ id: 'local', name: '本机', type: 'socket', endpoint: DOCKER_SOCKET }]
  }
  try {
    const data = JSON.parse(fs.readFileSync(DOCKER_NODES_PATH, 'utf8'))
    return data.nodes || []
  } catch {
    return [{ id: 'local', name: '本机', type: 'socket', endpoint: DOCKER_SOCKET }]
  }
}

function saveDockerNodes(nodes) {
  if (!fs.existsSync(OPENCLAW_DIR)) fs.mkdirSync(OPENCLAW_DIR, { recursive: true })
  fs.writeFileSync(DOCKER_NODES_PATH, JSON.stringify({ nodes }, null, 2))
}

function isDockerAvailable() {
  if (isWindows) return true // named pipe, can't stat
  return fs.existsSync(DOCKER_SOCKET)
}

// === 镜像拉取进度追踪 ===
const _pullProgress = new Map()

// === 实例注册表 ===

const DEFAULT_LOCAL_INSTANCE = { id: 'local', name: '本机', type: 'local', endpoint: null, gatewayPort: 18789, addedAt: 0, note: '' }

function readInstances() {
  if (!fs.existsSync(INSTANCES_PATH)) {
    return { activeId: 'local', instances: [{ ...DEFAULT_LOCAL_INSTANCE }] }
  }
  try {
    const data = JSON.parse(fs.readFileSync(INSTANCES_PATH, 'utf8'))
    if (!data.instances?.length) data.instances = [{ ...DEFAULT_LOCAL_INSTANCE }]
    if (!data.instances.find(i => i.id === 'local')) data.instances.unshift({ ...DEFAULT_LOCAL_INSTANCE })
    if (!data.activeId || !data.instances.find(i => i.id === data.activeId)) data.activeId = 'local'
    return data
  } catch {
    return { activeId: 'local', instances: [{ ...DEFAULT_LOCAL_INSTANCE }] }
  }
}

function saveInstances(data) {
  if (!fs.existsSync(OPENCLAW_DIR)) fs.mkdirSync(OPENCLAW_DIR, { recursive: true })
  fs.writeFileSync(INSTANCES_PATH, JSON.stringify(data, null, 2))
}

function getActiveInstance() {
  const data = readInstances()
  return data.instances.find(i => i.id === data.activeId) || data.instances[0]
}

async function proxyToInstance(instance, cmd, body) {
  const url = `${instance.endpoint}/__api/${cmd}`
  const resp = await fetch(url, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(body),
  })
  const text = await resp.text()
  try { return JSON.parse(text) }
  catch { return text }
}

async function instanceHealthCheck(instance) {
  const result = { id: instance.id, online: false, version: null, gatewayRunning: false, lastCheck: Date.now() }
  if (instance.type === 'local') {
    result.online = true
    try {
      const services = await handlers.get_services_status()
      result.gatewayRunning = services?.[0]?.running === true
    } catch {}
    try {
      const ver = await handlers.get_version_info()
      result.version = ver?.current
    } catch {}
    return result
  }
  // Docker 类型实例：通过 Docker API 检查容器状态
  if (instance.type === 'docker' && instance.containerId) {
    try {
      const nodes = readDockerNodes()
      const node = instance.nodeId ? nodes.find(n => n.id === instance.nodeId) : nodes[0]
      if (node) {
        const resp = await dockerRequest('GET', `/containers/${instance.containerId}/json`, null, node.endpoint)
        if (resp.status < 400 && resp.data?.State?.Running) {
          result.online = true
          result.gatewayRunning = true
        }
      }
    } catch {}
    return result
  }

  if (!instance.endpoint) return result
  try {
    const resp = await fetch(`${instance.endpoint}/__api/check_installation`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: '{}',
      signal: AbortSignal.timeout(5000),
    })
    if (resp.ok) {
      const data = await resp.json()
      result.online = true
      result.version = data?.version || null
    }
  } catch {}
  if (result.online) {
    try {
      const resp = await fetch(`${instance.endpoint}/__api/get_services_status`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: '{}',
        signal: AbortSignal.timeout(5000),
      })
      if (resp.ok) {
        const services = await resp.json()
        result.gatewayRunning = services?.[0]?.running === true
      }
    } catch {}
  }
  return result
}

// 始终在本机处理的命令（不代理到远程实例）
const ALWAYS_LOCAL = new Set([
  'instance_list', 'instance_add', 'instance_remove', 'instance_set_active',
  'instance_health_check', 'instance_health_all',
  'docker_info', 'docker_list_containers', 'docker_create_container',
  'docker_start_container', 'docker_stop_container', 'docker_restart_container',
  'docker_remove_container', 'docker_container_logs', 'docker_container_exec', 'docker_init_worker', 'docker_gateway_chat', 'docker_pull_image', 'docker_pull_status',
  'docker_list_images', 'docker_list_nodes', 'docker_add_node', 'docker_remove_node',
  'docker_cluster_overview',
  'auth_check', 'auth_login', 'auth_logout',
  'read_panel_config', 'write_panel_config',
  'get_deploy_mode',
  'assistant_exec', 'assistant_read_file', 'assistant_write_file',
  'assistant_list_dir', 'assistant_system_info', 'assistant_list_processes',
  'assistant_check_port', 'assistant_web_search', 'assistant_fetch_url',
  'assistant_ensure_data_dir', 'assistant_save_image', 'assistant_load_image', 'assistant_delete_image',
])

// === API Handlers ===

const handlers = {
  // 配置读写
  read_openclaw_config() {
    if (!fs.existsSync(CONFIG_PATH)) throw new Error('openclaw.json 不存在，请先安装 OpenClaw')
    const content = fs.readFileSync(CONFIG_PATH, 'utf8')
    return JSON.parse(content)
  },

  write_openclaw_config({ config }) {
    const bak = CONFIG_PATH + '.bak'
    if (fs.existsSync(CONFIG_PATH)) fs.copyFileSync(CONFIG_PATH, bak)
    const cleaned = stripUiFields(config)
    fs.writeFileSync(CONFIG_PATH, JSON.stringify(cleaned, null, 2))
    return true
  },

  read_mcp_config() {
    if (!fs.existsSync(MCP_CONFIG_PATH)) return {}
    return JSON.parse(fs.readFileSync(MCP_CONFIG_PATH, 'utf8'))
  },

  write_mcp_config({ config }) {
    fs.writeFileSync(MCP_CONFIG_PATH, JSON.stringify(config, null, 2))
    return true
  },

  // 服务管理
  async get_services_status() {
    const label = 'ai.openclaw.gateway'
    const { running, pid } = isMac ? macCheckService(label) : isLinux ? linuxCheckGateway() : await winCheckGateway()

    let cliInstalled = false
    if (isMac) {
      cliInstalled = fs.existsSync('/opt/homebrew/bin/openclaw') || fs.existsSync('/usr/local/bin/openclaw')
    } else if (isWindows) {
      try { cliInstalled = fs.existsSync(path.join(process.env.APPDATA || '', 'npm', 'openclaw.cmd')) }
      catch { cliInstalled = false }
    } else {
      cliInstalled = !!findOpenclawBin()
    }

    return [{ label, running, pid, description: 'OpenClaw Gateway', cli_installed: cliInstalled }]
  },

  start_service({ label }) {
    if (isMac) { macStartService(label); return true }
    if (isLinux) { linuxStartGateway(); return true }
    winStartGateway()
    return true
  },

  async stop_service({ label }) {
    if (isMac) { macStopService(label); return true }
    if (isLinux) { linuxStopGateway(); return true }
    await winStopGateway()
    return true
  },

  async restart_service({ label }) {
    if (isMac) { macRestartService(label); return true }
    if (isLinux) {
      try { linuxStopGateway() } catch {}
      for (let i = 0; i < 10; i++) {
        const { running } = linuxCheckGateway()
        if (!running) break
        await new Promise(r => setTimeout(r, 500))
      }
      linuxStartGateway()
      return true
    }
    try { await winStopGateway() } catch {}
    for (let i = 0; i < 10; i++) {
      const { running } = await winCheckGateway()
      if (!running) break
      await new Promise(r => setTimeout(r, 500))
    }
    winStartGateway()
    return true
  },

  reload_gateway() {
    if (isMac) {
      macRestartService('ai.openclaw.gateway')
      return 'Gateway 已重启'
    } else if (isLinux) {
      try { linuxStopGateway() } catch {}
      linuxStartGateway()
      return 'Gateway 已重启'
    } else {
      throw new Error('Windows 请使用 Tauri 桌面应用')
    }
  },

  restart_gateway() {
    if (isMac) {
      macRestartService('ai.openclaw.gateway')
      return 'Gateway 已重启'
    } else if (isLinux) {
      try { linuxStopGateway() } catch {}
      linuxStartGateway()
      return 'Gateway 已重启'
    } else {
      throw new Error('Windows 请使用 Tauri 桌面应用')
    }
  },

  // === 实例管理 ===

  instance_list() {
    const data = readInstances()
    return data
  },

  instance_add({ name, type, endpoint, gatewayPort, containerId, nodeId, note }) {
    if (!name) throw new Error('实例名称不能为空')
    if (!endpoint) throw new Error('端点地址不能为空')
    const data = readInstances()
    const id = type === 'docker' ? `docker-${(containerId || Date.now().toString(36)).slice(0, 12)}` : `remote-${Date.now().toString(36)}`
    if (data.instances.find(i => i.endpoint === endpoint)) throw new Error('该端点已存在')
    data.instances.push({
      id, name, type: type || 'remote', endpoint,
      gatewayPort: gatewayPort || 18789,
      containerId: containerId || null,
      nodeId: nodeId || null,
      addedAt: Math.floor(Date.now() / 1000),
      note: note || '',
    })
    saveInstances(data)
    return { id, name }
  },

  instance_remove({ id }) {
    if (id === 'local') throw new Error('本机实例不可删除')
    const data = readInstances()
    data.instances = data.instances.filter(i => i.id !== id)
    if (data.activeId === id) data.activeId = 'local'
    saveInstances(data)
    return true
  },

  instance_set_active({ id }) {
    const data = readInstances()
    if (!data.instances.find(i => i.id === id)) throw new Error('实例不存在')
    data.activeId = id
    saveInstances(data)
    return { activeId: id }
  },

  async instance_health_check({ id }) {
    const data = readInstances()
    const instance = data.instances.find(i => i.id === id)
    if (!instance) throw new Error('实例不存在')
    return instanceHealthCheck(instance)
  },

  async instance_health_all() {
    const data = readInstances()
    const results = await Promise.allSettled(data.instances.map(i => instanceHealthCheck(i)))
    return results.map((r, idx) => r.status === 'fulfilled' ? r.value : { id: data.instances[idx].id, online: false, lastCheck: Date.now() })
  },

  // === Docker 集群管理 ===

  async docker_test_endpoint({ endpoint } = {}) {
    if (!endpoint) throw new Error('请提供端点地址')
    const resp = await dockerRequest('GET', '/info', null, endpoint)
    if (resp.status !== 200) throw new Error('Docker 守护进程未响应')
    const d = resp.data
    return {
      ServerVersion: d.ServerVersion,
      Containers: d.Containers,
      Images: d.Images,
      OS: d.OperatingSystem,
    }
  },

  async docker_info({ nodeId } = {}) {
    const nodes = readDockerNodes()
    const node = nodeId ? nodes.find(n => n.id === nodeId) : nodes[0]
    if (!node) throw new Error('节点不存在')
    const resp = await dockerRequest('GET', '/info', null, node.endpoint)
    if (resp.status !== 200) throw new Error('Docker 守护进程未响应')
    const d = resp.data
    return {
      nodeId: node.id, nodeName: node.name,
      containers: d.Containers, containersRunning: d.ContainersRunning,
      containersPaused: d.ContainersPaused, containersStopped: d.ContainersStopped,
      images: d.Images, serverVersion: d.ServerVersion,
      os: d.OperatingSystem, arch: d.Architecture,
      cpus: d.NCPU, memory: d.MemTotal,
    }
  },

  async docker_list_containers({ nodeId, all = true } = {}) {
    const nodes = readDockerNodes()
    const node = nodeId ? nodes.find(n => n.id === nodeId) : nodes[0]
    if (!node) throw new Error('节点不存在')
    const query = all ? '?all=true' : ''
    const resp = await dockerRequest('GET', `/containers/json${query}`, null, node.endpoint)
    if (resp.status !== 200) throw new Error('获取容器列表失败')
    return (resp.data || []).map(c => ({
      id: c.Id?.slice(0, 12),
      name: (c.Names?.[0] || '').replace(/^\//, ''),
      image: c.Image,
      state: c.State,
      status: c.Status,
      ports: (c.Ports || []).map(p => p.PublicPort ? `${p.PublicPort}→${p.PrivatePort}` : `${p.PrivatePort}`).join(', '),
      created: c.Created,
      nodeId: node.id, nodeName: node.name,
    }))
  },

  async docker_create_container({ nodeId, name, image, tag = 'latest', panelPort = 1420, gatewayPort = 18789, envVars = {}, volume = true } = {}) {
    const nodes = readDockerNodes()
    const node = nodeId ? nodes.find(n => n.id === nodeId) : nodes[0]
    if (!node) throw new Error('节点不存在')
    const imgFull = `${image || OPENCLAW_IMAGE}:${tag}`
    const containerName = name || `openclaw-${Date.now().toString(36)}`
    const env = Object.entries(envVars).filter(([, v]) => v).map(([k, v]) => `${k}=${v}`)
    const portBindings = {}
    const exposedPorts = {}
    if (panelPort) {
      portBindings['1420/tcp'] = [{ HostPort: String(panelPort) }]
      exposedPorts['1420/tcp'] = {}
    }
    if (gatewayPort) {
      portBindings['18789/tcp'] = [{ HostPort: String(gatewayPort) }]
      exposedPorts['18789/tcp'] = {}
    }
    const config = {
      Image: imgFull,
      Env: env,
      ExposedPorts: exposedPorts,
      HostConfig: {
        PortBindings: portBindings,
        RestartPolicy: { Name: 'unless-stopped' },
        Binds: volume ? [`openclaw-data-${containerName}:/root/.openclaw`] : [],
      },
    }
    const query = `?name=${encodeURIComponent(containerName)}`
    const resp = await dockerRequest('POST', `/containers/create${query}`, config, node.endpoint)
    if (resp.status === 404) {
      // Image not found, need to pull first
      throw new Error(`镜像 ${imgFull} 不存在，请先拉取`)
    }
    if (resp.status !== 201) throw new Error(resp.data?.message || '创建容器失败')
    // Auto-start
    const startResp = await dockerRequest('POST', `/containers/${resp.data.Id}/start`, null, node.endpoint)
    if (startResp.status !== 204 && startResp.status !== 304) {
      throw new Error('容器已创建但启动失败')
    }
    const containerId = resp.data.Id?.slice(0, 12)

    // 自动注册为可管理实例
    if (panelPort) {
      const endpoint = `http://127.0.0.1:${panelPort}`
      const instData = readInstances()
      if (!instData.instances.find(i => i.endpoint === endpoint)) {
        instData.instances.push({
          id: `docker-${containerId}`,
          name: containerName,
          type: 'docker',
          endpoint,
          gatewayPort: gatewayPort || 18789,
          containerId,
          nodeId: node.id,
          addedAt: Math.floor(Date.now() / 1000),
          note: `Image: ${imgFull}`,
        })
        saveInstances(instData)
      }
    }

    return { id: containerId, name: containerName, started: true, instanceId: `docker-${containerId}` }
  },

  async docker_start_container({ nodeId, containerId } = {}) {
    const nodes = readDockerNodes()
    const node = nodeId ? nodes.find(n => n.id === nodeId) : nodes[0]
    if (!node) throw new Error('节点不存在')
    const resp = await dockerRequest('POST', `/containers/${containerId}/start`, null, node.endpoint)
    if (resp.status !== 204 && resp.status !== 304) throw new Error(resp.data?.message || '启动失败')
    return true
  },

  async docker_stop_container({ nodeId, containerId } = {}) {
    const nodes = readDockerNodes()
    const node = nodeId ? nodes.find(n => n.id === nodeId) : nodes[0]
    if (!node) throw new Error('节点不存在')
    const resp = await dockerRequest('POST', `/containers/${containerId}/stop`, null, node.endpoint)
    if (resp.status !== 204 && resp.status !== 304) throw new Error(resp.data?.message || '停止失败')
    return true
  },

  async docker_restart_container({ nodeId, containerId } = {}) {
    const nodes = readDockerNodes()
    const node = nodeId ? nodes.find(n => n.id === nodeId) : nodes[0]
    if (!node) throw new Error('节点不存在')
    const resp = await dockerRequest('POST', `/containers/${containerId}/restart`, null, node.endpoint)
    if (resp.status !== 204) throw new Error(resp.data?.message || '重启失败')
    return true
  },

  async docker_remove_container({ nodeId, containerId, force = false } = {}) {
    const nodes = readDockerNodes()
    const node = nodeId ? nodes.find(n => n.id === nodeId) : nodes[0]
    if (!node) throw new Error('节点不存在')
    const query = force ? '?force=true&v=true' : '?v=true'
    const resp = await dockerRequest('DELETE', `/containers/${containerId}${query}`, null, node.endpoint)
    if (resp.status !== 204) throw new Error(resp.data?.message || '删除失败')

    // 自动移除对应的实例注册
    const instData = readInstances()
    const instId = `docker-${containerId}`
    const before = instData.instances.length
    instData.instances = instData.instances.filter(i => i.id !== instId && i.containerId !== containerId)
    if (instData.instances.length < before) {
      if (instData.activeId === instId) instData.activeId = 'local'
      saveInstances(instData)
    }

    return true
  },

  async docker_gateway_chat({ nodeId, containerId, message, timeout = 120000 } = {}) {
    if (!containerId || !message) throw new Error('缺少 containerId 或 message')
    // 1. 查找容器的 Gateway 端口
    const nodes = readDockerNodes()
    const node = nodeId ? nodes.find(n => n.id === nodeId) : nodes[0]
    if (!node) throw new Error('节点不存在')
    const resp = await dockerRequest('GET', `/containers/${containerId}/json`, null, node.endpoint)
    if (resp.status >= 400) throw new Error('容器不存在或无法访问')
    const ports = resp.data?.NetworkSettings?.Ports || {}
    const gwBinding = ports['18789/tcp']
    if (!gwBinding || !gwBinding[0]?.HostPort) throw new Error('该容器没有暴露 Gateway 端口 (18789)')
    const gwPort = gwBinding[0].HostPort

    // 2. TCP 端口预检 — 快速判断 Gateway 是否在监听，失败则自动修复
    const containerName = resp.data?.Name?.replace(/^\//, '') || containerId.slice(0, 12)
    const tcpCheck = (port) => new Promise((resolve, reject) => {
      const sock = net.connect({ host: '127.0.0.1', port, timeout: 5000 })
      sock.on('connect', () => { sock.destroy(); resolve() })
      sock.on('timeout', () => { sock.destroy(); reject(new Error('timeout')) })
      sock.on('error', (e) => reject(e))
    })
    try {
      await tcpCheck(gwPort)
    } catch {
      // Gateway 未运行 → 自动修复：同步配置 + 重启 Gateway
      console.log(`[gateway-chat] ${containerName}: Gateway 未响应，自动修复中...`)
      try {
        await handlers.docker_init_worker({ nodeId, containerId, role: 'general' })
        // 等待 Gateway 启动
        await new Promise(r => setTimeout(r, 8000))
        await tcpCheck(gwPort)
        console.log(`[gateway-chat] ${containerName}: 自动修复成功`)
      } catch (e2) {
        throw new Error(`${containerName}: Gateway 自动修复失败 — ${e2.message}`)
      }
    }

    // 2b. 从容器配置中读取 Gateway auth token（Gateway 启动时自动生成）
    let gatewayToken = ''
    try {
      const tokenExec = await dockerRequest('POST', `/containers/${containerId}/exec`, {
        AttachStdout: true, AttachStderr: true,
        Cmd: ['sh', '-c', 'node -e "const c=JSON.parse(require(\'fs\').readFileSync(\'/root/.openclaw/openclaw.json\',\'utf8\'));process.stdout.write(c.gateway?.auth?.token||\'\')"']
      }, node.endpoint)
      const tokenExecId = tokenExec.data?.Id
      if (tokenExecId) {
        const tokenResp = await new Promise((ok, no) => {
          const opts = { path: `/exec/${tokenExecId}/start`, method: 'POST', headers: { 'Content-Type': 'application/json' } }
          if (node.endpoint && node.endpoint.startsWith('tcp://')) {
            const url = new URL(node.endpoint.replace('tcp://', 'http://'))
            opts.hostname = url.hostname
            opts.port = parseInt(url.port) || 2375
          } else {
            opts.socketPath = node.endpoint || DOCKER_SOCKET
          }
          const req = http.request(opts, res => {
            let d = ''
            res.on('data', c => d += c.toString().replace(/[\x00-\x08]/g, ''))
            res.on('end', () => ok(d.trim()))
          })
          req.on('error', () => ok(''))
          req.write(JSON.stringify({ Detach: false, Tty: false }))
          req.end()
        })
        gatewayToken = tokenResp.replace(/[^a-zA-Z0-9_\-\.]/g, '')
        if (gatewayToken) console.log(`[gateway-chat] 读取到 auth token: ${gatewayToken.slice(0, 8)}...`)
      }
    } catch (e) {
      console.warn(`[gateway-chat] 读取 auth token 失败: ${e.message}`)
    }

    // 3. 通过 WebSocket 连接 Gateway（Node 22 内置 WebSocket）
    return new Promise((resolve, reject) => {
      const wsUrl = `ws://127.0.0.1:${gwPort}/ws`
      let ws
      try { ws = new WebSocket(wsUrl) } catch (e) { return reject(new Error(`无法创建 WebSocket: ${e.message}`)) }
      let result = '', handshakeOk = false, sessionKey = 'agent:main:cluster-task', done = false
      const timer = setTimeout(() => { if (!done) { done = true; ws.close(); reject(new Error('Gateway 通信超时(120s)')) } }, timeout)
      // 如果 3s 内没收到 challenge，主动发 connect
      const challengeTimer = setTimeout(() => { if (!handshakeOk) doConnect('') }, 3000)

      function doConnect(nonce) {
        try {
          const frame = handlers.create_connect_frame({ nonce, gatewayToken })
          ws.send(JSON.stringify(frame))
        } catch {
          ws.send(JSON.stringify({ type: 'req', id: 'connect-1', method: 'connect', params: {} }))
        }
      }

      function sendChat() {
        const id = `chat-${Date.now().toString(36)}`
        ws.send(JSON.stringify({
          type: 'req', id, method: 'chat.send',
          params: { sessionKey, message, deliver: false, idempotencyKey: id }
        }))
      }

      ws.addEventListener('open', () => {
        console.log(`[gateway-chat] WebSocket 已连接 ${wsUrl}`)
      })

      ws.addEventListener('message', (evt) => {
        let msg
        try { msg = JSON.parse(typeof evt.data === 'string' ? evt.data : evt.data.toString()) } catch { return }

        // connect.challenge
        if (msg.type === 'event' && msg.event === 'connect.challenge') {
          clearTimeout(challengeTimer)
          doConnect(msg.payload?.nonce || '')
          return
        }
        // connect 响应
        if (msg.type === 'res' && msg.id?.startsWith('connect')) {
          clearTimeout(challengeTimer)
          if (msg.ok) {
            handshakeOk = true
            console.log(`[gateway-chat] 握手成功: ${containerName}`)
            const defaults = msg.payload?.snapshot?.sessionDefaults
            if (defaults?.mainSessionKey) sessionKey = defaults.mainSessionKey
            else sessionKey = `agent:${defaults?.defaultAgentId || 'main'}:cluster-task`
            sendChat()
          } else {
            done = true; clearTimeout(timer); ws.close()
            const errMsg = msg.error?.message || ''
            if (errMsg.includes('origin not allowed') || errMsg.includes('not paired'))
              reject(new Error(`Gateway 需要设备配对 — 请先在容器 ${containerName} 的面板中完成配对`))
            else
              reject(new Error(errMsg || 'Gateway 握手失败'))
          }
          return
        }
        // chat 事件流
        if (msg.type === 'event' && msg.event === 'chat') {
          const p = msg.payload
          if (p?.state === 'delta') {
            const content = p.message?.content
            if (typeof content === 'string' && content.length > result.length) result = content
          }
          if (p?.state === 'final') {
            const content = p.message?.content
            if (typeof content === 'string' && content) result = content
            done = true; clearTimeout(timer); ws.close()
            resolve({ ok: true, result })
          }
          return
        }
        // chat.send 响应
        if (msg.type === 'res' && !msg.id?.startsWith('connect')) {
          if (!msg.ok) {
            done = true; clearTimeout(timer); ws.close()
            const errMsg = msg.error?.message || '任务发送失败'
            if (errMsg.includes('no model') || errMsg.includes('model'))
              reject(new Error(`${containerName}: 未配置模型 — 请先在容器面板中配置 AI 模型`))
            else
              reject(new Error(errMsg))
          }
        }
      })

      ws.addEventListener('error', (e) => {
        if (!done) {
          done = true; clearTimeout(timer); clearTimeout(challengeTimer)
          reject(new Error(`WebSocket 连接失败 ${wsUrl}: ${e.message || '连接被拒绝'}`))
        }
      })
      ws.addEventListener('close', (e) => {
        clearTimeout(timer); clearTimeout(challengeTimer)
        if (!done) {
          done = true
          if (result) resolve({ ok: true, result })
          else if (e.code === 4001 || e.code === 4003) reject(new Error(`Gateway 认证失败 — 请检查容器 ${containerName} 的 Token 配置`))
          else resolve({ ok: true, result: result || '（无回复）' })
        }
      })
    })
  },

  async docker_init_worker({ nodeId, containerId, role = 'general' } = {}) {
    if (!containerId) throw new Error('缺少 containerId')
    const nodes = readDockerNodes()
    const node = nodeId ? nodes.find(n => n.id === nodeId) : nodes[0]
    if (!node) throw new Error('节点不存在')

    const results = { config: false, personality: false, files: [] }

    // helper: base64 encode string
    const b64 = (s) => Buffer.from(s, 'utf8').toString('base64')

    // helper: exec command in container
    const cExec = async (cmd) => {
      const createResp = await dockerRequest('POST', `/containers/${containerId}/exec`, {
        AttachStdout: true, AttachStderr: true, Cmd: ['sh', '-c', cmd]
      }, node.endpoint)
      if (createResp.status >= 400) throw new Error(`exec 失败: ${createResp.status}`)
      const execId = createResp.data?.Id
      if (!execId) return
      await dockerRequest('POST', `/exec/${execId}/start`, { Detach: true }, node.endpoint)
      // 给 exec 一点时间完成
      await new Promise(r => setTimeout(r, 300))
    }

    // 1. 同步 openclaw.json（模型 + API Key 配置）
    try {
      if (fs.existsSync(CONFIG_PATH)) {
        const localConfig = JSON.parse(fs.readFileSync(CONFIG_PATH, 'utf8'))
        // 只同步 OpenClaw 认识的字段，避免 Unrecognized key 导致 Gateway 崩溃
        const syncConfig = {}
        if (localConfig.meta) syncConfig.meta = localConfig.meta // 保持原始 meta，不加自定义字段
        if (localConfig.env) syncConfig.env = localConfig.env
        if (localConfig.models) syncConfig.models = localConfig.models
        if (localConfig.auth) syncConfig.auth = localConfig.auth
        // Gateway 配置：只设置 controlUi（允许连接），不复制 host/bind 等本机特定字段
        syncConfig.gateway = {
          port: 18789,
          mode: 'local',
          bind: 'lan',
          controlUi: { allowedOrigins: ['*'] },
        }

        const configB64 = b64(JSON.stringify(syncConfig, null, 2))
        await cExec(`mkdir -p /root/.openclaw && echo '${configB64}' | base64 -d > /root/.openclaw/openclaw.json`)
        results.config = true
        results.files.push('openclaw.json')
        console.log(`[init-worker] 配置已同步 → ${containerId.slice(0, 12)}`)
      }
    } catch (e) {
      console.warn(`[init-worker] 配置同步失败: ${e.message}`)
    }

    // 2. 角色性格注入（SOUL.md + IDENTITY.md + AGENTS.md）
    try {
      // 角色性格模板
      const ROLE_SOULS = {
        general: { identity: '# 龙虾步兵\n通用作战单位，隶属统帅龙虾军团', soul: '# 龙虾步兵 · 性格\n\n## 核心\n- 忠诚可靠，执行力强\n- 能处理各类任务：写作、编程、翻译、分析\n- 回复简洁专业\n- 主动报告任务进展\n\n## 边界\n- 尊重隐私，不泄露信息\n- 不确定时先询问统帅\n- 每次回复聚焦任务本身' },
        coder: { identity: '# 龙虾突击兵\n编程作战专家，隶属统帅龙虾军团', soul: '# 龙虾突击兵 · 性格\n\n## 核心\n- 精通多种编程语言和框架\n- 代码质量第一，回复包含可运行示例\n- 擅长调试、重构、Code Review\n- 主动提示潜在问题和最佳实践\n\n## 边界\n- 修改文件前先理解上下文\n- 不跳过测试\n- 不引入不必要的依赖' },
        translator: { identity: '# 龙虾翻译官\n多语言作战专家，隶属统帅龙虾军团', soul: '# 龙虾翻译官 · 性格\n\n## 核心\n- 精通中英日韩法德西等主流语言互译\n- 追求信达雅，翻译精准\n- 保留原文语境和风格\n- 对专业术语严格把关\n\n## 边界\n- 不确定的术语标注原文\n- 不过度意译\n- 保持文体一致性' },
        writer: { identity: '# 龙虾文书官\n写作任务专家，隶属统帅龙虾军团', soul: '# 龙虾文书官 · 性格\n\n## 核心\n- 文思敏捷，创意丰富\n- 能调整语气适应不同场景\n- 精通博客、技术文档、营销文案等\n- 善于讲故事，引人入胜\n\n## 边界\n- 不抄袭\n- 保持原创性\n- 注重可读性和准确性' },
        analyst: { identity: '# 龙虾参谋\n数据分析专家，隶属统帅龙虾军团', soul: '# 龙虾参谋 · 性格\n\n## 核心\n- 逻辑清晰，善用数据说话\n- 结论有理有据，给出可行建议\n- 善用图表和结构化格式呈现\n- 擅长统计分析、商业分析、竞品分析\n\n## 边界\n- 不编造数据\n- 区分相关性和因果性\n- 标注不确定性' },
        custom: { identity: '# 龙虾特种兵\n特殊任务执行者，隶属统帅龙虾军团', soul: '# 龙虾特种兵 · 性格\n\n## 核心\n- 灵活多变，适应力强\n- 按需配置技能\n- 不拘泥形式，主动寻找最优解\n\n## 边界\n- 行动前确认方向\n- 不超出授权范围' },
      }

      const roleSoul = ROLE_SOULS[role] || ROLE_SOULS.general

      // 每个兵种独立的 AGENTS.md（操作指令）
      const ROLE_AGENTS = {
        general: '# 操作指令\n\n你是龙虾军团的步兵，接受统帅通过 ClawPanel 下达的任务指令。\n\n## 规则\n- 收到任务后立即执行，完成后简要汇报结果\n- 如果任务不清楚，先确认再行动\n- 保持回复简洁，重点突出\n- 你有独立的记忆空间，会自动记录重要信息',
        coder: '# 操作指令\n\n你是龙虾军团的突击兵，专精编程作战。\n\n## 规则\n- 收到编程任务后，先分析需求再写代码\n- 代码必须可运行，包含必要的注释\n- 主动进行错误处理和边界检查\n- 如果涉及多个文件，说明修改顺序\n- 完成后给出测试建议\n\n## 专长\n- 全栈开发、API 设计、数据库优化\n- Bug 定位与修复、代码重构\n- 性能优化、安全审计',
        translator: '# 操作指令\n\n你是龙虾军团的翻译官，专精多语言互译。\n\n## 规则\n- 翻译要信达雅，保持原文风格\n- 专业术语保留原文标注\n- 长文分段翻译，保持上下文一致\n- 文学作品注重意境传达\n- 技术文档注重准确性\n\n## 专长\n- 中英日韩法德西等主流语言\n- 技术文档、文学作品、商务邮件',
        writer: '# 操作指令\n\n你是龙虾军团的文书官，专精写作任务。\n\n## 规则\n- 根据场景调整语气和风格\n- 注重结构清晰、逻辑连贯\n- 创意写作要有个性和亮点\n- 技术文档要准确严谨\n- 营销文案要抓住痛点\n\n## 专长\n- 博客文章、技术文档、营销文案\n- 故事创作、剧本、诗歌\n- SEO 优化、社交媒体内容',
        analyst: '# 操作指令\n\n你是龙虾军团的参谋，专精数据分析和战略规划。\n\n## 规则\n- 用数据说话，结论必须有依据\n- 区分事实、推断和假设\n- 善用表格和结构化格式呈现\n- 给出可执行的建议\n- 标注不确定性和风险\n\n## 专长\n- 市场分析、竞品研究、用户画像\n- 数据可视化、统计分析\n- 商业计划、策略建议',
        custom: '# 操作指令\n\n你是龙虾军团的特种兵，执行特殊任务。\n\n## 规则\n- 灵活应对各类非标准任务\n- 行动前确认方向\n- 不超出授权范围\n- 主动寻找最优解决方案',
      }

      const wsFiles = {
        'SOUL.md': roleSoul.soul,
        'IDENTITY.md': roleSoul.identity,
        'AGENTS.md': ROLE_AGENTS[role] || ROLE_AGENTS.general,
      }

      // 写入兵种专属文件（不复制本机的 TOOLS.md/USER.md/记忆，每个士兵独立发展）
      await cExec('mkdir -p /root/.openclaw/workspace')
      for (const [fname, content] of Object.entries(wsFiles)) {
        const encoded = b64(content)
        await cExec(`echo '${encoded}' | base64 -d > /root/.openclaw/workspace/${fname}`)
        results.files.push(`workspace/${fname}`)
      }
      results.personality = true
      console.log(`[init-worker] 兵种配置注入完成 (${role}) → ${containerId.slice(0, 12)}`)
    } catch (e) {
      console.warn(`[init-worker] 兵种配置注入失败: ${e.message}`)
    }

    // 5. 清理无效字段 + 重启 Gateway
    try {
      // entrypoint 会 sed 注入 gateway.host（OpenClaw 不认识），doctor --fix 清理
      await cExec('openclaw doctor --fix 2>/dev/null || true')
      // 停止旧 Gateway
      await cExec('pkill -f openclaw-gateway 2>/dev/null; pkill -f "openclaw gateway" 2>/dev/null; sleep 1')
      // 启动新 Gateway — 作为独立 Detach exec 的主进程（不能 nohup &，shell 退出会 SIGTERM 杀子进程）
      await cExec('mkdir -p /root/.openclaw/logs && exec openclaw gateway >> /root/.openclaw/logs/gateway.log 2>&1')
      console.log(`[init-worker] Gateway 已重启 → ${containerId.slice(0, 12)}`)
    } catch (e) {
      console.warn(`[init-worker] Gateway 重启失败: ${e.message}`)
    }

    return results
  },

  async docker_container_exec({ nodeId, containerId, cmd } = {}) {
    const nodes = readDockerNodes()
    const node = nodeId ? nodes.find(n => n.id === nodeId) : nodes[0]
    if (!node) throw new Error('节点不存在')
    if (!containerId) throw new Error('缺少 containerId')
    if (!cmd || !Array.isArray(cmd)) throw new Error('cmd 必须是字符串数组')
    // Step 1: 创建 exec 实例
    const createResp = await dockerRequest('POST', `/containers/${containerId}/exec`, {
      AttachStdout: true, AttachStderr: true, Cmd: cmd
    }, node.endpoint)
    if (createResp.status >= 400) throw new Error(`exec 创建失败: ${JSON.stringify(createResp.data)}`)
    const execId = createResp.data?.Id
    if (!execId) throw new Error('exec 创建失败: 无 ID')
    // Step 2: 启动 exec
    const startResp = await dockerRequest('POST', `/exec/${execId}/start`, { Detach: true }, node.endpoint)
    if (startResp.status >= 400) throw new Error(`exec 启动失败: ${JSON.stringify(startResp.data)}`)
    return { ok: true, execId }
  },

  async docker_container_logs({ nodeId, containerId, tail = 200 } = {}) {
    const nodes = readDockerNodes()
    const node = nodeId ? nodes.find(n => n.id === nodeId) : nodes[0]
    if (!node) throw new Error('节点不存在')
    const resp = await dockerRequest('GET', `/containers/${containerId}/logs?stdout=true&stderr=true&tail=${tail}`, null, node.endpoint)
    // Docker logs 返回带 stream header 的原始字节，简单清理
    let logs = typeof resp.data === 'string' ? resp.data : JSON.stringify(resp.data)
    // 去除 Docker stream 帧头（每 8 字节一个 header）
    logs = logs.replace(/[\x00-\x08]/g, '').replace(/\r/g, '')
    return logs
  },

  async docker_pull_image({ nodeId, image, tag = 'latest', requestId } = {}) {
    const nodes = readDockerNodes()
    const node = nodeId ? nodes.find(n => n.id === nodeId) : nodes[0]
    if (!node) throw new Error('节点不存在')
    const imgFull = `${image || OPENCLAW_IMAGE}:${tag}`
    const rid = requestId || `pull-${Date.now()}`
    _pullProgress.set(rid, { status: 'connecting', image: imgFull, layers: {}, message: '连接 Docker...', percent: 0 })
    const endpoint = node.endpoint
    const apiPath = `/images/create?fromImage=${encodeURIComponent(image || OPENCLAW_IMAGE)}&tag=${tag}`
    try {
      await new Promise((resolve, reject) => {
        const opts = { path: apiPath, method: 'POST', headers: { 'Content-Type': 'application/json' } }
        if (endpoint && endpoint.startsWith('tcp://')) {
          const url = new URL(endpoint.replace('tcp://', 'http://'))
          opts.hostname = url.hostname
          opts.port = parseInt(url.port) || 2375
        } else {
          opts.socketPath = endpoint || DOCKER_SOCKET
        }
        const req = http.request(opts, (res) => {
          if (res.statusCode !== 200) {
            let errData = ''
            res.on('data', chunk => errData += chunk)
            res.on('end', () => {
              const err = (() => { try { return JSON.parse(errData).message } catch { return `HTTP ${res.statusCode}` } })()
              _pullProgress.set(rid, { ..._pullProgress.get(rid), status: 'error', message: err })
              reject(new Error(err))
            })
            return
          }
          _pullProgress.set(rid, { ..._pullProgress.get(rid), status: 'pulling', message: '正在拉取镜像层...' })
          let lastError = null
          res.on('data', (chunk) => {
            const text = chunk.toString()
            for (const line of text.split('\n').filter(Boolean)) {
              try {
                const obj = JSON.parse(line)
                if (obj.error) { lastError = obj.error; continue }
                const p = _pullProgress.get(rid)
                if (obj.id && obj.progressDetail) {
                  p.layers[obj.id] = {
                    status: obj.status || '',
                    current: obj.progressDetail.current || 0,
                    total: obj.progressDetail.total || 0,
                  }
                }
                if (obj.status) p.message = obj.id ? `${obj.id}: ${obj.status}` : obj.status
                // 计算总体进度
                const layers = Object.values(p.layers)
                if (layers.length > 0) {
                  const totalBytes = layers.reduce((s, l) => s + (l.total || 0), 0)
                  const currentBytes = layers.reduce((s, l) => s + (l.current || 0), 0)
                  p.percent = totalBytes > 0 ? Math.round((currentBytes / totalBytes) * 100) : 0
                  p.layerCount = layers.length
                  p.completedLayers = layers.filter(l => l.status === 'Pull complete' || l.status === 'Already exists').length
                }
                _pullProgress.set(rid, p)
              } catch {}
            }
          })
          res.on('end', () => {
            if (lastError) {
              _pullProgress.set(rid, { ..._pullProgress.get(rid), status: 'error', message: lastError })
              reject(new Error(lastError))
            } else {
              _pullProgress.set(rid, { ..._pullProgress.get(rid), status: 'done', message: '拉取完成', percent: 100 })
              resolve()
            }
          })
        })
        req.on('error', (e) => {
          _pullProgress.set(rid, { ..._pullProgress.get(rid), status: 'error', message: e.message })
          reject(new Error('Docker 连接失败: ' + e.message))
        })
        req.setTimeout(600000, () => {
          _pullProgress.set(rid, { ..._pullProgress.get(rid), status: 'error', message: '超时' })
          req.destroy()
          reject(new Error('镜像拉取超时（10分钟）'))
        })
        req.end()
      })
    } finally {
      // 30秒后清理进度数据
      setTimeout(() => _pullProgress.delete(rid), 30000)
    }
    return { message: `镜像 ${imgFull} 拉取完成`, requestId: rid }
  },

  docker_pull_status({ requestId } = {}) {
    if (!requestId) return { status: 'unknown' }
    return _pullProgress.get(requestId) || { status: 'unknown' }
  },

  async docker_list_images({ nodeId } = {}) {
    const nodes = readDockerNodes()
    const node = nodeId ? nodes.find(n => n.id === nodeId) : nodes[0]
    if (!node) throw new Error('节点不存在')
    const resp = await dockerRequest('GET', '/images/json', null, node.endpoint)
    if (resp.status !== 200) throw new Error('获取镜像列表失败')
    return (resp.data || [])
      .filter(img => (img.RepoTags || []).some(t => t.includes('openclaw')))
      .map(img => ({
        id: img.Id?.replace('sha256:', '').slice(0, 12),
        tags: img.RepoTags || [],
        size: img.Size,
        created: img.Created,
      }))
  },

  // Docker 节点管理
  docker_list_nodes() {
    return readDockerNodes()
  },

  async docker_add_node({ name, endpoint }) {
    if (!name || !endpoint) throw new Error('节点名称和地址不能为空')
    // 验证连接
    try {
      await dockerRequest('GET', '/info', null, endpoint)
    } catch (e) {
      throw new Error(`无法连接到 ${endpoint}: ${e.message}`)
    }
    const nodes = readDockerNodes()
    const id = 'node-' + Date.now().toString(36)
    const type = endpoint.startsWith('tcp://') ? 'tcp' : 'socket'
    nodes.push({ id, name, type, endpoint })
    saveDockerNodes(nodes)
    return { id, name, type, endpoint }
  },

  docker_remove_node({ nodeId }) {
    if (nodeId === 'local') throw new Error('不能删除本机节点')
    const nodes = readDockerNodes().filter(n => n.id !== nodeId)
    saveDockerNodes(nodes)
    return true
  },

  // 集群概览（聚合所有节点）
  async docker_cluster_overview() {
    const nodes = readDockerNodes()
    const results = []
    for (const node of nodes) {
      try {
        const infoResp = await dockerRequest('GET', '/info', null, node.endpoint)
        const ctResp = await dockerRequest('GET', '/containers/json?all=true', null, node.endpoint)
        const containers = (ctResp.data || []).map(c => ({
          id: c.Id?.slice(0, 12),
          name: (c.Names?.[0] || '').replace(/^\//, ''),
          image: c.Image, state: c.State, status: c.Status,
          ports: (c.Ports || []).map(p => p.PublicPort ? `${p.PublicPort}→${p.PrivatePort}` : `${p.PrivatePort}`).join(', '),
        }))
        const d = infoResp.data || {}
        results.push({
          ...node, online: true,
          dockerVersion: d.ServerVersion, os: d.OperatingSystem,
          cpus: d.NCPU, memory: d.MemTotal,
          totalContainers: d.Containers, runningContainers: d.ContainersRunning,
          stoppedContainers: d.ContainersStopped,
          containers,
        })
      } catch (e) {
        results.push({ ...node, online: false, error: e.message, containers: [] })
      }
    }
    return results
  },

  // 部署模式检测
  get_deploy_mode() {
    const inDocker = fs.existsSync('/.dockerenv') || (process.env.CLAWPANEL_MODE === 'docker')
    const dockerAvailable = isDockerAvailable()
    return { inDocker, dockerAvailable, mode: inDocker ? 'docker' : 'local' }
  },

  // 安装检测
  check_installation() {
    const inDocker = fs.existsSync('/.dockerenv')
    return { installed: fs.existsSync(CONFIG_PATH), path: OPENCLAW_DIR, platform: isMac ? 'macos' : process.platform, inDocker }
  },

  check_node() {
    try {
      const ver = execSync('node --version 2>&1', { windowsHide: true }).toString().trim()
      return { installed: true, version: ver }
    } catch {
      return { installed: false, version: null }
    }
  },

  // 版本信息
  get_version_info() {
    let current = null
    if (isMac) {
      try {
        const target = fs.readlinkSync('/opt/homebrew/bin/openclaw')
        const pkgPath = path.resolve('/opt/homebrew/bin', target, '..', 'package.json')
        current = JSON.parse(fs.readFileSync(pkgPath, 'utf8')).version
      } catch {}
    }
    if (!current) {
      try { current = execSync('openclaw --version 2>&1', { windowsHide: true }).toString().trim().split(/\s+/).pop() } catch {}
    }
    return { current, latest: null, update_available: false, source: 'chinese' }
  },

  // 清理 base URL：去掉尾部斜杠和已知端点路径，防止路径重复
  _normalizeBaseUrl(raw) {
    let base = raw.replace(/\/+$/, '')
    base = base.replace(/\/(chat\/completions|completions|responses|messages|models)\/?$/, '')
    return base.replace(/\/+$/, '')
  },

  // 模型测试
  async test_model({ baseUrl, apiKey, modelId }) {
    const url = `${this._normalizeBaseUrl(baseUrl)}/chat/completions`
    const body = JSON.stringify({
      model: modelId,
      messages: [{ role: 'user', content: 'Hi' }],
      max_tokens: 16,
      stream: false
    })
    const controller = new AbortController()
    const timeout = setTimeout(() => controller.abort(), 30000)
    try {
      const headers = { 'Content-Type': 'application/json' }
      if (apiKey) headers['Authorization'] = `Bearer ${apiKey}`
      const resp = await fetch(url, { method: 'POST', headers, body, signal: controller.signal })
      clearTimeout(timeout)
      if (!resp.ok) {
        const text = await resp.text()
        let msg = `HTTP ${resp.status}`
        try { msg = JSON.parse(text).error?.message || msg } catch {}
        throw new Error(msg)
      }
      const data = await resp.json()
      const content = data.choices?.[0]?.message?.content
      const reasoning = data.choices?.[0]?.message?.reasoning_content
      return content || (reasoning ? `[reasoning] ${reasoning}` : '（无回复内容）')
    } catch (e) {
      clearTimeout(timeout)
      if (e.name === 'AbortError') throw new Error('请求超时 (30s)')
      throw e
    }
  },

  async list_remote_models({ baseUrl, apiKey }) {
    const url = `${this._normalizeBaseUrl(baseUrl)}/models`
    const headers = {}
    if (apiKey) headers['Authorization'] = `Bearer ${apiKey}`
    const controller = new AbortController()
    const timeout = setTimeout(() => controller.abort(), 15000)
    try {
      const resp = await fetch(url, { headers, signal: controller.signal })
      clearTimeout(timeout)
      if (!resp.ok) throw new Error(`HTTP ${resp.status}`)
      const data = await resp.json()
      const ids = (data.data || []).map(m => m.id).sort()
      if (!ids.length) throw new Error('该服务商返回了空的模型列表')
      return ids
    } catch (e) {
      clearTimeout(timeout)
      if (e.name === 'AbortError') throw new Error('请求超时 (15s)')
      throw e
    }
  },

  // 日志
  read_log_tail({ logName, lines = 100 }) {
    const logFiles = {
      'gateway': 'gateway.log',
      'gateway-err': 'gateway.err.log',
      'guardian': 'guardian.log',
      'guardian-backup': 'guardian-backup.log',
      'config-audit': 'config-audit.log',
    }
    const file = logFiles[logName] || logFiles['gateway']
    const logPath = path.join(LOGS_DIR, file)
    if (!fs.existsSync(logPath)) return ''
    try {
      return execSync(`tail -${lines} "${logPath}" 2>&1`, { windowsHide: true }).toString()
    } catch {
      const content = fs.readFileSync(logPath, 'utf8')
      return content.split('\n').slice(-lines).join('\n')
    }
  },

  search_log({ logName, query, maxResults = 50 }) {
    const logFiles = {
      'gateway': 'gateway.log',
      'gateway-err': 'gateway.err.log',
    }
    const file = logFiles[logName] || logFiles['gateway']
    const logPath = path.join(LOGS_DIR, file)
    if (!fs.existsSync(logPath)) return []
    // 纯 JS 实现，避免 shell 命令注入
    const content = fs.readFileSync(logPath, 'utf8')
    const queryLower = (query || '').toLowerCase()
    const matched = content.split('\n').filter(line => line.toLowerCase().includes(queryLower))
    return matched.slice(-maxResults)
  },

  // Agent 管理
  list_agents() {
    const result = [{ id: 'main', isDefault: true, identityName: null, model: null, workspace: null }]
    const agentsDir = path.join(OPENCLAW_DIR, 'agents')
    if (fs.existsSync(agentsDir)) {
      try {
        for (const entry of fs.readdirSync(agentsDir)) {
          if (entry === 'main') continue
          const p = path.join(agentsDir, entry)
          if (fs.statSync(p).isDirectory()) {
            result.push({ id: entry, isDefault: false, identityName: null, model: null, workspace: null })
          }
        }
      } catch {}
    }
    return result
  },

  // 记忆文件
  list_memory_files({ category, agent_id }) {
    const suffix = agent_id && agent_id !== 'main' ? `/agents/${agent_id}` : ''
    const dir = path.join(OPENCLAW_DIR, 'workspace' + suffix, category || 'memory')
    if (!fs.existsSync(dir)) return []
    return fs.readdirSync(dir).filter(f => f.endsWith('.md'))
  },

  read_memory_file({ path: filePath, agent_id }) {
    if (isUnsafePath(filePath)) throw new Error('非法路径')
    const suffix = agent_id && agent_id !== 'main' ? `/agents/${agent_id}` : ''
    const full = path.join(OPENCLAW_DIR, 'workspace' + suffix, filePath)
    if (!fs.existsSync(full)) return ''
    return fs.readFileSync(full, 'utf8')
  },

  write_memory_file({ path: filePath, content, category, agent_id }) {
    if (isUnsafePath(filePath)) throw new Error('非法路径')
    const suffix = agent_id && agent_id !== 'main' ? `/agents/${agent_id}` : ''
    const full = path.join(OPENCLAW_DIR, 'workspace' + suffix, filePath)
    const dir = path.dirname(full)
    if (!fs.existsSync(dir)) fs.mkdirSync(dir, { recursive: true })
    fs.writeFileSync(full, content)
    return true
  },

  delete_memory_file({ path: filePath, agent_id }) {
    if (isUnsafePath(filePath)) throw new Error('非法路径')
    const suffix = agent_id && agent_id !== 'main' ? `/agents/${agent_id}` : ''
    const full = path.join(OPENCLAW_DIR, 'workspace' + suffix, filePath)
    if (fs.existsSync(full)) fs.unlinkSync(full)
    return true
  },

  export_memory_zip({ category, agent_id }) {
    throw new Error('ZIP 导出仅在 Tauri 桌面应用中可用')
  },

  // 备份管理
  list_backups() {
    if (!fs.existsSync(BACKUPS_DIR)) return []
    return fs.readdirSync(BACKUPS_DIR)
      .filter(f => f.endsWith('.json'))
      .map(name => {
        const stat = fs.statSync(path.join(BACKUPS_DIR, name))
        return { name, size: stat.size, created_at: Math.floor((stat.birthtimeMs || stat.mtimeMs) / 1000) }
      })
      .sort((a, b) => b.created_at - a.created_at)
  },

  create_backup() {
    if (!fs.existsSync(BACKUPS_DIR)) fs.mkdirSync(BACKUPS_DIR, { recursive: true })
    const now = new Date()
    const pad = n => String(n).padStart(2, '0')
    const name = `openclaw-${now.getFullYear()}${pad(now.getMonth() + 1)}${pad(now.getDate())}-${pad(now.getHours())}${pad(now.getMinutes())}${pad(now.getSeconds())}.json`
    fs.copyFileSync(CONFIG_PATH, path.join(BACKUPS_DIR, name))
    return { name, size: fs.statSync(path.join(BACKUPS_DIR, name)).size }
  },

  restore_backup({ name }) {
    if (name.includes('..') || name.includes('/') || name.includes('\\')) throw new Error('非法文件名')
    const src = path.join(BACKUPS_DIR, name)
    if (!fs.existsSync(src)) throw new Error('备份不存在')
    if (fs.existsSync(CONFIG_PATH)) handlers.create_backup()
    fs.copyFileSync(src, CONFIG_PATH)
    return true
  },

  delete_backup({ name }) {
    if (name.includes('..') || name.includes('/') || name.includes('\\')) throw new Error('非法文件名')
    const p = path.join(BACKUPS_DIR, name)
    if (fs.existsSync(p)) fs.unlinkSync(p)
    return true
  },

  // Vision 补丁
  patch_model_vision() {
    if (!fs.existsSync(CONFIG_PATH)) return false
    const config = JSON.parse(fs.readFileSync(CONFIG_PATH, 'utf8'))
    let changed = false
    const providers = config?.models?.providers
    if (providers) {
      for (const p of Object.values(providers)) {
        if (!Array.isArray(p.models)) continue
        for (const m of p.models) {
          if (typeof m === 'object' && !m.input) {
            m.input = ['text', 'image']
            changed = true
          }
        }
      }
    }
    if (changed) {
      fs.copyFileSync(CONFIG_PATH, CONFIG_PATH + '.bak')
      fs.writeFileSync(CONFIG_PATH, JSON.stringify(config, null, 2))
    }
    return changed
  },

  // Gateway 安装/卸载
  install_gateway() {
    try { execSync('openclaw --version 2>&1', { windowsHide: true }) } catch { throw new Error('openclaw CLI 未安装') }
    return execSync('openclaw gateway install 2>&1', { windowsHide: true }).toString() || 'Gateway 服务已安装'
  },

  async list_openclaw_versions({ source = 'chinese' } = {}) {
    const pkg = source === 'official' ? 'openclaw' : '@qingchencloud/openclaw-zh'
    const encodedPkg = pkg.replace('/', '%2F')
    const registry = 'https://registry.npmmirror.com'
    try {
      const resp = await fetch(`${registry}/${encodedPkg}`, { headers: { 'Accept': 'application/json' }, signal: AbortSignal.timeout(10000) })
      const data = await resp.json()
      const versions = Object.keys(data.versions || {})
      versions.sort((a, b) => {
        const pa = a.split(/[^0-9]/).filter(Boolean).map(Number)
        const pb = b.split(/[^0-9]/).filter(Boolean).map(Number)
        for (let i = 0; i < Math.max(pa.length, pb.length); i++) {
          if ((pb[i] || 0) !== (pa[i] || 0)) return (pb[i] || 0) - (pa[i] || 0)
        }
        return 0
      })
      return versions
    } catch (e) {
      throw new Error('查询版本失败: ' + e.message)
    }
  },

  upgrade_openclaw({ source = 'chinese', version } = {}) {
    const OPENCLAW_DIR = path.join(homedir(), '.openclaw')
    const pkg = source === 'official' ? 'openclaw' : '@qingchencloud/openclaw-zh'
    const ver = version || 'latest'
    const npmBin = isWindows ? 'npm.cmd' : 'npm'
    try {
      const out = execSync(`${npmBin} install ${pkg}@${ver} --prefix "${OPENCLAW_DIR}" 2>&1`, { timeout: 120000, windowsHide: true }).toString()
      const action = ver === 'latest' ? '升级' : '安装'
      return `${action}完成 (${pkg}@${ver})\n${out.slice(-200)}`
    } catch (e) {
      throw new Error('安装失败: ' + (e.stderr?.toString() || e.message).slice(-300))
    }
  },

  uninstall_openclaw({ cleanConfig = false } = {}) {
    const npmBin = isWindows ? 'npm.cmd' : 'npm'
    try { execSync(`${npmBin} uninstall -g openclaw 2>&1`, { timeout: 60000, windowsHide: true }) } catch {}
    try { execSync(`${npmBin} uninstall -g @qingchencloud/openclaw-zh 2>&1`, { timeout: 60000, windowsHide: true }) } catch {}
    if (cleanConfig && fs.existsSync(OPENCLAW_DIR)) {
      try { fs.rmSync(OPENCLAW_DIR, { recursive: true, force: true }) } catch {}
    }
    return cleanConfig ? 'OpenClaw 已完全卸载（包括配置文件）' : 'OpenClaw 已卸载（配置文件保留）'
  },

  uninstall_gateway() {
    if (isMac) {
      const uid = getUid()
      try { execSync(`launchctl bootout gui/${uid}/ai.openclaw.gateway 2>&1`) } catch {}
      const plist = path.join(homedir(), 'Library/LaunchAgents/ai.openclaw.gateway.plist')
      if (fs.existsSync(plist)) fs.unlinkSync(plist)
    }
    return 'Gateway 服务已卸载'
  },

  // 自动初始化配置文件（CLI 已装但 openclaw.json 不存在时）
  init_openclaw_config() {
    if (fs.existsSync(CONFIG_PATH)) return { created: false, message: '配置文件已存在' }
    if (!fs.existsSync(OPENCLAW_DIR)) fs.mkdirSync(OPENCLAW_DIR, { recursive: true })
    const defaultConfig = {
      "$schema": "https://openclaw.ai/schema/config.json",
      meta: { lastTouchedVersion: "2026.1.1" },
      models: { providers: {} },
      gateway: {
        mode: "local",
        port: 18789,
        auth: { mode: "none" },
        controlUi: { allowedOrigins: ["*"], allowInsecureAuth: true }
      },
      tools: { profile: "full", sessions: { visibility: "all" } }
    }
    fs.writeFileSync(CONFIG_PATH, JSON.stringify(defaultConfig, null, 2))
    return { created: true, message: '配置文件已创建' }
  },

  get_deploy_config() {
    try {
      const config = JSON.parse(fs.readFileSync(CONFIG_PATH, 'utf8'))
      const gw = config.gateway || {}
      return { gatewayUrl: `http://127.0.0.1:${gw.port || 18789}`, authToken: gw.auth?.token || '', version: null }
    } catch {
      return { gatewayUrl: 'http://127.0.0.1:18789', authToken: '', version: null }
    }
  },

  get_npm_registry() {
    const regFile = path.join(OPENCLAW_DIR, 'npm-registry.txt')
    if (fs.existsSync(regFile)) return fs.readFileSync(regFile, 'utf8').trim() || 'https://registry.npmmirror.com'
    return 'https://registry.npmmirror.com'
  },

  set_npm_registry({ registry }) {
    fs.writeFileSync(path.join(OPENCLAW_DIR, 'npm-registry.txt'), registry.trim())
    return true
  },

  // Skills 管理（模拟 openclaw skills CLI JSON 输出）
  skills_list() {
    // 尝试真实 CLI
    try {
      const out = execSync('npx -y openclaw skills list --json --verbose', { encoding: 'utf8', timeout: 30000 })
      return JSON.parse(out)
    } catch {
      // CLI 不可用时返回 mock 数据
      return {
        skills: [
          { name: 'github', description: 'GitHub operations via gh CLI: issues, PRs, CI runs, code review.', source: 'openclaw-bundled', bundled: true, emoji: '🐙', eligible: true, disabled: false, blockedByAllowlist: false, requirements: { bins: ['gh'], anyBins: [], env: [], config: [], os: [] }, missing: { bins: [], anyBins: [], env: [], config: [], os: [] }, install: [{ id: 'brew', kind: 'brew', label: 'Install GitHub CLI (brew)', bins: ['gh'] }] },
          { name: 'weather', description: 'Get current weather and forecasts via wttr.in. No API key needed.', source: 'openclaw-bundled', bundled: true, emoji: '🌤️', eligible: true, disabled: false, blockedByAllowlist: false, requirements: { bins: ['curl'], anyBins: [], env: [], config: [], os: [] }, missing: { bins: [], anyBins: [], env: [], config: [], os: [] }, install: [] },
          { name: 'summarize', description: 'Summarize web pages, PDFs, images, audio and more.', source: 'openclaw-bundled', bundled: true, emoji: '📝', eligible: false, disabled: false, blockedByAllowlist: false, requirements: { bins: [], anyBins: [], env: [], config: [], os: [] }, missing: { bins: [], anyBins: [], env: [], config: [], os: [] }, install: [] },
          { name: 'slack', description: 'Send and read Slack messages via CLI.', source: 'openclaw-bundled', bundled: true, emoji: '💬', eligible: false, disabled: false, blockedByAllowlist: false, requirements: { bins: ['slack-cli'], anyBins: [], env: [], config: [], os: [] }, missing: { bins: ['slack-cli'], anyBins: [], env: [], config: [], os: [] }, install: [{ id: 'brew', kind: 'brew', label: 'Install Slack CLI (brew)', bins: ['slack-cli'] }] },
          { name: 'notion', description: 'Create and search Notion pages using the API.', source: 'openclaw-bundled', bundled: true, emoji: '📓', eligible: false, disabled: true, blockedByAllowlist: false, requirements: { bins: [], anyBins: [], env: ['NOTION_API_KEY'], config: [], os: [] }, missing: { bins: [], anyBins: [], env: ['NOTION_API_KEY'], config: [], os: [] }, install: [] },
        ],
        source: 'mock',
        cliAvailable: false,
      }
    }
  },
  skills_info({ name }) {
    try {
      const out = execSync(`npx -y openclaw skills info ${JSON.stringify(name)} --json`, { encoding: 'utf8', timeout: 30000 })
      return JSON.parse(out)
    } catch (e) {
      throw new Error('查看详情失败: ' + (e.message || e))
    }
  },
  skills_check() {
    try {
      const out = execSync('npx -y openclaw skills check --json', { encoding: 'utf8', timeout: 30000 })
      return JSON.parse(out)
    } catch {
      return { summary: { total: 0, eligible: 0, disabled: 0, blocked: 0, missingRequirements: 0 }, eligible: [], disabled: [], blocked: [], missingRequirements: [] }
    }
  },
  skills_install_dep({ kind, spec }) {
    const cmds = {
      brew: `brew install ${spec?.formula || ''}`,
      node: `npm install -g ${spec?.package || ''}`,
      go: `go install ${spec?.module || ''}`,
      uv: `uv tool install ${spec?.package || ''}`,
    }
    const cmd = cmds[kind]
    if (!cmd) throw new Error(`不支持的安装类型: ${kind}`)
    try {
      const out = execSync(cmd, { encoding: 'utf8', timeout: 120000 })
      return { success: true, output: out.trim() }
    } catch (e) {
      throw new Error(`安装失败: ${e.message || e}`)
    }
  },
  skills_clawhub_search({ query }) {
    const q = String(query || '').trim()
    if (!q) return []
    try {
      const out = execSync(`npx -y clawhub search ${JSON.stringify(q)}`, { encoding: 'utf8', timeout: 30000 })
      return out.split('\n')
        .map(line => line.trim())
        .filter(line => line && !line.startsWith('-') && !line.startsWith('Search'))
        .map(line => {
          const parts = line.split(/\s{2,}/).filter(Boolean)
          return { slug: parts[0] || '', description: parts.slice(1).join(' ').trim(), source: 'clawhub' }
        })
        .filter(item => item.slug)
    } catch (e) {
      throw new Error('搜索失败: ' + (e.message || e))
    }
  },
  skills_clawhub_install({ slug }) {
    const skillsDir = path.join(OPENCLAW_DIR, 'skills')
    if (!fs.existsSync(skillsDir)) fs.mkdirSync(skillsDir, { recursive: true })
    try {
      const out = execSync(`npx -y clawhub install ${JSON.stringify(slug)}`, { cwd: homedir(), encoding: 'utf8', timeout: 120000 })
      return { success: true, slug, output: out.trim() }
    } catch (e) {
      throw new Error('安装失败: ' + (e.message || e))
    }
  },

  // 扩展工具
  get_cftunnel_status() {
    // 优先使用 cftunnel CLI（跨平台）
    const bin = isWindows ? 'cftunnel.exe' : 'cftunnel'
    try {
      execSync(`${bin} --version`, { timeout: 3000, windowsHide: true, stdio: 'pipe' })
    } catch {
      return { installed: false }
    }
    // 已安装，获取状态
    let running = false, pid = null, tunnel_name = ''
    try {
      const statusOut = execSync(`${bin} status 2>&1`, { timeout: 5000, windowsHide: true }).toString()
      if (statusOut.includes('运行中')) running = true
      const pidMatch = statusOut.match(/PID[：:]\s*(\d+)/)
      if (pidMatch) pid = parseInt(pidMatch[1])
      const nameMatch = statusOut.match(/隧道[：:]\s*([^\s(]+)/)
      if (nameMatch) tunnel_name = nameMatch[1]
    } catch {}
    // 补充进程检测
    if (!running) {
      try {
        if (isWindows) {
          const out = execSync('tasklist /FI "IMAGENAME eq cftunnel.exe" /FO CSV /NH 2>nul', { timeout: 3000, windowsHide: true }).toString()
          if (out.includes('cftunnel.exe')) running = true
        } else {
          const out = execSync('pgrep -f cftunnel 2>/dev/null', { timeout: 3000 }).toString().trim()
          if (out) { running = true; pid = pid || parseInt(out.split('\n')[0]) || null }
        }
      } catch {}
    }
    // 获取路由列表
    let routes = []
    try {
      const listOut = execSync(`${bin} list 2>&1`, { timeout: 5000, windowsHide: true }).toString()
      const lines = listOut.split('\n').filter(l => l.trim() && !l.includes('---') && !l.toLowerCase().includes('name'))
      routes = lines.map(l => {
        const parts = l.split(/\s{2,}|\t/).map(s => s.trim()).filter(Boolean)
        return parts.length >= 3 ? { name: parts[0], domain: parts[1], service: parts[2] } : null
      }).filter(Boolean)
    } catch {}
    return { installed: true, running, pid, tunnel_name, routes }
  },

  get_clawapp_status() {
    const port = 3210
    let running = false, pid = null
    // 检测端口是否在监听
    try {
      if (isWindows) {
        const out = execSync(`netstat -ano | findstr :${port} | findstr LISTENING`, { timeout: 3000, windowsHide: true }).toString().trim()
        if (out) {
          running = true
          const parts = out.split(/\s+/)
          pid = parseInt(parts[parts.length - 1]) || null
        }
      } else {
        const out = execSync(`lsof -i :${port} -t 2>/dev/null`, { timeout: 3000 }).toString().trim()
        if (out) { running = true; pid = parseInt(out.split('\n')[0]) || null }
      }
    } catch {}
    // 检测是否安装（多个可能路径）
    const candidates = isWindows
      ? [path.join(homedir(), 'Desktop\\clawapp'), path.join(homedir(), 'clawapp')]
      : [path.join(homedir(), 'Desktop/clawapp'), path.join(homedir(), 'clawapp'), '/opt/clawapp']
    const installed = candidates.some(p => fs.existsSync(p))
    return { installed, running, pid, port, url: `http://localhost:${port}` }
  },

  // 设备配对 + Gateway 握手
  auto_pair_device() {
    const originsChanged = patchGatewayOrigins()
    const { deviceId, publicKey } = getOrCreateDeviceKey()
    if (!fs.existsSync(DEVICES_DIR)) fs.mkdirSync(DEVICES_DIR, { recursive: true })
    let paired = {}
    if (fs.existsSync(PAIRED_PATH)) paired = JSON.parse(fs.readFileSync(PAIRED_PATH, 'utf8'))
    const platform = process.platform === 'darwin' ? 'macos' : process.platform
    if (paired[deviceId]) {
      if (paired[deviceId].platform !== platform) {
        paired[deviceId].platform = platform
        paired[deviceId].deviceFamily = 'desktop'
        fs.writeFileSync(PAIRED_PATH, JSON.stringify(paired, null, 2))
        return { message: '设备已配对（已修正平台字段）', changed: true }
      }
      return { message: '设备已配对', changed: originsChanged }
    }
    const nowMs = Date.now()
    paired[deviceId] = {
      deviceId, publicKey, platform, deviceFamily: 'desktop',
      clientId: 'openclaw-control-ui', clientMode: 'ui',
      role: 'operator', roles: ['operator'],
      scopes: SCOPES, approvedScopes: SCOPES, tokens: {},
      createdAtMs: nowMs, approvedAtMs: nowMs,
    }
    fs.writeFileSync(PAIRED_PATH, JSON.stringify(paired, null, 2))
    return { message: '设备配对成功', changed: true }
  },

  check_pairing_status() {
    if (!fs.existsSync(DEVICE_KEY_FILE)) return { paired: false }
    const keyData = JSON.parse(fs.readFileSync(DEVICE_KEY_FILE, 'utf8'))
    if (!fs.existsSync(PAIRED_PATH)) return { paired: false }
    const paired = JSON.parse(fs.readFileSync(PAIRED_PATH, 'utf8'))
    return { paired: !!paired[keyData.deviceId] }
  },

  create_connect_frame({ nonce, gatewayToken }) {
    const { deviceId, publicKey, privateKey } = getOrCreateDeviceKey()
    const signedAt = Date.now()
    const platform = process.platform === 'darwin' ? 'macos' : process.platform
    const scopesStr = SCOPES.join(',')
    const payloadStr = `v3|${deviceId}|openclaw-control-ui|ui|operator|${scopesStr}|${signedAt}|${gatewayToken || ''}|${nonce || ''}|${platform}|desktop`
    const signature = crypto.sign(null, Buffer.from(payloadStr), privateKey)
    const sigB64 = Buffer.from(signature).toString('base64url')
    const idHex = (signedAt & 0xFFFFFFFF).toString(16).padStart(8, '0')
    const rndHex = Math.floor(Math.random() * 0xFFFF).toString(16).padStart(4, '0')
    return {
      type: 'req',
      id: `connect-${idHex}-${rndHex}`,
      method: 'connect',
      params: {
        minProtocol: 3, maxProtocol: 3,
        client: { id: 'openclaw-control-ui', version: '1.0.0', platform, deviceFamily: 'desktop', mode: 'ui' },
        role: 'operator', scopes: SCOPES, caps: [],
        auth: { token: gatewayToken || '' },
        device: { id: deviceId, publicKey, signedAt, nonce: nonce || '', signature: sigB64 },
        locale: 'zh-CN', userAgent: 'ClawPanel/1.0.0 (web)',
      },
    }
  },
  // 数据目录 & 图片存储
  assistant_ensure_data_dir() {
    const dataDir = path.join(OPENCLAW_DIR, 'clawpanel')
    for (const sub of ['images', 'sessions', 'cache']) {
      const dir = path.join(dataDir, sub)
      if (!fs.existsSync(dir)) fs.mkdirSync(dir, { recursive: true })
    }
    return dataDir
  },

  assistant_save_image({ id, data }) {
    const dir = path.join(OPENCLAW_DIR, 'clawpanel', 'images')
    if (!fs.existsSync(dir)) fs.mkdirSync(dir, { recursive: true })
    const pureB64 = data.includes(',') ? data.split(',')[1] : data
    const ext = data.startsWith('data:image/png') ? 'png'
      : data.startsWith('data:image/gif') ? 'gif'
      : data.startsWith('data:image/webp') ? 'webp' : 'jpg'
    const filepath = path.join(dir, `${id}.${ext}`)
    fs.writeFileSync(filepath, Buffer.from(pureB64, 'base64'))
    return filepath
  },

  assistant_load_image({ id }) {
    const dir = path.join(OPENCLAW_DIR, 'clawpanel', 'images')
    for (const ext of ['jpg', 'png', 'gif', 'webp', 'jpeg']) {
      const filepath = path.join(dir, `${id}.${ext}`)
      if (fs.existsSync(filepath)) {
        const bytes = fs.readFileSync(filepath)
        const mime = ext === 'png' ? 'image/png' : ext === 'gif' ? 'image/gif' : ext === 'webp' ? 'image/webp' : 'image/jpeg'
        return `data:${mime};base64,${bytes.toString('base64')}`
      }
    }
    throw new Error(`图片 ${id} 不存在`)
  },

  assistant_delete_image({ id }) {
    const dir = path.join(OPENCLAW_DIR, 'clawpanel', 'images')
    for (const ext of ['jpg', 'png', 'gif', 'webp', 'jpeg']) {
      const filepath = path.join(dir, `${id}.${ext}`)
      if (fs.existsSync(filepath)) fs.unlinkSync(filepath)
    }
    return null
  },

  // === AI 助手工具（Web 模式真实执行） ===

  assistant_exec({ command, cwd }) {
    if (!command) throw new Error('命令不能为空')
    // 安全限制：禁止危险命令
    const dangerous = ['rm -rf /', 'mkfs', 'dd if=', ':(){', 'format ', 'del /f /s /q C:']
    if (dangerous.some(d => command.includes(d))) throw new Error('危险命令已被拦截')
    const opts = { timeout: 30000, maxBuffer: 1024 * 1024, windowsHide: true }
    if (cwd) opts.cwd = cwd
    try {
      const output = execSync(command, opts).toString()
      return output || '（命令已执行，无输出）'
    } catch (e) {
      const stderr = e.stderr?.toString() || ''
      const stdout = e.stdout?.toString() || ''
      return `退出码: ${e.status || 1}\n${stdout}${stderr ? '\n[stderr] ' + stderr : ''}`
    }
  },

  assistant_read_file({ path: filePath }) {
    if (!filePath) throw new Error('路径不能为空')
    const expanded = filePath.startsWith('~/') ? path.join(homedir(), filePath.slice(2)) : filePath
    if (!fs.existsSync(expanded)) throw new Error(`文件不存在: ${filePath}`)
    const stat = fs.statSync(expanded)
    if (stat.size > 1024 * 1024) throw new Error(`文件过大 (${(stat.size / 1024 / 1024).toFixed(1)}MB)，最大 1MB`)
    return fs.readFileSync(expanded, 'utf8')
  },

  assistant_write_file({ path: filePath, content }) {
    if (!filePath) throw new Error('路径不能为空')
    const expanded = filePath.startsWith('~/') ? path.join(homedir(), filePath.slice(2)) : filePath
    const dir = path.dirname(expanded)
    if (!fs.existsSync(dir)) fs.mkdirSync(dir, { recursive: true })
    fs.writeFileSync(expanded, content || '')
    return `已写入 ${filePath} (${Buffer.byteLength(content || '', 'utf8')} 字节)`
  },

  assistant_list_dir({ path: dirPath }) {
    if (!dirPath) throw new Error('路径不能为空')
    const expanded = dirPath.startsWith('~/') ? path.join(homedir(), dirPath.slice(2)) : dirPath
    if (!fs.existsSync(expanded)) throw new Error(`目录不存在: ${dirPath}`)
    const entries = fs.readdirSync(expanded, { withFileTypes: true })
    return entries.map(e => {
      if (e.isDirectory()) return `[DIR]  ${e.name}/`
      try {
        const stat = fs.statSync(path.join(expanded, e.name))
        const size = stat.size < 1024 ? `${stat.size} B` : stat.size < 1048576 ? `${(stat.size / 1024).toFixed(1)} KB` : `${(stat.size / 1048576).toFixed(1)} MB`
        return `[FILE] ${e.name} (${size})`
      } catch {
        return `[FILE] ${e.name}`
      }
    }).join('\n') || '（空目录）'
  },

  assistant_system_info() {
    const platform = process.platform === 'win32' ? 'windows' : process.platform === 'darwin' ? 'macos' : 'linux'
    const arch = process.arch
    const home = homedir()
    const hostname = os.hostname()
    const shell = process.platform === 'win32' ? 'powershell / cmd' : (process.env.SHELL || '/bin/bash')
    const sep = path.sep
    const totalMem = (os.totalmem() / 1024 / 1024 / 1024).toFixed(1)
    const freeMem = (os.freemem() / 1024 / 1024 / 1024).toFixed(1)
    const cpus = os.cpus()
    const cpuModel = cpus[0]?.model || '未知'
    const lines = [
      `OS: ${platform}`,
      `Arch: ${arch}`,
      `Home: ${home}`,
      `Hostname: ${hostname}`,
      `Shell: ${shell}`,
      `Path separator: ${sep}`,
      `CPU: ${cpuModel} (${cpus.length} 核)`,
      `Memory: ${freeMem}GB free / ${totalMem}GB total`,
    ]
    // Node.js 版本
    try {
      const nodeVer = execSync('node --version 2>&1', { windowsHide: true }).toString().trim()
      lines.push(`Node.js: ${nodeVer}`)
    } catch {}
    return lines.join('\n')
  },

  assistant_list_processes({ filter }) {
    try {
      if (isWindows) {
        const cmd = filter
          ? `tasklist /FI "IMAGENAME eq ${filter}*" /FO CSV /NH 2>nul`
          : 'tasklist /FO CSV /NH 2>nul | more +1'
        const output = execSync(cmd, { timeout: 5000, windowsHide: true }).toString().trim()
        return output || '（无匹配进程）'
      } else {
        const cmd = filter
          ? `ps aux | head -1 && ps aux | grep -i "${filter}" | grep -v grep`
          : 'ps aux | head -20'
        const output = execSync(cmd, { timeout: 5000 }).toString().trim()
        return output || '（无匹配进程）'
      }
    } catch (e) {
      return e.stdout?.toString() || '（无匹配进程）'
    }
  },

  assistant_check_port({ port }) {
    if (!port) throw new Error('端口号不能为空')
    try {
      if (isWindows) {
        const output = execSync(`netstat -ano | findstr :${port}`, { timeout: 5000, windowsHide: true }).toString().trim()
        return output ? `端口 ${port} 已被占用（正在监听）\n${output}` : `端口 ${port} 未被占用（空闲）`
      } else {
        const output = execSync(`ss -tlnp 'sport = :${port}' 2>/dev/null || lsof -i :${port} 2>/dev/null`, { timeout: 5000 }).toString().trim()
        // ss 输出第一行是表头，需要检查是否有第二行
        const lines = output.split('\n').filter(l => l.trim())
        if (lines.length > 1 || output.includes(`:${port}`)) {
          return `端口 ${port} 已被占用（正在监听）\n${output}`
        }
        return `端口 ${port} 未被占用（空闲）`
      }
    } catch {
      return `端口 ${port} 未被占用（空闲）`
    }
  },

  // === AI 助手联网搜索工具 ===

  async assistant_web_search({ query, max_results = 5 }) {
    if (!query) throw new Error('搜索关键词不能为空')
    try {
      // 使用 DuckDuckGo HTML 搜索
      const url = `https://html.duckduckgo.com/html/?q=${encodeURIComponent(query)}`
      const https = require('https')
      const http = require('http')
      const fetchModule = url.startsWith('https') ? https : http
      const html = await new Promise((resolve, reject) => {
        const req = fetchModule.get(url, { headers: { 'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36' }, timeout: 10000 }, (res) => {
          if (res.statusCode >= 300 && res.statusCode < 400 && res.headers.location) {
            // 跟随重定向
            const rUrl = res.headers.location.startsWith('http') ? res.headers.location : `https://html.duckduckgo.com${res.headers.location}`
            fetchModule.get(rUrl, { headers: { 'User-Agent': 'Mozilla/5.0' }, timeout: 10000 }, (res2) => {
              let d = ''; res2.on('data', c => d += c); res2.on('end', () => resolve(d))
            }).on('error', reject)
            return
          }
          let data = ''; res.on('data', c => data += c); res.on('end', () => resolve(data))
        })
        req.on('error', reject)
        req.on('timeout', () => { req.destroy(); reject(new Error('搜索超时')) })
      })

      // 解析搜索结果
      const results = []
      const regex = /<a[^>]+class="result__a"[^>]*href="([^"]*)"[^>]*>([\s\S]*?)<\/a>[\s\S]*?<a[^>]+class="result__snippet"[^>]*>([\s\S]*?)<\/a>/gi
      let match
      while ((match = regex.exec(html)) !== null && results.length < max_results) {
        const rawUrl = match[1]
        const title = match[2].replace(/<[^>]+>/g, '').trim()
        const snippet = match[3].replace(/<[^>]+>/g, '').trim()
        // DuckDuckGo 的 URL 需要解码
        let finalUrl = rawUrl
        try {
          const uddg = new URL(rawUrl, 'https://duckduckgo.com').searchParams.get('uddg')
          if (uddg) finalUrl = decodeURIComponent(uddg)
        } catch {}
        if (title && finalUrl) {
          results.push({ title, url: finalUrl, snippet })
        }
      }

      if (results.length === 0) {
        return `搜索「${query}」未找到相关结果。`
      }

      let output = `搜索「${query}」找到 ${results.length} 条结果：\n\n`
      results.forEach((r, i) => {
        output += `${i + 1}. **${r.title}**\n   ${r.url}\n   ${r.snippet}\n\n`
      })
      return output
    } catch (err) {
      return `搜索失败: ${err.message}。请检查网络连接。`
    }
  },

  async assistant_fetch_url({ url }) {
    if (!url) throw new Error('URL 不能为空')
    if (!url.startsWith('http://') && !url.startsWith('https://')) throw new Error('URL 必须以 http:// 或 https:// 开头')

    try {
      // 优先使用 Jina Reader API（免费，返回 Markdown）
      const jinaUrl = 'https://r.jina.ai/' + url
      const https = require('https')
      const content = await new Promise((resolve, reject) => {
        const req = https.get(jinaUrl, {
          headers: { 'User-Agent': 'Mozilla/5.0', 'Accept': 'text/plain' },
          timeout: 15000,
        }, (res) => {
          let data = ''
          res.on('data', c => {
            data += c
            if (data.length > 100000) { req.destroy(); resolve(data.slice(0, 100000) + '\n\n[内容已截断，超过 100KB 限制]') }
          })
          res.on('end', () => resolve(data))
        })
        req.on('error', reject)
        req.on('timeout', () => { req.destroy(); reject(new Error('抓取超时')) })
      })

      return content || '（页面内容为空）'
    } catch (err) {
      return `抓取失败: ${err.message}`
    }
  },

  // === 面板配置（Web 模式） ===

  read_panel_config() {
    return readPanelConfig()
  },

  write_panel_config({ config }) {
    if (!fs.existsSync(OPENCLAW_DIR)) fs.mkdirSync(OPENCLAW_DIR, { recursive: true })
    fs.writeFileSync(PANEL_CONFIG_PATH, JSON.stringify(config, null, 2))
    invalidateConfigCache()
    return true
  },

  // === 扩展工具操作（Web 模式） ===

  cftunnel_action({ action }) {
    const bin = isWindows ? 'cftunnel.exe' : 'cftunnel'
    const cmd = action === 'up' ? `${bin} up -d` : `${bin} down`
    try {
      execSync(cmd, { timeout: 15000, windowsHide: true }).toString()
      return true
    } catch (e) {
      throw new Error(`cftunnel ${action} 失败: ${e.stderr?.toString() || e.message}`)
    }
  },

  get_cftunnel_logs({ lines = 20 }) {
    const bin = isWindows ? 'cftunnel.exe' : 'cftunnel'
    // 优先使用 cftunnel log 命令
    try {
      return execSync(`${bin} log -n ${lines} 2>&1`, { timeout: 5000, windowsHide: true }).toString()
    } catch {}
    // 回退：直接读日志文件
    const logPath = path.join(homedir(), '.cftunnel', 'cftunnel.log')
    if (!fs.existsSync(logPath)) return '暂无日志'
    try {
      if (!isWindows) {
        return execSync(`tail -${lines} "${logPath}" 2>&1`, { timeout: 3000 }).toString()
      }
      const content = fs.readFileSync(logPath, 'utf8')
      return content.split('\n').slice(-lines).join('\n')
    } catch {
      const content = fs.readFileSync(logPath, 'utf8')
      return content.split('\n').slice(-lines).join('\n')
    }
  },

  install_cftunnel() {
    try {
      let out
      if (isWindows) {
        out = execSync('powershell -NoProfile -ExecutionPolicy Bypass -Command "$tmp = Join-Path $env:TEMP install-cftunnel.ps1; Invoke-WebRequest -Uri https://raw.githubusercontent.com/qingchencloud/cftunnel/main/install.ps1 -OutFile $tmp -UseBasicParsing; & $tmp; Remove-Item $tmp -ErrorAction SilentlyContinue"', { timeout: 120000, windowsHide: true }).toString()
      } else {
        out = execSync('curl -fsSL https://raw.githubusercontent.com/qingchencloud/cftunnel/main/install.sh | bash', { timeout: 120000 }).toString()
      }
      return `安装完成\n${out.slice(-500)}`
    } catch (e) {
      throw new Error('安装失败: ' + (e.stderr?.toString() || e.message).slice(-500))
    }
  },

  install_clawapp() {
    try {
      let out
      if (isWindows) {
        out = execSync('powershell -NoProfile -ExecutionPolicy Bypass -Command "$tmp = Join-Path $env:TEMP install-clawapp.ps1; Invoke-WebRequest -Uri https://raw.githubusercontent.com/qingchencloud/clawapp/main/install.ps1 -OutFile $tmp -UseBasicParsing; & $tmp -Auto; Remove-Item $tmp -ErrorAction SilentlyContinue"', { timeout: 300000, windowsHide: true }).toString()
      } else {
        out = execSync('curl -fsSL https://raw.githubusercontent.com/qingchencloud/clawapp/main/install.sh | bash', { timeout: 300000 }).toString()
      }
      return `安装完成\n${out.slice(-500)}`
    } catch (e) {
      throw new Error('安装失败: ' + (e.stderr?.toString() || e.message).slice(-500))
    }
  },

  // === Agent 管理（Web 模式） ===

  add_agent({ name, model, workspace }) {
    if (!name) throw new Error('Agent 名称不能为空')
    const agentsDir = path.join(OPENCLAW_DIR, 'agents')
    const agentDir = path.join(agentsDir, name)
    if (fs.existsSync(agentDir)) throw new Error(`Agent "${name}" 已存在`)
    fs.mkdirSync(agentDir, { recursive: true })
    const meta = { id: name, model: model || null, workspace: workspace || null }
    fs.writeFileSync(path.join(agentDir, 'agent.json'), JSON.stringify(meta, null, 2))
    return true
  },

  delete_agent({ id }) {
    if (!id || id === 'main') throw new Error('不能删除默认 Agent')
    const agentDir = path.join(OPENCLAW_DIR, 'agents', id)
    if (!fs.existsSync(agentDir)) throw new Error(`Agent "${id}" 不存在`)
    fs.rmSync(agentDir, { recursive: true, force: true })
    return true
  },

  update_agent_identity({ id, name, emoji }) {
    if (!id) throw new Error('Agent ID 不能为空')
    // 写入 openclaw.json 的 agents 配置
    if (!fs.existsSync(CONFIG_PATH)) throw new Error('openclaw.json 不存在')
    const config = JSON.parse(fs.readFileSync(CONFIG_PATH, 'utf8'))
    if (!config.agents) config.agents = {}
    if (!config.agents.profiles) config.agents.profiles = {}
    if (!config.agents.profiles[id]) config.agents.profiles[id] = {}
    if (name) config.agents.profiles[id].identityName = name
    if (emoji) config.agents.profiles[id].emoji = emoji
    fs.copyFileSync(CONFIG_PATH, CONFIG_PATH + '.bak')
    fs.writeFileSync(CONFIG_PATH, JSON.stringify(config, null, 2))
    return true
  },

  update_agent_model({ id, model }) {
    if (!id) throw new Error('Agent ID 不能为空')
    if (!fs.existsSync(CONFIG_PATH)) throw new Error('openclaw.json 不存在')
    const config = JSON.parse(fs.readFileSync(CONFIG_PATH, 'utf8'))
    if (!config.agents) config.agents = {}
    if (!config.agents.profiles) config.agents.profiles = {}
    if (!config.agents.profiles[id]) config.agents.profiles[id] = {}
    config.agents.profiles[id].model = model || null
    fs.copyFileSync(CONFIG_PATH, CONFIG_PATH + '.bak')
    fs.writeFileSync(CONFIG_PATH, JSON.stringify(config, null, 2))
    return true
  },

  backup_agent({ id }) {
    if (!id) throw new Error('Agent ID 不能为空')
    const suffix = id !== 'main' ? `/agents/${id}` : ''
    const wsDir = path.join(OPENCLAW_DIR, 'workspace' + suffix)
    if (!fs.existsSync(wsDir)) return '工作区为空，无需备份'
    if (!fs.existsSync(BACKUPS_DIR)) fs.mkdirSync(BACKUPS_DIR, { recursive: true })
    const now = new Date()
    const pad = n => String(n).padStart(2, '0')
    const name = `agent-${id}-${now.getFullYear()}${pad(now.getMonth() + 1)}${pad(now.getDate())}-${pad(now.getHours())}${pad(now.getMinutes())}.tar`
    try {
      execSync(`tar -cf "${path.join(BACKUPS_DIR, name)}" -C "${wsDir}" .`, { timeout: 30000 })
      return `已备份: ${name}`
    } catch (e) {
      throw new Error('备份失败: ' + (e.message || e))
    }
  },

  // === 初始设置工具（Web 模式） ===

  check_node_at_path({ nodeDir }) {
    const nodeBin = path.join(nodeDir, isWindows ? 'node.exe' : 'node')
    if (!fs.existsSync(nodeBin)) throw new Error(`未在 ${nodeDir} 找到 node`)
    try {
      const ver = execSync(`"${nodeBin}" --version 2>&1`, { timeout: 5000, windowsHide: true }).toString().trim()
      return { installed: true, version: ver, path: nodeBin }
    } catch (e) {
      throw new Error('node 检测失败: ' + e.message)
    }
  },

  scan_node_paths() {
    const results = []
    const candidates = isWindows
      ? ['C:\\Program Files\\nodejs', 'C:\\Program Files (x86)\\nodejs']
      : ['/usr/local/bin', '/usr/bin', '/opt/homebrew/bin', path.join(homedir(), '.nvm/versions/node'), path.join(homedir(), '.volta/bin')]
    for (const p of candidates) {
      const nodeBin = path.join(p, isWindows ? 'node.exe' : 'node')
      if (fs.existsSync(nodeBin)) {
        try {
          const ver = execSync(`"${nodeBin}" --version 2>&1`, { timeout: 5000, windowsHide: true }).toString().trim()
          results.push({ path: p, version: ver })
        } catch {}
      }
    }
    return results
  },

  save_custom_node_path({ nodeDir }) {
    const cfg = readPanelConfig()
    cfg.customNodePath = nodeDir
    if (!fs.existsSync(OPENCLAW_DIR)) fs.mkdirSync(OPENCLAW_DIR, { recursive: true })
    fs.writeFileSync(PANEL_CONFIG_PATH, JSON.stringify(cfg, null, 2))
    invalidateConfigCache()
    return true
  },

  // === 访问密码认证 ===
  auth_check() {
    const pw = getAccessPassword()
    return { required: !!pw, authenticated: false /* 由中间件覆写 */ }
  },
  auth_login() { throw new Error('由中间件处理') },
  auth_logout() { throw new Error('由中间件处理') },
  auth_set_password({ password }) {
    const cfg = readPanelConfig()
    cfg.accessPassword = password || ''
    fs.writeFileSync(PANEL_CONFIG_PATH, JSON.stringify(cfg, null, 2))
    // 清除所有 session（密码变更后强制重新登录）
    _sessions.clear()
    return true
  },

  check_panel_update() { return { latest: null, url: 'https://github.com/qingchencloud/clawpanel/releases' } },

  // 前端热更新
  async check_frontend_update() {
    const pkgPath = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..', 'package.json')
    const pkg = JSON.parse(fs.readFileSync(pkgPath, 'utf8'))
    const currentVersion = pkg.version

    try {
      const resp = await globalThis.fetch('https://claw.qt.cool/update/latest.json', {
        signal: AbortSignal.timeout(8000),
        headers: { 'User-Agent': 'ClawPanel-Web' },
      })
      if (!resp.ok) throw new Error(`HTTP ${resp.status}`)
      const manifest = await resp.json()
      const latestVersion = manifest.version || ''
      const minAppVersion = manifest.minAppVersion || '0.0.0'
      const compatible = versionGe(currentVersion, minAppVersion)
      const hasUpdate = !!latestVersion && latestVersion !== currentVersion && compatible && versionGt(latestVersion, currentVersion)
      return { currentVersion, latestVersion, hasUpdate, compatible, updateReady: false, manifest }
    } catch {
      return { currentVersion, latestVersion: currentVersion, hasUpdate: false, compatible: true, updateReady: false, manifest: { version: currentVersion } }
    }
  },
  download_frontend_update() { return { success: true, files: 12, path: path.join(OPENCLAW_DIR, 'clawpanel', 'web-update') } },
  rollback_frontend_update() { return { success: true } },
  get_update_status() {
    const pkgPath = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..', 'package.json')
    const pkg = JSON.parse(fs.readFileSync(pkgPath, 'utf8'))
    return { currentVersion: pkg.version, updateReady: false, updateVersion: '', updateDir: path.join(OPENCLAW_DIR, 'clawpanel', 'web-update') }
  },
  write_env_file({ path: p, config }) {
    const expanded = p.startsWith('~/') ? path.join(homedir(), p.slice(2)) : p
    if (!expanded.startsWith(OPENCLAW_DIR)) throw new Error('只允许写入 ~/.openclaw/ 下的文件')
    const dir = path.dirname(expanded)
    if (!fs.existsSync(dir)) fs.mkdirSync(dir, { recursive: true })
    fs.writeFileSync(expanded, config)
    return true
  },
}

// === Vite 插件 ===

// 初始化：密码检测 + 启动日志 + 定时清理
function _initApi() {
  const cfg = readPanelConfig()
  if (!cfg.accessPassword && !cfg.ignoreRisk) {
    cfg.accessPassword = '123456'
    cfg.mustChangePassword = true
    if (!fs.existsSync(OPENCLAW_DIR)) fs.mkdirSync(OPENCLAW_DIR, { recursive: true })
    fs.writeFileSync(PANEL_CONFIG_PATH, JSON.stringify(cfg, null, 2))
    invalidateConfigCache()
    console.log('[api] ⚠️  首次启动，默认访问密码: 123456')
    console.log('[api] ⚠️  首次登录后将强制要求修改密码')
  }
  const pw = getAccessPassword()
  console.log('[api] API 已启动，配置目录:', OPENCLAW_DIR)
  console.log('[api] 平台:', isMac ? 'macOS' : process.platform)
  console.log('[api] 访问密码:', pw ? '已设置' : (cfg.ignoreRisk ? '无视风险模式（无密码）' : '未设置'))

  // 定时清理过期 session 和登录限速记录（每 10 分钟）
  setInterval(() => {
    const now = Date.now()
    for (const [token, session] of _sessions) {
      if (now > session.expires) _sessions.delete(token)
    }
    for (const [ip, record] of _loginAttempts) {
      if (record.lockedUntil && now >= record.lockedUntil) _loginAttempts.delete(ip)
    }
  }, 10 * 60 * 1000)
}

// API 中间件（dev server 和 preview server 共用）
async function _apiMiddleware(req, res, next) {
  if (!req.url?.startsWith('/__api/')) return next()

  const cmd = req.url.slice(7).split('?')[0]

  // --- 认证特殊处理 ---
  if (cmd === 'auth_check') {
    const cfg = readPanelConfig()
    const pw = cfg.accessPassword || ''
    const isDefault = pw === '123456'
    const resp = {
      required: !!pw,
      authenticated: !pw || isAuthenticated(req),
      mustChangePassword: isDefault,
    }
    if (isDefault) resp.defaultPassword = '123456'
    res.setHeader('Content-Type', 'application/json')
    res.end(JSON.stringify(resp))
    return
  }

  if (cmd === 'auth_login') {
    const clientIp = req.headers['x-forwarded-for']?.split(',')[0]?.trim() || req.socket.remoteAddress || ''
    const rateLimitErr = checkLoginRateLimit(clientIp)
    if (rateLimitErr) {
      res.statusCode = 429
      res.setHeader('Content-Type', 'application/json')
      res.end(JSON.stringify({ error: rateLimitErr }))
      return
    }
    const args = await readBody(req)
    const cfg = readPanelConfig()
    const pw = cfg.accessPassword || ''
    if (!pw) {
      res.setHeader('Content-Type', 'application/json')
      res.end(JSON.stringify({ success: true }))
      return
    }
    if (args.password !== pw) {
      recordLoginFailure(clientIp)
      res.statusCode = 401
      res.setHeader('Content-Type', 'application/json')
      res.end(JSON.stringify({ error: '密码错误' }))
      return
    }
    clearLoginAttempts(clientIp)
    const token = crypto.randomUUID()
    _sessions.set(token, { expires: Date.now() + SESSION_TTL })
    res.setHeader('Set-Cookie', `clawpanel_session=${token}; Path=/; HttpOnly; SameSite=Lax; Max-Age=${SESSION_TTL / 1000}`)
    res.setHeader('Content-Type', 'application/json')
    res.end(JSON.stringify({ success: true, mustChangePassword: !!cfg.mustChangePassword }))
    return
  }

  if (cmd === 'auth_change_password') {
    const args = await readBody(req)
    const cfg = readPanelConfig()
    const pw = cfg.accessPassword || ''
    if (pw && !isAuthenticated(req)) {
      res.statusCode = 401
      res.setHeader('Content-Type', 'application/json')
      res.end(JSON.stringify({ error: '未登录' }))
      return
    }
    if (pw && args.oldPassword !== pw) {
      res.statusCode = 400
      res.setHeader('Content-Type', 'application/json')
      res.end(JSON.stringify({ error: '当前密码错误' }))
      return
    }
    const weakErr = checkPasswordStrength(args.newPassword)
    if (weakErr) {
      res.statusCode = 400
      res.setHeader('Content-Type', 'application/json')
      res.end(JSON.stringify({ error: weakErr }))
      return
    }
    if (args.newPassword === pw) {
      res.statusCode = 400
      res.setHeader('Content-Type', 'application/json')
      res.end(JSON.stringify({ error: '新密码不能与旧密码相同' }))
      return
    }
    cfg.accessPassword = args.newPassword
    delete cfg.mustChangePassword
    delete cfg.ignoreRisk
    fs.writeFileSync(PANEL_CONFIG_PATH, JSON.stringify(cfg, null, 2))
    invalidateConfigCache()
    _sessions.clear()
    const token = crypto.randomUUID()
    _sessions.set(token, { expires: Date.now() + SESSION_TTL })
    res.setHeader('Set-Cookie', `clawpanel_session=${token}; Path=/; HttpOnly; SameSite=Lax; Max-Age=${SESSION_TTL / 1000}`)
    res.setHeader('Content-Type', 'application/json')
    res.end(JSON.stringify({ success: true }))
    return
  }

  if (cmd === 'auth_status') {
    const cfg = readPanelConfig()
    if (cfg.accessPassword && !isAuthenticated(req)) {
      res.statusCode = 401
      res.setHeader('Content-Type', 'application/json')
      res.end(JSON.stringify({ error: '未登录' }))
      return
    }
    const isDefault = cfg.accessPassword === '123456'
    const result = {
      hasPassword: !!cfg.accessPassword,
      mustChangePassword: isDefault,
      ignoreRisk: !!cfg.ignoreRisk,
    }
    if (isDefault) {
      result.defaultPassword = '123456'
    }
    res.setHeader('Content-Type', 'application/json')
    res.end(JSON.stringify(result))
    return
  }

  if (cmd === 'auth_ignore_risk') {
    if (!isAuthenticated(req)) {
      res.statusCode = 401
      res.setHeader('Content-Type', 'application/json')
      res.end(JSON.stringify({ error: '未登录' }))
      return
    }
    const args = await readBody(req)
    const cfg = readPanelConfig()
    if (args.enable) {
      delete cfg.accessPassword
      delete cfg.mustChangePassword
      cfg.ignoreRisk = true
      _sessions.clear()
    } else {
      delete cfg.ignoreRisk
    }
    fs.writeFileSync(PANEL_CONFIG_PATH, JSON.stringify(cfg, null, 2))
    invalidateConfigCache()
    res.setHeader('Content-Type', 'application/json')
    res.end(JSON.stringify({ success: true }))
    return
  }

  if (cmd === 'auth_logout') {
    const cookies = parseCookies(req)
    if (cookies.clawpanel_session) _sessions.delete(cookies.clawpanel_session)
    res.setHeader('Set-Cookie', 'clawpanel_session=; Path=/; HttpOnly; Max-Age=0')
    res.setHeader('Content-Type', 'application/json')
    res.end(JSON.stringify({ success: true }))
    return
  }

  // --- 认证中间件：非豁免接口必须校验 ---
  if (!isAuthenticated(req)) {
    res.statusCode = 401
    res.setHeader('Content-Type', 'application/json')
    res.end(JSON.stringify({ error: '未登录', code: 'AUTH_REQUIRED' }))
    return
  }

  // --- 实例代理：非 ALWAYS_LOCAL 命令，活跃实例非本机时代理转发 ---
  const activeInst = getActiveInstance()
  if (activeInst.type !== 'local' && activeInst.endpoint && !ALWAYS_LOCAL.has(cmd)) {
    try {
      const args = await readBody(req)
      const result = await proxyToInstance(activeInst, cmd, args)
      res.setHeader('Content-Type', 'application/json')
      res.end(JSON.stringify(result))
    } catch (e) {
      res.statusCode = 502
      res.setHeader('Content-Type', 'application/json')
      res.end(JSON.stringify({ error: `实例「${activeInst.name}」不可达: ${e.message}` }))
    }
    return
  }

  const handler = handlers[cmd]

  if (!handler) {
    res.statusCode = 404
    res.setHeader('Content-Type', 'application/json')
    res.end(JSON.stringify({ error: `未实现的命令: ${cmd}` }))
    return
  }

  try {
    const args = await readBody(req)
    const result = await handler(args)
    res.setHeader('Content-Type', 'application/json')
    res.end(JSON.stringify(result))
  } catch (e) {
    res.statusCode = 500
    res.setHeader('Content-Type', 'application/json')
    res.end(JSON.stringify({ error: e.message || String(e) }))
  }
}

// 导出供 serve.js 独立部署使用
export { _initApi, _apiMiddleware }

export function devApiPlugin() {
  let _inited = false
  function ensureInit() {
    if (_inited) return
    _inited = true
    _initApi()
  }
  return {
    name: 'clawpanel-dev-api',
    configureServer(server) {
      ensureInit()
      server.middlewares.use(_apiMiddleware)
    },
    configurePreviewServer(server) {
      ensureInit()
      server.middlewares.use(_apiMiddleware)
    },
  }
}
