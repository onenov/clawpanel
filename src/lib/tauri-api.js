/**
 * Tauri API 封装层
 * 开发阶段用 mock 数据，Tauri 环境用 invoke
 */

const isTauri = !!window.__TAURI_INTERNALS__

async function invoke(cmd, args = {}) {
  if (isTauri) {
    const { invoke: tauriInvoke } = await import('@tauri-apps/api/core')
    return tauriInvoke(cmd, args)
  }
  return mockInvoke(cmd, args)
}

// Mock 数据，方便纯浏览器开发调试
function mockInvoke(cmd, args) {
  const mocks = {
    get_services_status: () => [
      { label: 'ai.openclaw.gateway', pid: null, running: false, description: 'OpenClaw Gateway' },
    ],
    get_version_info: () => ({
      current: '2026.2.23',
      latest: null,
      update_available: false,
    }),
    read_openclaw_config: () => ({
      meta: { lastTouchedVersion: '2026.2.23' },
      models: {
        mode: 'replace',
        providers: {
          'newapi-claude': {
            baseUrl: 'http://192.168.1.14:30080/v1',
            api: 'openai-completions',
            models: [
              { id: 'claude-opus-4-6' },
              { id: 'claude-sonnet-4-5' },
            ],
          },
        },
      },
      agents: {
        defaults: {
          model: { primary: 'newapi-claude/claude-opus-4-6', fallbacks: ['newapi-claude/claude-sonnet-4-5'] },
          maxConcurrent: 4,
          subagents: 2,
        },
      },
      gateway: { port: 18789, mode: 'local', bind: 'loopback', authToken: '' },
    }),
    write_openclaw_config: () => true,
    read_log_tail: ({ logName }) => {
      const logs = {
        'gateway': [
          '2026-02-26 13:29:01 [INFO] Gateway started on :18789',
          '2026-02-26 13:29:02 [INFO] Agent connected: claude-opus-4-6',
          '2026-02-26 13:29:05 [INFO] Request /v1/chat/completions → 200 (1.2s)',
          '2026-02-26 13:30:12 [INFO] Request /v1/chat/completions → 200 (3.8s)',
          '2026-02-26 13:31:00 [WARN] Rate limit approaching: 45/50 rpm',
          '2026-02-26 13:32:15 [INFO] Request /v1/chat/completions → 200 (2.1s)',
        ],
        'gateway-err': ['2026-02-26 12:00:01 [ERROR] Upstream 502: connection refused'],
        'guardian': ['2026-02-26 13:29:00 [INFO] Health check passed', '2026-02-26 13:30:00 [INFO] Health check passed'],
        'guardian-backup': ['2026-02-26 12:00:00 [INFO] Backup completed: openclaw.json.bak'],
        'config-audit': ['{"ts":"2026-02-26T13:29:00Z","action":"config.read","file":"openclaw.json"}'],
      }
      return (logs[logName] || logs['gateway']).join('\n')
    },
    search_log: ({ query }) => [
      `2026-02-26 13:29:01 [INFO] Match: ${query}`,
      `2026-02-26 13:30:12 [INFO] Found: ${query} in request`,
    ],
    list_memory_files: ({ category }) => {
      const files = {
        memory: ['active-context.md', 'decisions.md', 'progress.md'],
        archive: ['2026-02-sprint1.md', '2026-02-sprint2.md'],
        core: ['AGENTS.md', 'CLAUDE.md'],
      }
      return files[category] || files.memory
    },
    read_memory_file: ({ path }) => `# ${path}\n\n这是 ${path} 的内容示例。\n\n## 概述\n\n在此记录工作记忆...`,
    write_memory_file: () => true,
    delete_memory_file: () => true,
    export_memory_zip: ({ category }) => `/tmp/openclaw-${category}-20260226-160000.zip`,
    check_installation: () => ({ installed: true, path: '/usr/local/bin/openclaw', version: '2026.2.23' }),
    get_deploy_config: () => ({ gatewayUrl: 'http://127.0.0.1:18789', authToken: '', version: '2026.2.23' }),
    read_mcp_config: () => ({
      mcpServers: {
        'exa': { command: 'npx', args: ['-y', '@anthropic/exa-mcp-server'], env: { EXA_API_KEY: '***' } },
        'web-reader': { command: 'npx', args: ['-y', '@anthropic/web-reader-mcp'], env: {} },
        'pal': { command: 'node', args: ['/opt/pal-mcp/index.js'], env: {} },
      },
    }),
    write_mcp_config: () => true,
    start_service: () => true,
    stop_service: () => true,
    restart_service: () => true,
    reload_gateway: () => 'Gateway 已重载',
    upgrade_openclaw: () => '升级成功，当前版本: 2026.2.26-zh.3 (mock)',
    install_gateway: () => 'Gateway 服务已安装 (mock)',
    uninstall_gateway: () => 'Gateway 服务已卸载 (mock)',
    get_npm_registry: () => 'https://registry.npmmirror.com',
    set_npm_registry: () => true,
    test_model: ({ modelId }) => `模型 ${modelId} 连通正常 (mock)`,
    list_remote_models: () => ['gpt-4o', 'gpt-4o-mini', 'gpt-4-turbo', 'gpt-3.5-turbo', 'o3-mini', 'dall-e-3', 'text-embedding-3-small'],
    write_env_file: () => true,
    list_backups: () => [
      { name: 'openclaw-20260226-143000.json', size: 8542, created_at: 1740577800 },
      { name: 'openclaw-20260225-100000.json', size: 8210, created_at: 1740474000 },
    ],
    create_backup: () => ({ name: 'openclaw-20260226-160000.json', size: 8542 }),
    restore_backup: () => true,
    delete_backup: () => true,
    get_cftunnel_status: () => ({
      installed: true, version: 'cftunnel 0.7.0', running: true,
      tunnel_name: 'mac-home', pid: 73325,
      routes: [
        { name: 'clawapp', domain: 'chat.qrj.ai', service: 'http://localhost:3210' },
        { name: 'newapi', domain: 'newapi.qrj.ai', service: 'http://localhost:30080' },
        { name: 'webhook', domain: 'webhook.qrj.ai', service: 'http://localhost:9801' },
      ],
    }),
    cftunnel_action: () => true,
    get_cftunnel_logs: () => '2026-02-26 13:29:01 [INFO] Tunnel started\n2026-02-26 13:30:00 [INFO] Connection healthy',
    get_clawapp_status: () => ({ running: true, pid: 7752, port: 3210, url: 'http://localhost:3210' }),
  }
  const fn = mocks[cmd]
  return fn ? Promise.resolve(fn(args)) : Promise.reject(`未知命令: ${cmd}`)
}

// 导出 API
export const api = {
  // 服务管理
  getServicesStatus: () => invoke('get_services_status'),
  startService: (label) => invoke('start_service', { label }),
  stopService: (label) => invoke('stop_service', { label }),
  restartService: (label) => invoke('restart_service', { label }),

  // 配置
  getVersionInfo: () => invoke('get_version_info'),
  readOpenclawConfig: () => invoke('read_openclaw_config'),
  writeOpenclawConfig: (config) => invoke('write_openclaw_config', { config }),
  readMcpConfig: () => invoke('read_mcp_config'),
  writeMcpConfig: (config) => invoke('write_mcp_config', { config }),
  reloadGateway: () => invoke('reload_gateway'),
  upgradeOpenclaw: (source = 'chinese') => invoke('upgrade_openclaw', { source }),
  installGateway: () => invoke('install_gateway'),
  uninstallGateway: () => invoke('uninstall_gateway'),
  getNpmRegistry: () => invoke('get_npm_registry'),
  setNpmRegistry: (registry) => invoke('set_npm_registry', { registry }),
  testModel: (baseUrl, apiKey, modelId) => invoke('test_model', { baseUrl, apiKey, modelId }),
  listRemoteModels: (baseUrl, apiKey) => invoke('list_remote_models', { baseUrl, apiKey }),

  // 日志
  readLogTail: (logName, lines = 100) => invoke('read_log_tail', { logName, lines }),
  searchLog: (logName, query, maxResults = 50) => invoke('search_log', { logName, query, maxResults }),

  // 记忆文件
  listMemoryFiles: (category) => invoke('list_memory_files', { category }),
  readMemoryFile: (path) => invoke('read_memory_file', { path }),
  writeMemoryFile: (path, content, category) => invoke('write_memory_file', { path, content, category: category || 'memory' }),
  deleteMemoryFile: (path) => invoke('delete_memory_file', { path }),
  exportMemoryZip: (category) => invoke('export_memory_zip', { category }),

  // 安装/部署
  checkInstallation: () => invoke('check_installation'),
  getDeployConfig: () => invoke('get_deploy_config'),
  writeEnvFile: (path, config) => invoke('write_env_file', { path, config }),

  // 备份管理
  listBackups: () => invoke('list_backups'),
  createBackup: () => invoke('create_backup'),
  restoreBackup: (name) => invoke('restore_backup', { name }),
  deleteBackup: (name) => invoke('delete_backup', { name }),

  // 扩展工具
  getCftunnelStatus: () => invoke('get_cftunnel_status'),
  cftunnelAction: (action) => invoke('cftunnel_action', { action }),
  getCftunnelLogs: (lines = 20) => invoke('get_cftunnel_logs', { lines }),
  getClawappStatus: () => invoke('get_clawapp_status'),
  installCftunnel: () => invoke('install_cftunnel'),
}
