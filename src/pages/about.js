/**
 * 关于页面
 * 版本信息、项目链接、相关项目、系统环境
 */
import { api } from '../lib/tauri-api.js'
import { toast } from '../components/toast.js'
import { showUpgradeModal } from '../components/modal.js'

export async function render() {
  const page = document.createElement('div')
  page.className = 'page'

  page.innerHTML = `
    <div class="page-header" style="display:flex;align-items:center;gap:16px">
      <img src="/images/logo-brand.png" alt="ClawPanel" style="height:48px;width:auto">
      <div>
        <h1 class="page-title" style="margin:0">ClawPanel</h1>
        <p class="page-desc" style="margin:0">OpenClaw 可视化管理面板</p>
      </div>
    </div>
    <div class="stat-cards" id="version-cards">
      <div class="stat-card loading-placeholder"></div>
      <div class="stat-card loading-placeholder"></div>
      <div class="stat-card loading-placeholder"></div>
    </div>
    <div class="config-section">
      <div class="config-section-title">社群交流</div>
      <div id="community-section"></div>
    </div>
    <div class="config-section">
      <div class="config-section-title">相关项目</div>
      <div id="projects-list"></div>
    </div>
    <div class="config-section">
      <div class="config-section-title">快捷链接</div>
      <div id="links-list"></div>
    </div>
    <div class="config-section" style="color:var(--text-tertiary);font-size:var(--font-size-xs)">
      <p>ClawPanel 基于 Tauri v2 构建，前端 Vanilla JS + Vite，后端 Rust。</p>
      <p style="margin-top:8px">MIT License &copy; 2026 qingchencloud</p>
    </div>
  `

  loadData(page)
  renderCommunity(page)
  renderProjects(page)
  renderLinks(page)
  return page
}

async function loadData(page) {
  const cards = page.querySelector('#version-cards')
  try {
    const [version, install] = await Promise.all([
      api.getVersionInfo(),
      api.checkInstallation(),
    ])

    // 尝试从 Tauri API 获取 ClawPanel 自身版本号，失败则 fallback
    let panelVersion = '0.1.0'
    try {
      const { getVersion } = await import('@tauri-apps/api/app')
      panelVersion = await getVersion()
    } catch {
      // 非 Tauri 环境或 API 不可用，使用 fallback
    }

    cards.innerHTML = `
      <div class="stat-card">
        <div class="stat-card-header"><span class="stat-card-label">ClawPanel</span></div>
        <div class="stat-card-value">${panelVersion}</div>
        <div class="stat-card-meta">Tauri v2 桌面应用</div>
      </div>
      <div class="stat-card">
        <div class="stat-card-header"><span class="stat-card-label">OpenClaw · ${version.source === 'official' ? '官方版' : '汉化版'}</span></div>
        <div class="stat-card-value">${version.current || '未安装'}</div>
        <div class="stat-card-meta" style="display:flex;align-items:center;gap:8px">
          ${version.update_available
            ? `<span style="color:var(--accent)">新版本: ${version.latest}</span><button class="btn btn-primary btn-sm" id="btn-upgrade" style="padding:2px 8px;font-size:var(--font-size-xs)">升级</button>`
            : version.current ? '<span style="color:var(--success)">已是最新</span>' : '<span style="color:var(--error)">未检测到</span>'}
        </div>
      </div>
      <div class="stat-card">
        <div class="stat-card-header"><span class="stat-card-label">安装路径</span></div>
        <div class="stat-card-value" style="font-size:var(--font-size-sm);word-break:break-all">${install.path || '未知'}</div>
        <div class="stat-card-meta">${install.installed ? '配置文件存在' : '未找到配置文件'}</div>
      </div>
    `

    // 绑定升级按钮
    const upgradeBtn = cards.querySelector('#btn-upgrade')
    if (upgradeBtn) {
      upgradeBtn.onclick = async () => {
        const modal = showUpgradeModal()
        let unlistenLog, unlistenProgress
        try {
          const { listen } = await import('@tauri-apps/api/event')
          unlistenLog = await listen('upgrade-log', (e) => modal.appendLog(e.payload))
          unlistenProgress = await listen('upgrade-progress', (e) => modal.setProgress(e.payload))
          const msg = await api.upgradeOpenclaw()
          modal.setDone(msg)
          loadData(page)
        } catch (e) {
          modal.appendLog(String(e))
          modal.setError('升级失败')
        } finally {
          unlistenLog?.()
          unlistenProgress?.()
        }
      }
    }
  } catch {
    cards.innerHTML = '<div class="stat-card"><div class="stat-card-label">加载失败</div></div>'
  }
}

function renderCommunity(page) {
  const el = page.querySelector('#community-section')
  el.innerHTML = `
    <div style="display:flex;gap:24px;flex-wrap:wrap;align-items:flex-start">
      <div style="text-align:center">
        <img src="/images/OpenClaw-QQ.png" alt="QQ 交流群" style="width:140px;height:140px;border-radius:var(--radius-md);border:1px solid var(--border-primary)">
        <div style="font-size:var(--font-size-sm);margin-top:8px;color:var(--text-secondary)">QQ 交流群</div>
      </div>
      <div style="text-align:center">
        <img src="/images/OpenClawWx.png" alt="微信交流群" style="width:140px;height:140px;border-radius:var(--radius-md);border:1px solid var(--border-primary)">
        <div style="font-size:var(--font-size-sm);margin-top:8px;color:var(--text-secondary)">微信交流群</div>
      </div>
      <div style="flex:1;min-width:200px;display:flex;flex-direction:column;gap:8px;padding-top:4px">
        <div style="font-size:var(--font-size-sm);color:var(--text-secondary)">扫码或点击链接加入交流群，反馈问题、获取帮助</div>
        <div style="display:flex;flex-wrap:wrap;gap:8px;margin-top:8px">
          <a class="btn btn-primary btn-sm" href="https://qt.cool/c/OpenClaw" target="_blank" rel="noopener">加入 QQ 群</a>
          <a class="btn btn-primary btn-sm" href="https://qt.cool/c/OpenClawWx" target="_blank" rel="noopener">加入微信群</a>
          <a class="btn btn-secondary btn-sm" href="https://yb.tencent.com/gp/i/LsvIw7mdR7Lb" target="_blank" rel="noopener">元宝派社群</a>
        </div>
        <div style="font-size:var(--font-size-xs);color:var(--text-tertiary);margin-top:8px">
          2000 人大群，满员自动切换 · 碰到问题可直接在群内反馈
        </div>
      </div>
    </div>
  `
}

const PROJECTS = [
  {
    name: 'OpenClaw',
    desc: 'AI Agent 框架，支持多模型协作、工具调用、记忆管理',
    url: 'https://github.com/openclaw/openclaw',
  },
  {
    name: 'ClawApp',
    desc: '跨平台移动聊天客户端，H5 + 代理服务器架构，支持离线和流式传输',
    url: 'https://github.com/qingchencloud/clawapp',
  },
  {
    name: 'cftunnel',
    desc: '全协议内网穿透工具，Cloud 模式免费 HTTP/WS + Relay 模式自建中继',
    url: 'https://github.com/qingchencloud/cftunnel',
  },
  {
    name: 'ClawPanel',
    desc: 'OpenClaw 可视化管理面板，Tauri v2 桌面应用',
    url: 'https://github.com/qingchencloud/clawpanel',
  },
]

function renderProjects(page) {
  const el = page.querySelector('#projects-list')
  el.innerHTML = PROJECTS.map(p => `
    <div class="service-card">
      <div class="service-info">
        <div>
          <div class="service-name">${p.name}</div>
          <div class="service-desc">${p.desc}</div>
        </div>
      </div>
      <div class="service-actions">
        <a class="btn btn-secondary btn-sm" href="${p.url}" target="_blank" rel="noopener">GitHub</a>
      </div>
    </div>
  `).join('')
}

const LINKS = [
  { label: 'cftunnel 官网', url: 'https://cftunnel.qt.cool' },
  { label: 'cftunnel 桌面客户端', url: 'https://github.com/qingchencloud/cftunnel-app/releases' },
  { label: 'OpenClaw 中文翻译', url: 'https://github.com/1186258278/OpenClawChineseTranslation' },
  { label: 'ClawApp 文档', url: 'https://github.com/qingchencloud/clawapp#readme' },
]

function renderLinks(page) {
  const el = page.querySelector('#links-list')
  el.innerHTML = `<div style="display:flex;flex-wrap:wrap;gap:var(--space-sm)">
    ${LINKS.map(l => `<a class="btn btn-secondary btn-sm" href="${l.url}" target="_blank" rel="noopener">${l.label}</a>`).join('')}
  </div>`
}
