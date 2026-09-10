import { useEffect, useState, useCallback } from 'react'
import { Wifi, WifiOff, RefreshCw, LayoutDashboard, Radar, Globe2, Sparkles, LogOut, ArrowUpRight, ShieldCheck, AlertCircle, ChevronRight } from 'lucide-react'
import Login, { Brand } from './components/Login'
import Overview   from './components/Overview'
import AttackFeed from './components/AttackFeed'
import Charts     from './components/Charts'
import GeoMap     from './components/GeoMap'
import Report     from './components/Report'
import IpDetail   from './components/IpDetail'
import { useWebSocket } from './hooks/useWebSocket'
import { authFetch, getSession, saveSession, clearSession } from './lib/api'

const API = ''  // vazio = mesmo host (proxy do Vite em dev)

async function apiFetch(path, options) {
  const res = await authFetch(API + path, { signal: AbortSignal.timeout(15000), ...options })
  if (!res.ok) throw new Error(res.statusText)
  return res.json()
}

export default function App() {
  const [session, setSession] = useState(getSession)
  const logout = useCallback(() => { clearSession(); setSession(null) }, [])
  useEffect(() => {
    window.addEventListener('beeia:unauthorized', logout)
    return () => window.removeEventListener('beeia:unauthorized', logout)
  }, [logout])
  return session ? <Dashboard onLogout={logout} /> : <Login onLogin={key => { saveSession(key); setSession(getSession()) }} />
}

const NAV = [
  { id: 'overview', label: 'Visão geral', icon: LayoutDashboard },
  { id: 'attacks', label: 'Ataques', icon: Radar },
  { id: 'map', label: 'Mapa de ameaças', icon: Globe2 },
  { id: 'reports', label: 'Relatórios com IA', icon: Sparkles },
]
const TITLES = {
  overview: ['Visão geral', 'Toda a atividade do seu ambiente, em um só lugar.'],
  attacks: ['Central de ataques', 'Investigue as sessões detectadas e gerencie bloqueios.'],
  map: ['Mapa de ameaças', 'Explore a origem geográfica dos ataques registrados.'],
  reports: ['Inteligência de ameaças', 'Transforme os eventos do ambiente em análises com IA.'],
}

function Dashboard({ onLogout }) {
  const [page, setPage] = useState('overview')
  const [inspectedIp, setInspectedIp] = useState(null)
  const [error, setError] = useState('')
  const [updatedAt, setUpdatedAt] = useState(null)
  const [stats,     setStats]     = useState(null)
  const [attacks,   setAttacks]   = useState([])
  const [chartData, setChartData] = useState([])
  const [geoData,   setGeoData]   = useState([])
  const [loading,   setLoading]   = useState(true)

  // Carrega dados iniciais via REST
  const loadAll = useCallback(async () => {
    setLoading(true)
    try {
      const [s, a, c, g] = await Promise.all([
        apiFetch('/api/stats'),
        apiFetch('/api/attacks?limit=100'),
        apiFetch('/api/attacks/chart?hours=12'),
        apiFetch('/api/geo'),
      ])
      setStats(s)
      setAttacks(a)
      setChartData(c)
      setGeoData(g)
      setUpdatedAt(new Date())
      setError('')
    } catch (e) {
      setError('Não foi possível atualizar os dados. Verifique a conexão com o servidor e tente novamente.')
    } finally {
      setLoading(false)
    }
  }, [])

  useEffect(() => {
    loadAll()
    const interval = setInterval(loadAll, 30_000)
    return () => clearInterval(interval)
  }, [loadAll])

  // WebSocket: recebe ataques em tempo real
  const connected = useWebSocket(useCallback((msg) => {
    if (msg.type === 'stats') {
      setStats(msg.data)
    }
    if (msg.type === 'new_attack') {
      setAttacks(prev => [msg.data, ...prev].slice(0, 200))
      setStats(prev => prev ? {
        ...prev,
        total_attacks:    (prev.total_attacks ?? 0) + 1,
        attacks_last_24h: (prev.attacks_last_24h ?? 0) + 1,
        attack_type_counts: {
          ...prev.attack_type_counts,
          [msg.data.attack_type]: ((prev.attack_type_counts?.[msg.data.attack_type] ?? 0) + 1),
        },
      } : prev)
      if (msg.data.latitude != null && msg.data.longitude != null) {
        setGeoData(prev => {
          const existing = prev.findIndex(p => p.src_ip === msg.data.src_ip)
          if (existing >= 0) {
            const updated = [...prev]
            updated[existing] = { ...updated[existing], count: (updated[existing].count ?? 1) + 1 }
            return updated
          }
          return [...prev, { ...msg.data, count: 1 }]
        })
      }
    }
    if (msg.type === 'ip_blocked') {
      setAttacks(prev => prev.map(a =>
        a.src_ip === msg.data.ip ? { ...a, blocked: 1 } : a
      ))
      setStats(prev => prev ? { ...prev, blocked_count: (prev.blocked_count ?? 0) + 1 } : prev)
    }
  }, []))

  // Bloquear IP manualmente
  const handleBlock = async (ip) => {
    try {
      const res = await apiFetch(`/api/block/${encodeURIComponent(ip)}`, { method: 'POST' })
      if (res.success) {
        setAttacks(prev => prev.map(a => a.src_ip === ip ? { ...a, blocked: 1 } : a))
        loadAll()
      }
      else setError(res.message || 'Não foi possível bloquear este IP.')
    } catch (e) {
      setError('Não foi possível bloquear o IP. Verifique a conexão e as permissões do servidor.')
    }
  }

  return (
    <div className="dashboard-shell">
      <aside className="sidebar">
        <Brand />
        <div className="workspace-label"><span className="workspace-avatar">B</span><div>Ambiente BeeIA<small>Honeypot monitoring</small></div><ChevronRight size={15} /></div>
        <div className="nav-caption">WORKSPACE</div>
        <nav aria-label="Navegação principal">{NAV.map(({ id, label, icon: Icon }) => <button key={id} className={`nav-item ${page === id ? 'active' : ''}`} aria-current={page === id ? 'page' : undefined} onClick={() => setPage(id)}><Icon size={19} /><span>{label}</span>{page === id && <span className="nav-dot" />}</button>)}</nav>
        <div className="sidebar-bottom"><div className="sidebar-info"><ShieldCheck size={22} /><strong>Visibilidade para proteger</strong><p>Cowrie e Dionaea.<br />Inteligência em cada evento.</p></div><button className="logout-button" onClick={onLogout}><LogOut size={17} /> Sair do painel</button><div className="sidebar-version">BeeIA <span>THREAT MONITOR</span></div></div>
      </aside>
      <div className="dashboard-body">
        <header className="topbar"><div className="breadcrumb">Workspace <ChevronRight size={13} /><span>{TITLES[page][0]}</span></div><div className={`connection-status ${connected ? 'online' : ''}`}>{connected ? <Wifi size={14} /> : <WifiOff size={14} />}{connected ? 'Ao vivo' : 'Sem conexão ao vivo'}</div></header>
        <main className="dashboard-main">
          <div className="page-heading"><div><div className="eyebrow">CENTRAL DE MONITORAMENTO</div><h1>{TITLES[page][0]}</h1><p>{TITLES[page][1]}</p></div><button className="secondary-button" onClick={loadAll} disabled={loading}><RefreshCw size={15} className={loading ? 'animate-spin' : ''} />{loading ? 'Atualizando...' : 'Atualizar dados'}</button></div>
          {error && <div className="notice error" role="alert"><AlertCircle size={18} /><span>{error}</span></div>}
          {loading && !stats && <div className="notice" role="status"><RefreshCw size={17} className="animate-spin" /> Carregando dados do ambiente...</div>}
          {(page === 'overview' || page === 'attacks') && <Overview stats={stats} />}
          {page === 'overview' && <>
            <div className="section-label"><h2>Panorama de ameaças</h2><span>Dados consolidados do ambiente</span></div>
            <div className="analysis-grid"><GeoMap geoData={geoData} /><Charts chartData={chartData} typeCounts={stats?.attack_type_counts ?? {}} /></div>
            <div className="section-label"><h2>Atividade recente</h2><button onClick={() => setPage('attacks')}>Explorar ataques <ArrowUpRight size={15} /></button></div>
            <AttackFeed attacks={attacks} onBlock={handleBlock} onInspect={setInspectedIp} compact />
            <button className="report-callout" onClick={() => setPage('reports')}><span className="callout-icon"><Sparkles size={22} /></span><span><strong>Dos eventos à inteligência.</strong><small>Gere uma análise das ameaças com recomendações de mitigação.</small></span><ArrowUpRight size={21} /></button>
          </>}
          {page === 'attacks' && <AttackFeed attacks={attacks} onBlock={handleBlock} onInspect={setInspectedIp} />}
          {page === 'map' && <GeoMap geoData={geoData} />}
          {page === 'reports' && <Report />}
          <IpDetail ip={inspectedIp} onClose={() => setInspectedIp(null)} onBlock={handleBlock} />
          <footer className="dashboard-footer"><span>BeeIA / Threat Intelligence</span><span>{updatedAt ? `Última sincronização às ${updatedAt.toLocaleTimeString('pt-BR')}` : 'Aguardando sincronização'}</span></footer>
        </main>
      </div>
    </div>
  )
}
