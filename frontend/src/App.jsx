import { useEffect, useState, useCallback } from 'react'
import { Wifi, WifiOff, RefreshCw } from 'lucide-react'
import Overview   from './components/Overview'
import AttackFeed from './components/AttackFeed'
import Charts     from './components/Charts'
import GeoMap     from './components/GeoMap'
import { useWebSocket } from './hooks/useWebSocket'

const API = ''  // vazio = mesmo host (proxy do Vite em dev)

async function apiFetch(path) {
  const res = await fetch(API + path)
  if (!res.ok) throw new Error(res.statusText)
  return res.json()
}

export default function App() {
  const [stats,     setStats]     = useState(null)
  const [attacks,   setAttacks]   = useState([])
  const [chartData, setChartData] = useState([])
  const [geoData,   setGeoData]   = useState([])
  const [loading,   setLoading]   = useState(true)

  // Carrega dados iniciais via REST
  const loadAll = useCallback(async () => {
    try {
      const [s, a, c, g] = await Promise.all([
        apiFetch('/api/stats'),
        apiFetch('/api/attacks?limit=100'),
        apiFetch('/api/attacks/chart?hours=24'),
        apiFetch('/api/geo'),
      ])
      setStats(s)
      setAttacks(a)
      setChartData(c)
      setGeoData(g)
    } catch (e) {
      console.error('Erro ao carregar dados:', e)
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
      if (msg.data.latitude && msg.data.longitude) {
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
      const res = await apiFetch(`/api/block/${ip}`)
      if (res.success) {
        setAttacks(prev => prev.map(a => a.src_ip === ip ? { ...a, blocked: 1 } : a))
        setStats(prev => prev ? { ...prev, blocked_count: (prev.blocked_count ?? 0) + 1 } : prev)
      }
    } catch (e) {
      console.error('Erro ao bloquear IP:', e)
    }
  }

  if (loading) {
    return (
      <div className="h-screen flex items-center justify-center text-slate-400">
        <RefreshCw className="animate-spin mr-2" size={18} />
        Conectando ao backend...
      </div>
    )
  }

  return (
    <div className="min-h-screen bg-surface-900 flex flex-col">

      {/* Header */}
      <header className="bg-surface-800 border-b border-surface-700 px-6 py-3 flex items-center justify-between">
        <div className="flex items-center gap-3">
          <span className="text-xl">🐝</span>
          <div>
            <h1 className="font-bold text-slate-100 text-lg leading-tight">BeeIA</h1>
            <p className="text-xs text-slate-500">Honeypot Threat Monitor</p>
          </div>
        </div>

        <div className="flex items-center gap-4">
          <button
            onClick={loadAll}
            className="text-slate-400 hover:text-slate-200 transition-colors"
            title="Atualizar"
          >
            <RefreshCw size={16} />
          </button>
          <div className={`flex items-center gap-1.5 text-xs ${connected ? 'text-green-400' : 'text-red-400'}`}>
            {connected ? <Wifi size={14} /> : <WifiOff size={14} />}
            {connected ? 'Ao vivo' : 'Desconectado'}
          </div>
        </div>
      </header>

      {/* Conteúdo */}
      <main className="flex-1 p-6 flex flex-col gap-5 max-w-screen-2xl mx-auto w-full">

        {/* Cards de visão geral */}
        <Overview stats={stats} />

        {/* Feed + Gráficos lado a lado */}
        <div className="grid grid-cols-1 xl:grid-cols-3 gap-5" style={{ minHeight: 420 }}>
          <div className="xl:col-span-2">
            <AttackFeed attacks={attacks} onBlock={handleBlock} />
          </div>
          <div>
            <Charts
              chartData={chartData}
              typeCounts={stats?.attack_type_counts ?? {}}
            />
          </div>
        </div>

        {/* Mapa geográfico */}
        <GeoMap geoData={geoData} />

      </main>
    </div>
  )
}
