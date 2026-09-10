import { useState } from 'react'
import { ShieldOff, ShieldCheck, Search } from 'lucide-react'

const TYPE_STYLES = {
  brute_force:           'bg-red-900/50 text-red-300 border-red-700',
  command_injection:     'bg-orange-900/50 text-orange-300 border-orange-700',
  malware_download:      'bg-purple-900/50 text-purple-300 border-purple-700',
  recon:                 'bg-blue-900/50 text-blue-300 border-blue-700',
  port_scan:             'bg-teal-900/50 text-teal-300 border-teal-700',
  service_probe:         'bg-yellow-900/50 text-yellow-300 border-yellow-700',
  exploit_attempt:       'bg-pink-900/50 text-pink-300 border-pink-700',
  // Classes do modelo Dionaea treinado com captura real.
  connection_flood:      'bg-indigo-900/50 text-indigo-300 border-indigo-700',
  credential_bruteforce: 'bg-emerald-900/50 text-emerald-300 border-emerald-700',
}

const TYPE_LABELS = {
  brute_force:           'Brute Force',
  command_injection:     'Cmd Injection',
  malware_download:      'Malware DL',
  recon:                 'Recon',
  port_scan:             'Port Scan',
  service_probe:         'Probe',
  exploit_attempt:       'Exploit',
  connection_flood:      'Flood',
  credential_bruteforce: 'Cred. Brute',
}

const HONEYPOT_STYLES = {
  cowrie:  'bg-cyan-900/40 text-cyan-300 border-cyan-700',
  dionaea: 'bg-amber-900/40 text-amber-300 border-amber-700',
}

const HONEYPOT_LABELS = {
  cowrie:  'Cowrie',
  dionaea: 'Dionaea',
}

function Badge({ type }) {
  return (
    <span className={`text-xs px-2 py-0.5 rounded border font-medium ${TYPE_STYLES[type] ?? 'bg-slate-700 text-slate-300 border-slate-600'}`}>
      {TYPE_LABELS[type] ?? type}
    </span>
  )
}

function HoneypotBadge({ honeypot }) {
  const hp = honeypot || 'cowrie'
  return (
    <span className={`text-xs px-2 py-0.5 rounded border font-medium ${HONEYPOT_STYLES[hp] ?? 'bg-slate-700 text-slate-300 border-slate-600'}`}>
      {HONEYPOT_LABELS[hp] ?? hp}
    </span>
  )
}

function ConfBar({ value }) {
  const pct = Math.max(0, Math.min(100, Math.round((Number(value) || 0) * 100)))
  const color = pct >= 90 ? 'bg-red-500' : pct >= 70 ? 'bg-orange-500' : 'bg-yellow-500'
  return (
    <div className="flex items-center gap-2">
      <div className="w-16 h-1.5 bg-surface-700 rounded-full overflow-hidden">
        <div className={`h-full rounded-full ${color}`} style={{ width: `${pct}%` }} />
      </div>
      <span className="text-xs text-slate-400">{pct}%</span>
    </div>
  )
}

export default function AttackFeed({ attacks, onBlock, onInspect, compact = false }) {
  const [blocking, setBlocking] = useState(null)
  const [search, setSearch] = useState('')
  const [honeypot, setHoneypot] = useState('all')
  const filtered = attacks.filter(a => (honeypot === 'all' || (a.honeypot || 'cowrie') === honeypot) && [a.src_ip, a.country, a.attack_type, TYPE_LABELS[a.attack_type]].some(value => String(value || '').toLowerCase().includes(search.toLowerCase())))
  const visible = compact ? filtered.slice(0, 6) : filtered

  const handleBlock = async (ip) => {
    setBlocking(ip)
    try { await onBlock(ip) } finally { setBlocking(null) }
  }

  return (
    <div className="bg-surface-800 rounded-xl border border-surface-700 flex flex-col overflow-hidden h-full">
      <div className="px-5 py-3 border-b border-surface-700 flex items-center justify-between">
        <h2 className="font-semibold text-slate-200">Sessões detectadas</h2>
        <span className="text-xs text-slate-400">{filtered.length} de {attacks.length} sessões carregadas</span>
      </div>
      <div className="feed-toolbar"><label className="search-input"><Search size={16} /><input aria-label="Buscar nas sessões carregadas" placeholder="Buscar IP, país ou tipo de ataque..." value={search} onChange={e => setSearch(e.target.value)} /></label><select aria-label="Filtrar honeypot nas sessões carregadas" value={honeypot} onChange={e => setHoneypot(e.target.value)}><option value="all">Todos os honeypots</option><option value="cowrie">Cowrie</option><option value="dionaea">Dionaea</option></select></div>

      <div className="attack-table-scroll">
        {visible.length === 0 ? (
          <div className="empty-state">
            <ShieldCheck size={28} />
            <strong>{attacks.length ? 'Nenhuma sessão encontrada' : 'Nenhum ataque registrado'}</strong>
            <span>{attacks.length ? 'Tente outro termo ou honeypot.' : 'Os novos eventos aparecerão aqui conforme forem detectados.'}</span>
          </div>
        ) : (
          <table className="w-full text-sm">
            <thead className="sticky top-0 bg-surface-800 border-b border-surface-700">
              <tr className="text-xs text-slate-500 uppercase tracking-wider">
                <th className="px-4 py-2 text-left">IP Origem</th>
                <th className="px-4 py-2 text-left">Honeypot</th>
                <th className="px-4 py-2 text-left">Tipo</th>
                <th className="px-4 py-2 text-left">Confiança</th>
                <th className="px-4 py-2 text-left">País</th>
                <th className="px-4 py-2 text-left">Hora</th>
                <th className="px-4 py-2 text-left">Ação</th>
              </tr>
            </thead>
            <tbody>
              {visible.map((a, i) => (
                <tr
                  key={a.session_id ?? i}
                  className="border-b border-surface-700/50 hover:bg-surface-700/40 transition-colors"
                >
                  <td className="px-4 py-2 font-mono text-cyan-300 text-xs">
                    {onInspect ? (
                      <button className="ip-link" onClick={() => onInspect(a.src_ip)} title={`Ver tudo o que ${a.src_ip} tentou`}>
                        {a.src_ip}
                      </button>
                    ) : a.src_ip}
                  </td>
                  <td className="px-4 py-2"><HoneypotBadge honeypot={a.honeypot} /></td>
                  <td className="px-4 py-2"><Badge type={a.attack_type} /></td>
                  <td className="px-4 py-2"><ConfBar value={a.confidence} /></td>
                  <td className="px-4 py-2 text-slate-400 text-xs">{a.country ?? '—'}</td>
                  <td className="px-4 py-2 text-slate-500 text-xs">
                    {a.timestamp ? new Date(a.timestamp).toLocaleTimeString('pt-BR') : '—'}
                  </td>
                  <td className="px-4 py-2">
                    {a.blocked ? (
                      <span className="text-xs text-red-400 flex items-center gap-1">
                        <ShieldOff size={12} /> Bloqueado
                      </span>
                    ) : (
                      <button
                        onClick={() => handleBlock(a.src_ip)}
                        disabled={blocking === a.src_ip}
                        className="text-xs px-2 py-0.5 rounded bg-red-900/40 text-red-300 border border-red-700 hover:bg-red-800/60 disabled:opacity-50 transition-colors"
                      >
                        {blocking === a.src_ip ? '...' : 'Bloquear'}
                      </button>
                    )}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </div>
    </div>
  )
}
