import { useState } from 'react'
import { ShieldOff, ShieldCheck } from 'lucide-react'

const TYPE_STYLES = {
  brute_force:       'bg-red-900/50 text-red-300 border-red-700',
  command_injection: 'bg-orange-900/50 text-orange-300 border-orange-700',
  malware_download:  'bg-purple-900/50 text-purple-300 border-purple-700',
  recon:             'bg-blue-900/50 text-blue-300 border-blue-700',
}

const TYPE_LABELS = {
  brute_force:       'Brute Force',
  command_injection: 'Cmd Injection',
  malware_download:  'Malware DL',
  recon:             'Recon',
}

function Badge({ type }) {
  return (
    <span className={`text-xs px-2 py-0.5 rounded border font-medium ${TYPE_STYLES[type] ?? 'bg-slate-700 text-slate-300 border-slate-600'}`}>
      {TYPE_LABELS[type] ?? type}
    </span>
  )
}

function ConfBar({ value }) {
  const pct = Math.round(value * 100)
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

export default function AttackFeed({ attacks, onBlock }) {
  const [blocking, setBlocking] = useState(null)

  const handleBlock = async (ip) => {
    setBlocking(ip)
    await onBlock(ip)
    setBlocking(null)
  }

  return (
    <div className="bg-surface-800 rounded-xl border border-surface-700 flex flex-col overflow-hidden h-full">
      <div className="px-5 py-3 border-b border-surface-700 flex items-center justify-between">
        <h2 className="font-semibold text-slate-200">Feed de Ataques</h2>
        <span className="text-xs text-slate-500">{attacks.length} sessões</span>
      </div>

      <div className="overflow-y-auto flex-1">
        {attacks.length === 0 ? (
          <div className="flex flex-col items-center justify-center h-40 text-slate-500 text-sm gap-2">
            <ShieldCheck size={28} />
            Aguardando ataques...
          </div>
        ) : (
          <table className="w-full text-sm">
            <thead className="sticky top-0 bg-surface-800 border-b border-surface-700">
              <tr className="text-xs text-slate-500 uppercase tracking-wider">
                <th className="px-4 py-2 text-left">IP Origem</th>
                <th className="px-4 py-2 text-left">Tipo</th>
                <th className="px-4 py-2 text-left">Confiança</th>
                <th className="px-4 py-2 text-left">País</th>
                <th className="px-4 py-2 text-left">Hora</th>
                <th className="px-4 py-2 text-left">Ação</th>
              </tr>
            </thead>
            <tbody>
              {attacks.map((a, i) => (
                <tr
                  key={a.session_id ?? i}
                  className="border-b border-surface-700/50 hover:bg-surface-700/40 transition-colors"
                >
                  <td className="px-4 py-2 font-mono text-cyan-300 text-xs">{a.src_ip}</td>
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
