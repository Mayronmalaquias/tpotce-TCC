import { Shield, Globe, AlertTriangle, Ban } from 'lucide-react'

const ATTACK_LABELS = {
  brute_force:       'Brute Force',
  command_injection: 'Cmd Injection',
  malware_download:  'Malware Download',
  recon:             'Reconhecimento',
  none:              '—',
}

const ATTACK_COLORS = {
  brute_force:       'text-red-400',
  command_injection: 'text-orange-400',
  malware_download:  'text-purple-400',
  recon:             'text-blue-400',
  none:              'text-slate-400',
}

function Card({ icon: Icon, label, value, sub, color = 'text-cyan-400' }) {
  return (
    <div className="bg-surface-800 rounded-xl p-5 flex items-center gap-4 border border-surface-700">
      <div className={`p-3 rounded-lg bg-surface-700 ${color}`}>
        <Icon size={22} />
      </div>
      <div>
        <p className="text-xs text-slate-400 uppercase tracking-wider">{label}</p>
        <p className="text-2xl font-bold text-slate-100 leading-tight">{value}</p>
        {sub && <p className="text-xs text-slate-500 mt-0.5">{sub}</p>}
      </div>
    </div>
  )
}

export default function Overview({ stats }) {
  const topType    = stats?.top_attack_type || 'none'
  const typeCounts = stats?.attack_type_counts || {}
  const total      = Object.values(typeCounts).reduce((a, b) => a + b, 0)

  return (
    <div className="grid grid-cols-2 xl:grid-cols-4 gap-4">
      <Card
        icon={AlertTriangle}
        label="Total de Ataques"
        value={stats?.total_attacks ?? '—'}
        sub={`${stats?.attacks_last_24h ?? 0} nas últimas 24h`}
        color="text-red-400"
      />
      <Card
        icon={Globe}
        label="IPs Únicos"
        value={stats?.unique_ips ?? '—'}
        sub="origens distintas"
        color="text-cyan-400"
      />
      <Card
        icon={Shield}
        label="Tipo Predominante"
        value={ATTACK_LABELS[topType]}
        sub={topType !== 'none' ? `${typeCounts[topType] ?? 0} de ${total}` : ''}
        color={ATTACK_COLORS[topType]}
      />
      <Card
        icon={Ban}
        label="IPs Bloqueados"
        value={stats?.blocked_count ?? '—'}
        sub="pelo firewall"
        color="text-orange-400"
      />
    </div>
  )
}
