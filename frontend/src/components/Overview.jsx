import { Shield, Globe, AlertTriangle, Ban } from 'lucide-react'

const ATTACK_LABELS = {
  brute_force:           'Brute Force',
  command_injection:     'Cmd Injection',
  malware_download:      'Malware Download',
  recon:                 'Reconhecimento',
  port_scan:             'Port Scan',
  service_probe:         'Probe de Serviço',
  exploit_attempt:       'Tentativa de Exploit',
  // Classes do modelo Dionaea treinado com captura real.
  connection_flood:      'Flood de Conexões',
  credential_bruteforce: 'Brute Force de Credenciais',
  none:                  '—',
}

const ATTACK_COLORS = {
  brute_force:           'text-red-400',
  command_injection:     'text-orange-400',
  malware_download:      'text-purple-400',
  recon:                 'text-blue-400',
  port_scan:             'text-teal-400',
  service_probe:         'text-yellow-400',
  exploit_attempt:       'text-pink-400',
  connection_flood:      'text-indigo-400',
  credential_bruteforce: 'text-emerald-400',
  none:                  'text-slate-400',
}

function Card({ icon: Icon, label, value, sub, color = 'text-cyan-400' }) {
  return (
    <div className="metric-card">
      <div className={`metric-icon ${color}`}>
        <Icon size={22} />
      </div>
      <div>
        <p className="text-xs text-slate-400 uppercase tracking-wider">{label}</p>
        <p className="metric-value">{typeof value === 'number' ? value.toLocaleString('pt-BR') : value}</p>
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
    <div className="metrics-grid">
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
