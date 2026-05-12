import {
  BarChart, Bar, XAxis, YAxis, Tooltip, Legend, ResponsiveContainer,
  PieChart, Pie, Cell,
} from 'recharts'

const COLORS = {
  brute_force:       '#ef4444',
  command_injection: '#f97316',
  malware_download:  '#a855f7',
  recon:             '#3b82f6',
}

const LABELS = {
  brute_force:       'Brute Force',
  command_injection: 'Cmd Injection',
  malware_download:  'Malware DL',
  recon:             'Recon',
}

const ATTACK_TYPES = Object.keys(COLORS)

// Converte dados do backend [{hour, attack_type, count}] para
// [{hour, brute_force: N, command_injection: N, ...}]
function buildBarData(raw) {
  const map = {}
  raw.forEach(({ hour, attack_type, count }) => {
    const label = hour ? hour.slice(11, 16) : '??'
    if (!map[label]) map[label] = { hour: label, brute_force: 0, command_injection: 0, malware_download: 0, recon: 0 }
    if (attack_type in map[label]) map[label][attack_type] += count
  })
  return Object.values(map).slice(-12) // últimas 12 horas
}

function buildPieData(typeCounts) {
  return ATTACK_TYPES
    .filter(t => typeCounts[t] > 0)
    .map(t => ({ name: LABELS[t], value: typeCounts[t], color: COLORS[t] }))
}

const tooltipStyle = {
  backgroundColor: '#1e293b',
  border: '1px solid #334155',
  borderRadius: '8px',
  color: '#f1f5f9',
}

export default function Charts({ chartData, typeCounts = {} }) {
  const barData  = buildBarData(chartData ?? [])
  const pieData  = buildPieData(typeCounts)
  const hasData  = pieData.length > 0

  return (
    <div className="flex flex-col gap-4 h-full">

      {/* Ataques por hora */}
      <div className="bg-surface-800 rounded-xl border border-surface-700 p-4 flex-1">
        <h2 className="font-semibold text-slate-200 mb-3 text-sm">Ataques por Hora (últimas 12h)</h2>
        <ResponsiveContainer width="100%" height={180}>
          <BarChart data={barData} margin={{ top: 0, right: 10, left: -20, bottom: 0 }}>
            <XAxis dataKey="hour" tick={{ fill: '#94a3b8', fontSize: 11 }} />
            <YAxis tick={{ fill: '#94a3b8', fontSize: 11 }} allowDecimals={false} />
            <Tooltip contentStyle={tooltipStyle} />
            <Legend
              formatter={v => <span style={{ color: '#94a3b8', fontSize: 11 }}>{LABELS[v] ?? v}</span>}
            />
            {ATTACK_TYPES.map(t => (
              <Bar key={t} dataKey={t} stackId="a" fill={COLORS[t]} radius={t === 'recon' ? [3, 3, 0, 0] : [0, 0, 0, 0]} />
            ))}
          </BarChart>
        </ResponsiveContainer>
      </div>

      {/* Distribuição por tipo */}
      <div className="bg-surface-800 rounded-xl border border-surface-700 p-4 flex-1">
        <h2 className="font-semibold text-slate-200 mb-3 text-sm">Distribuição por Tipo</h2>
        {hasData ? (
          <ResponsiveContainer width="100%" height={180}>
            <PieChart>
              <Pie
                data={pieData}
                cx="50%" cy="50%"
                innerRadius={45} outerRadius={75}
                paddingAngle={3}
                dataKey="value"
                label={({ name, percent }) => `${name} ${(percent * 100).toFixed(0)}%`}
                labelLine={false}
              >
                {pieData.map((entry, i) => (
                  <Cell key={i} fill={entry.color} />
                ))}
              </Pie>
              <Tooltip contentStyle={tooltipStyle} />
            </PieChart>
          </ResponsiveContainer>
        ) : (
          <div className="flex items-center justify-center h-40 text-slate-500 text-sm">
            Sem dados suficientes
          </div>
        )}
      </div>
    </div>
  )
}
