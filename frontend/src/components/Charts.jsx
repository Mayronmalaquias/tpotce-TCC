import {
  BarChart, Bar, XAxis, YAxis, Tooltip, Legend, ResponsiveContainer,
  PieChart, Pie, Cell,
} from 'recharts'

const COLORS = {
  brute_force:           '#ef4444',
  command_injection:     '#f97316',
  malware_download:      '#a855f7',
  recon:                 '#3b82f6',
  port_scan:             '#14b8a6',
  service_probe:         '#eab308',
  exploit_attempt:       '#ec4899',
  // Classes do modelo Dionaea treinado com captura real.
  connection_flood:      '#6366f1',
  credential_bruteforce: '#10b981',
}

const LABELS = {
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

const KNOWN_TYPES = Object.keys(COLORS)
const FALLBACK_COLOR = '#94a3b8'

const colorOf = t => COLORS[t] ?? FALLBACK_COLOR
const labelOf = t => LABELS[t] ?? t

// Uma classe que o modelo passe a prever mas que ninguem lembrou de cadastrar
// aqui nao pode sumir do grafico em silencio: o conjunto de tipos e a uniao
// entre os conhecidos e os que realmente aparecem nos dados.
function typesToPlot(chartData, typeCounts) {
  const found = new Set(KNOWN_TYPES)
  chartData.forEach(({ attack_type }) => { if (attack_type) found.add(attack_type) })
  Object.keys(typeCounts).forEach(t => found.add(t))
  return [...found]
}

// Converte dados do backend [{hour, attack_type, count}] para
// [{hour, brute_force: N, command_injection: N, ...}]
function buildBarData(raw, types) {
  const map = {}
  const emptyRow = () => Object.fromEntries(types.map(t => [t, 0]))
  raw.forEach(({ hour, attack_type, count }) => {
    const label = hour ? hour.slice(11, 16) : '??'
    if (!map[label]) map[label] = { hour: label, ...emptyRow() }
    if (attack_type in map[label]) map[label][attack_type] += count
  })
  return Object.values(map).slice(-12) // últimas 12 horas
}

function buildPieData(typeCounts, types) {
  return types
    .filter(t => typeCounts[t] > 0)
    .map(t => ({ name: labelOf(t), value: typeCounts[t], color: colorOf(t) }))
}

const tooltipStyle = {
  backgroundColor: '#191d25',
  border: '1px solid #343a46',
  borderRadius: '8px',
  color: '#f1f5f9',
}

export default function Charts({ chartData, typeCounts = {} }) {
  const types    = typesToPlot(chartData ?? [], typeCounts)
  const lastType = types[types.length - 1]
  const barData  = buildBarData(chartData ?? [], types)
  const pieData  = buildPieData(typeCounts, types)
  const hasData  = pieData.length > 0

  return (
    <div className="charts-panel flex flex-col gap-4 h-full">

      {/* Ataques por hora */}
      <div className="bg-surface-800 rounded-xl border border-surface-700 p-4 flex-1">
        <h2 className="font-semibold text-slate-200 mb-3 text-sm">Ataques por Hora (últimas 12h)</h2>
        {barData.length ? <ResponsiveContainer width="100%" height={145}>
          <BarChart data={barData} maxBarSize={30} margin={{ top: 0, right: 10, left: -20, bottom: 0 }}>
            <XAxis dataKey="hour" tick={{ fill: '#94a3b8', fontSize: 11 }} />
            <YAxis tick={{ fill: '#94a3b8', fontSize: 11 }} allowDecimals={false} />
            <Tooltip contentStyle={tooltipStyle} />
            <Legend
              formatter={v => <span style={{ color: '#94a3b8', fontSize: 11 }}>{labelOf(v)}</span>}
            />
            {types.map(t => (
              <Bar key={t} dataKey={t} stackId="a" fill={colorOf(t)} radius={t === lastType ? [3, 3, 0, 0] : [0, 0, 0, 0]} />
            ))}
          </BarChart>
        </ResponsiveContainer> : <div className="chart-empty">Sem ataques nas últimas 12 horas</div>}
      </div>

      {/* Distribuição por tipo */}
      <div className="bg-surface-800 rounded-xl border border-surface-700 p-4 flex-1">
        <h2 className="font-semibold text-slate-200 mb-3 text-sm">Distribuição por Tipo</h2>
        {hasData ? (
          <ResponsiveContainer width="100%" height={145}>
            <PieChart>
              <Pie
                data={pieData}
                cx="50%" cy="50%"
                innerRadius={38} outerRadius={55}
                paddingAngle={3}
                dataKey="value"
              >
                {pieData.map((entry, i) => (
                  <Cell key={i} fill={entry.color} />
                ))}
              </Pie>
              <Tooltip contentStyle={tooltipStyle} />
              <Legend layout="vertical" align="right" verticalAlign="middle" iconType="circle" iconSize={7} wrapperStyle={{ fontSize: 10, maxWidth: '48%' }} />
            </PieChart>
          </ResponsiveContainer>
        ) : (
          <div className="chart-empty">
            Sem dados suficientes
          </div>
        )}
      </div>
    </div>
  )
}
