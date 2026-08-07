import { MapContainer, TileLayer, CircleMarker, Popup } from 'react-leaflet'

const COLORS = {
  brute_force:       '#ef4444',
  command_injection: '#f97316',
  malware_download:  '#a855f7',
  recon:             '#3b82f6',
  port_scan:         '#14b8a6',
  service_probe:     '#eab308',
  exploit_attempt:   '#ec4899',
}

const LABELS = {
  brute_force:       'Brute Force',
  command_injection: 'Cmd Injection',
  malware_download:  'Malware Download',
  recon:             'Reconhecimento',
  port_scan:         'Port Scan',
  service_probe:     'Probe de Serviço',
  exploit_attempt:   'Tentativa de Exploit',
}

const HONEYPOT_LABELS = { cowrie: 'Cowrie', dionaea: 'Dionaea' }

export default function GeoMap({ geoData = [] }) {
  const points = geoData.filter(p => p.latitude && p.longitude)

  return (
    <div className="bg-surface-800 rounded-xl border border-surface-700 overflow-hidden">
      <div className="px-5 py-3 border-b border-surface-700 flex items-center justify-between">
        <h2 className="font-semibold text-slate-200">Origem dos Ataques</h2>
        <span className="text-xs text-slate-500">{points.length} IPs geolocalizados</span>
      </div>

      <MapContainer
        center={[20, 0]}
        zoom={2}
        minZoom={2}
        style={{ height: '340px', width: '100%', background: '#0f172a' }}
        scrollWheelZoom={false}
      >
        <TileLayer
          attribution='&copy; <a href="https://www.openstreetmap.org/copyright">OpenStreetMap</a>'
          url="https://{s}.basemaps.cartocdn.com/dark_all/{z}/{x}/{y}{r}.png"
        />

        {points.map((p, i) => (
          <CircleMarker
            key={`${p.src_ip}-${i}`}
            center={[p.latitude, p.longitude]}
            radius={Math.min(4 + Math.log2(p.count + 1) * 2, 14)}
            pathOptions={{
              color:       COLORS[p.attack_type] ?? '#94a3b8',
              fillColor:   COLORS[p.attack_type] ?? '#94a3b8',
              fillOpacity: 0.75,
              weight:      1,
            }}
          >
            <Popup>
              <div className="text-xs leading-relaxed" style={{ minWidth: 160 }}>
                <p><strong>IP:</strong> {p.src_ip}</p>
                <p><strong>Honeypot:</strong> {HONEYPOT_LABELS[p.honeypot] ?? p.honeypot ?? 'Cowrie'}</p>
                <p><strong>Local:</strong> {[p.city, p.country].filter(Boolean).join(', ') || '—'}</p>
                <p><strong>Tipo:</strong> {LABELS[p.attack_type] ?? p.attack_type}</p>
                <p><strong>Ataques:</strong> {p.count}</p>
                {p.blocked ? <p className="text-red-500 font-semibold">BLOQUEADO</p> : null}
              </div>
            </Popup>
          </CircleMarker>
        ))}
      </MapContainer>
    </div>
  )
}
