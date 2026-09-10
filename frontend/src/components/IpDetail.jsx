import { useEffect, useState } from 'react'
import { X, ShieldOff, ShieldCheck, Globe, Clock, Activity, Terminal, Download, Radar, KeyRound, LoaderCircle, AlertCircle } from 'lucide-react'
import { authFetch } from '../lib/api'

const TYPE_LABELS = {
  brute_force:           'Brute Force',
  command_injection:     'Cmd Injection',
  malware_download:      'Malware Download',
  recon:                 'Reconhecimento',
  port_scan:             'Port Scan',
  service_probe:         'Probe de Serviço',
  exploit_attempt:       'Tentativa de Exploit',
  connection_flood:      'Flood de Conexões',
  credential_bruteforce: 'Brute Force de Credenciais',
}

const HONEYPOT_LABELS = { cowrie: 'Cowrie', dionaea: 'Dionaea' }

// O que o IP efetivamente fez, em vez de so o rotulo do classificador.
// `chave` casa com as colunas agregadas por get_ip_detail.
const COMPORTAMENTOS = [
  { chave: 'has_reverse_shell',  icone: Terminal, texto: 'Tentou abrir shell reverso' },
  { chave: 'has_wget_curl',      icone: Download, texto: 'Usou wget/curl para baixar algo' },
  { chave: 'has_file_download',  icone: Download, texto: 'Baixou arquivo' },
  { chave: 'has_recon_commands', icone: Radar,    texto: 'Rodou comandos de reconhecimento' },
  { chave: 'has_shellcode',      icone: Activity, texto: 'Enviou shellcode' },
]

const quando = valor => {
  if (!valor) return '—'
  const data = new Date(valor)
  return Number.isNaN(data.getTime()) ? valor : data.toLocaleString('pt-BR')
}

const duracao = segundos => {
  const total = Math.round(Number(segundos) || 0)
  if (total < 60) return `${total}s`
  if (total < 3600) return `${Math.floor(total / 60)}min ${total % 60}s`
  return `${Math.floor(total / 3600)}h ${Math.floor((total % 3600) / 60)}min`
}

function Metrica({ icone: Icone, rotulo, valor }) {
  return (
    <div className="ip-metric">
      <span className="ip-metric-icon"><Icone size={16} /></span>
      <div><strong>{valor}</strong><small>{rotulo}</small></div>
    </div>
  )
}

export default function IpDetail({ ip, onClose, onBlock }) {
  const [detalhe, setDetalhe] = useState(null)
  const [erro, setErro] = useState('')
  const [carregando, setCarregando] = useState(true)
  const [bloqueando, setBloqueando] = useState(false)

  useEffect(() => {
    if (!ip) return
    let cancelado = false
    setCarregando(true)
    setErro('')
    setDetalhe(null)

    authFetch(`/api/ip/${encodeURIComponent(ip)}`)
      .then(async resposta => {
        if (resposta.status === 404) throw new Error('Nenhum registro para este IP.')
        if (!resposta.ok) throw new Error('Não foi possível carregar o detalhamento.')
        return resposta.json()
      })
      .then(dados => { if (!cancelado) setDetalhe(dados) })
      .catch(err => { if (!cancelado) setErro(err.message) })
      .finally(() => { if (!cancelado) setCarregando(false) })

    return () => { cancelado = true }
  }, [ip])

  useEffect(() => {
    const aoTeclar = evento => { if (evento.key === 'Escape') onClose() }
    window.addEventListener('keydown', aoTeclar)
    return () => window.removeEventListener('keydown', aoTeclar)
  }, [onClose])

  if (!ip) return null

  const resumo = detalhe?.resumo
  const vistos = COMPORTAMENTOS.filter(c => resumo?.[c.chave])

  return (
    <div className="ip-overlay" role="dialog" aria-modal="true" aria-label={`Detalhes do IP ${ip}`} onClick={onClose}>
      <div className="ip-panel" onClick={evento => evento.stopPropagation()}>
        <header className="ip-panel-head">
          <div>
            <div className="eyebrow">O QUE ESTE IP TENTOU</div>
            <h2>{ip}</h2>
            {resumo && (
              <p className="ip-place">
                <Globe size={14} />
                {[resumo.city, resumo.country].filter(Boolean).join(', ') || 'Origem não identificada'}
              </p>
            )}
          </div>
          <button className="ip-close" onClick={onClose} aria-label="Fechar detalhamento"><X size={20} /></button>
        </header>

        {carregando && <div className="notice" role="status"><LoaderCircle size={17} className="animate-spin" /> Carregando o histórico deste IP...</div>}
        {erro && <div className="notice error" role="alert"><AlertCircle size={17} /><span>{erro}</span></div>}

        {resumo && (
          <div className="ip-panel-body">
            <div className="ip-metrics">
              <Metrica icone={Activity}  rotulo="sessões"          valor={resumo.total_sessoes} />
              <Metrica icone={KeyRound}  rotulo="tentativas login" valor={resumo.login_attempts ?? 0} />
              <Metrica icone={Terminal}  rotulo="comandos"         valor={resumo.command_count ?? 0} />
              <Metrica icone={Clock}     rotulo="tempo total"      valor={duracao(resumo.tempo_total_s)} />
            </div>

            {resumo.login_success > 0 && (
              <div className="notice error" role="alert">
                <AlertCircle size={17} />
                <span><strong>Conseguiu autenticar {resumo.login_success}x.</strong> O honeypot aceita credenciais de propósito — isso mostra o que o atacante faria depois de entrar.</span>
              </div>
            )}

            <section className="ip-section">
              <h3>Tipos de ataque classificados</h3>
              <ul className="ip-type-list">
                {detalhe.por_tipo.map(t => (
                  <li key={t.attack_type}>
                    <span>{TYPE_LABELS[t.attack_type] ?? t.attack_type}</span>
                    <span className="ip-type-count">{t.count}x<small>até {Math.round((t.max_confidence ?? 0) * 100)}% conf.</small></span>
                  </li>
                ))}
              </ul>
            </section>

            <section className="ip-section">
              <h3>O que ele fez</h3>
              {vistos.length ? (
                <ul className="ip-behaviour">
                  {vistos.map(({ chave, icone: Icone, texto }) => (
                    <li key={chave}><Icone size={15} /> {texto}</li>
                  ))}
                </ul>
              ) : (
                <p className="ip-empty">Só abriu conexões — nenhum comando, download ou shellcode registrado.</p>
              )}
              <p className="ip-note">
                {detalhe.por_honeypot.map(h => `${HONEYPOT_LABELS[h.honeypot] ?? h.honeypot}: ${h.count}`).join(' · ')}
                {resumo.unique_ports > 0 && ` · ${resumo.unique_ports} portas distintas`}
              </p>
            </section>

            <section className="ip-section">
              <h3>Sessões {detalhe.sessoes_truncadas && <small>(mostrando as {detalhe.sessoes.length} mais recentes de {resumo.total_sessoes})</small>}</h3>
              <div className="ip-table-scroll">
                <table className="ip-table">
                  <thead><tr><th>Quando</th><th>Honeypot</th><th>Tipo</th><th>Conf.</th><th>Logins</th><th>Cmds</th></tr></thead>
                  <tbody>
                    {detalhe.sessoes.map((s, i) => (
                      <tr key={s.session_id ?? i}>
                        <td>{quando(s.timestamp)}</td>
                        <td>{HONEYPOT_LABELS[s.honeypot] ?? s.honeypot}</td>
                        <td>{TYPE_LABELS[s.attack_type] ?? s.attack_type}</td>
                        <td>{Math.round((s.confidence ?? 0) * 100)}%</td>
                        <td>{s.login_attempts ?? 0}</td>
                        <td>{s.command_count ?? 0}</td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
              <p className="ip-note">Primeira: {quando(resumo.primeira)} · Última: {quando(resumo.ultima)}</p>
            </section>

            <footer className="ip-panel-foot">
              {resumo.blocked ? (
                <span className="ip-blocked"><ShieldOff size={16} /> IP já bloqueado no firewall</span>
              ) : (
                <button
                  className="primary-button"
                  disabled={bloqueando || !onBlock}
                  onClick={async () => { setBloqueando(true); try { await onBlock(ip) } finally { setBloqueando(false) } }}
                >
                  {bloqueando ? <><LoaderCircle size={16} className="animate-spin" /> Bloqueando...</> : <><ShieldCheck size={16} /> Bloquear este IP</>}
                </button>
              )}
            </footer>
          </div>
        )}
      </div>
    </div>
  )
}
