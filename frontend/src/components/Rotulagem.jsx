import { useCallback, useEffect, useMemo, useRef, useState } from 'react'
import { AlertCircle, Check, ChevronLeft, ChevronRight, EyeOff, LoaderCircle, SkipForward, UserRound } from 'lucide-react'
import { authFetch } from '../lib/api'

// Revisao cega: esta tela nunca recebe a previsao do modelo (ver backend/rotulagem.py).
// Cada revisor ve as sessoes numa ordem propria e so os proprios rotulos.

const REVISORES = [
  { id: 'mayron', nome: 'Mayron', coluna: 'revisor 1' },
  { id: 'caio', nome: 'Caio', coluna: 'revisor 2' },
]
const CHAVE_REVISOR = 'beeia-revisor'

const CLASSES = {
  cowrie: [
    ['brute_force', 'Tentativas de login por adivinhação de senha, sem uso do acesso para executar nada.'],
    ['recon', 'Login aceito seguido de comandos que só enumeram o sistema (uname, whoami, /proc/cpuinfo, ls), sem download nem payload.'],
    ['command_injection', 'Login aceito seguido de execução de payload malicioso: reverse shell, script ou binário montado e executado.'],
    ['malware_download', 'Usa wget, curl, tftp ou similar para baixar um arquivo e, em geral, executá-lo.'],
  ],
  dionaea: [
    ['service_probe', 'Uma ou poucas conexões a um serviço, sem login nem payload relevante: sondagem de banner ou varredura de fundo.'],
    ['credential_bruteforce', 'Tentativas de login repetidas em um serviço (MSSQL, FTP, MySQL, SMB…).'],
    ['connection_flood', 'Muitas conexões repetidas do mesmo IP na sessão, sem login nem exploração.'],
    ['port_scan', 'O mesmo IP toca várias portas ou serviços distintos em sequência rápida.'],
    ['exploit_attempt', 'Requisição de exploração de serviço, como DCERPC/SMB, payload grande ou shellcode.'],
    ['malware_download', 'O honeypot recebeu ou baixou um binário oferecido pelo atacante.'],
  ],
}
const ESPECIAIS = [
  ['fora_da_taxonomia', 'Nenhuma classe se aplica', 'O comportamento está claro, mas nenhuma classe acima o descreve.', '0'],
  ['inconclusivo', 'Inconclusivo', 'A evidência não basta para decidir. A sessão sai do cálculo.', 'i'],
]
const NOME_ESPECIAL = { fora_da_taxonomia: 'nenhuma classe', inconclusivo: 'inconclusivo' }

const FEATS = {
  cowrie: [['login_attempts', 'tentativas de login'], ['login_success', 'login aceito'], ['command_count', 'comandos'],
    ['has_recon_commands', 'reconhecimento', true], ['has_wget_curl', 'wget/curl', true], ['has_file_download', 'download', true], ['has_reverse_shell', 'reverse shell', true]],
  dionaea: [['connection_count', 'conexões'], ['unique_ports', 'portas distintas'], ['login_attempts', 'tentativas de login'],
    ['has_file_download', 'download', true], ['has_shellcode', 'shellcode', true]],
}
const EV_COWRIE = {
  'session.connect': 'conexão', 'session.closed': 'encerrada', 'login.failed': 'login recusado', 'login.success': 'login aceito',
  'command.input': 'comando', 'command.failed': 'comando sem efeito', 'client.version': 'cliente', 'client.kex': 'troca de chaves',
  'session.params': 'parâmetros', 'log.closed': 'tty gravado', 'telnet.option': 'opção telnet', 'session.file_download': 'download',
  'session.file_download.failed': 'download falhou', 'session.file_upload': 'upload', 'client.fingerprint': 'chave pública',
  'direct-tcpip.request': 'túnel TCP', 'direct-tcpip.data': 'dados do túnel', 'client.size': 'terminal', 'client.var': 'variável',
}

const hash = texto => { let h = 2166136261; for (const c of texto) { h ^= c.codePointAt(0); h = Math.imul(h, 16777619) } return h >>> 0 }
function embaralha(ids, semente) {
  let a = semente || 1
  const r = () => { a |= 0; a = a + 0x6D2B79F5 | 0; let t = Math.imul(a ^ a >>> 15, 1 | a); t = t + Math.imul(t ^ t >>> 7, 61 | t) ^ t; return ((t ^ t >>> 14) >>> 0) / 4294967296 }
  const out = ids.slice()
  for (let i = out.length - 1; i > 0; i--) { const j = Math.floor(r() * (i + 1)); [out[i], out[j]] = [out[j], out[i]] }
  return out
}
const instante = t => Date.parse(/Z$|[+-]\d\d:\d\d$/.test(t) ? t : `${t}Z`)
const espera = ms => new Promise(r => setTimeout(r, ms))

function evNome(hp, e) {
  if (hp === 'cowrie') return EV_COWRIE[e.ev] || e.ev
  return `${e.protocolo || '?'} :${e.porta ?? '?'}${e.transporte && e.transporte !== 'tcp' ? ` ${e.transporte}` : ''}`
}
function evTom(hp, e) {
  if (hp !== 'cowrie') return e.credentials ? 'login' : ''
  if (e.ev === 'login.success') return 'login'
  if (e.ev === 'command.input') return 'cmd'
  if (String(e.ev).includes('download') || e.url) return 'dl'
  return ''
}
function evDetalhe(hp, e) {
  const p = []
  if (hp === 'cowrie') {
    if (e.username !== undefined || e.password !== undefined) p.push(`${e.username ?? ''} / ${e.password ?? ''}`)
    if (e.input !== undefined) p.push(e.input)
    if (e.url) p.push(`url: ${e.url}`)
    if (e.outfile || e.destfile) p.push(`arquivo: ${e.outfile || e.destfile}`)
    if (e.shasum) p.push(`sha256: ${e.shasum}`)
    if (e.version) p.push(String(e.version))
    if (e.arch) p.push(`arquitetura: ${e.arch}`)
    if (e.dst_port) p.push(`porta ${e.dst_port}`)
    if (e.duration !== undefined) p.push(`duração ${e.duration}s`)
    if (e.size !== undefined && !e.shasum) p.push(`${e.size} bytes`)
    return p.join('\n')
  }
  if (e.credentials) {
    const u = e.credentials.username || [], s = e.credentials.password || []
    u.forEach((x, i) => p.push(`login ${x} / ${s[i] ?? ''}`))
  }
  if (e.ftp?.commands) {
    const c = e.ftp.commands.command || [], a = e.ftp.commands.arguments || []
    p.push(`ftp: ${c.map((x, i) => `${x} ${a[i] ?? ''}`.trim()).join(' · ')}`)
  }
  for (const [k, v] of Object.entries(e)) {
    if (['t', 'protocolo', 'transporte', 'porta', 'credentials', 'ftp'].includes(k)) continue
    p.push(`${k}: ${typeof v === 'object' ? JSON.stringify(v) : v}`)
  }
  return p.join('\n')
}

async function api(path, options) {
  // O limite global da API e de 60 req/min por IP: rotulando rapido, da para encostar nele.
  for (let tentativa = 0; ; tentativa++) {
    const res = await authFetch(path, { signal: AbortSignal.timeout(20000), ...options })
    if (res.ok) return res.json()
    const podeRepetir = res.status === 429 || res.status >= 500
    if (!podeRepetir || tentativa >= 3) {
      let detalhe = ''
      try { detalhe = (await res.json()).detail } catch {}
      throw new Error(detalhe || `Erro ${res.status}`)
    }
    await espera(res.status === 429 ? 4000 * (tentativa + 1) : 1000)
  }
}

function EscolhaRevisor({ onEscolher, progresso }) {
  return (
    <section className="rot-escolha">
      <div className="eyebrow">REVISÃO CEGA · 200 SESSÕES</div>
      <h2>Quem está rotulando?</h2>
      <p>Cada um entra só com o próprio nome. Os rótulos de um nunca aparecem para o outro, e a ordem das sessões é diferente para cada revisor.</p>
      <div className="rot-revisores">
        {REVISORES.map(r => (
          <button key={r.id} className="rot-revisor" onClick={() => onEscolher(r.id)}>
            <UserRound size={22} />
            <span><strong>{r.nome}</strong><small>{r.coluna}{progresso ? ` · ${progresso.revisores[r.id] ?? 0}/${progresso.total} rotuladas` : ''}</small></span>
            <ChevronRight size={18} />
          </button>
        ))}
      </div>
      <ul className="rot-regras">
        <li><strong>Enquanto não terminar, não abra Ataques, Mapa nem o detalhe de IP.</strong> Essas telas mostram a classe que o modelo previu.</li>
        <li>Não comentem sessões entre vocês antes de os dois terminarem. Combinar critérios gerais antes de começar pode e é recomendado.</li>
        <li>Decida pelos eventos. Se as contagens do topo divergirem deles, vale o evento; anote na observação.</li>
        <li><strong>Nenhuma classe se aplica</strong>: o comportamento está claro, mas o modelo não tem classe para ele (ex.: conexão aberta e fechada sem login). <strong>Inconclusivo</strong>: não dá para decidir. Não force rótulo.</li>
      </ul>
    </section>
  )
}

export default function Rotulagem() {
  const [revisor, setRevisor] = useState(() => { try { return sessionStorage.getItem(CHAVE_REVISOR) } catch { return null } })
  const [sessoes, setSessoes] = useState(null)
  const [rotulos, setRotulos] = useState({})
  const [carregado, setCarregado] = useState(false)
  const [idx, setIdx] = useState(0)
  const [filtro, setFiltro] = useState('todas')
  const [salvando, setSalvando] = useState(0)
  const [erro, setErro] = useState('')
  const [progresso, setProgresso] = useState(null)
  const fichaRef = useRef(null)
  const timersObs = useRef({})

  useEffect(() => {
    api('/api/rotulagem/sessoes').then(d => setSessoes(d.sessoes)).catch(e => setErro(e.message))
    api('/api/rotulagem/progresso').then(setProgresso).catch(() => {})
  }, [])

  const ordem = useMemo(() => {
    if (!sessoes) return []
    const ids = sessoes.map(s => s.id)
    return revisor ? embaralha(ids, hash(revisor)) : ids
  }, [sessoes, revisor])
  const porId = useMemo(() => Object.fromEntries((sessoes || []).map(s => [s.id, s])), [sessoes])
  const rotuloDe = useCallback(id => rotulos[id]?.rotulo || '', [rotulos])
  const feitas = ordem.filter(id => rotuloDe(id)).length

  useEffect(() => {
    if (!revisor || !sessoes) return
    let cancelado = false
    setCarregado(false)
    api(`/api/rotulagem/${revisor}`).then(d => {
      if (cancelado) return
      setRotulos(d.rotulos || {})
      const primeira = ordem.findIndex(id => !d.rotulos?.[id]?.rotulo)
      setIdx(primeira < 0 ? 0 : primeira)
      setCarregado(true)
    }).catch(e => { if (!cancelado) setErro(e.message) })
    return () => { cancelado = true }
  }, [revisor, sessoes, ordem])

  const escolhe = id => { try { sessionStorage.setItem(CHAVE_REVISOR, id) } catch {} setRevisor(id) }
  const troca = () => { try { sessionStorage.removeItem(CHAVE_REVISOR) } catch {} setRevisor(null); setRotulos({}); setCarregado(false); api('/api/rotulagem/progresso').then(setProgresso).catch(() => {}) }

  const grava = useCallback(async (id, corpo) => {
    setSalvando(n => n + 1)
    try {
      await api(`/api/rotulagem/${revisor}/${encodeURIComponent(id)}`, {
        method: 'PUT', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(corpo),
      })
      setErro('')
    } catch (e) {
      setErro(`O último rótulo não foi salvo (${e.message}). Ele continua marcado na tela; clique de novo para tentar.`)
    } finally {
      setSalvando(n => n - 1)
    }
  }, [revisor])

  const marca = useCallback((id, rotulo) => {
    const novo = rotuloDe(id) === rotulo ? '' : rotulo
    setRotulos(r => ({ ...r, [id]: { ...(r[id] || {}), rotulo: novo } }))
    grava(id, { rotulo: novo })
  }, [rotuloDe, grava])

  const anota = (id, texto) => {
    setRotulos(r => ({ ...r, [id]: { ...(r[id] || {}), observacao: texto } }))
    clearTimeout(timersObs.current[id])
    timersObs.current[id] = setTimeout(() => grava(id, { observacao: texto }), 800)
  }

  const vai = useCallback(i => setIdx(Math.max(0, Math.min(ordem.length - 1, i))), [ordem.length])
  const proximaPendente = useCallback(() => {
    for (let k = 1; k <= ordem.length; k++) {
      const i = (idx + k) % ordem.length
      if (!rotuloDe(ordem[i])) return vai(i)
    }
  }, [idx, ordem, rotuloDe, vai])

  useEffect(() => { fichaRef.current?.scrollIntoView({ block: 'nearest' }) }, [idx])

  const atual = carregado ? porId[ordem[idx]] : null

  useEffect(() => {
    if (!atual) return
    const aoTeclar = ev => {
      if (ev.target.closest?.('textarea, input, select') || ev.ctrlKey || ev.metaKey || ev.altKey) return
      const classes = CLASSES[atual.honeypot] || []
      if (/^[1-9]$/.test(ev.key) && Number(ev.key) <= classes.length) marca(atual.id, classes[Number(ev.key) - 1][0])
      else if (ev.key === '0') marca(atual.id, 'fora_da_taxonomia')
      else if (ev.key === 'i' || ev.key === 'I') marca(atual.id, 'inconclusivo')
      else if (ev.key === 'ArrowRight' || ev.key === 'j') vai(idx + 1)
      else if (ev.key === 'ArrowLeft' || ev.key === 'k') vai(idx - 1)
      else if (ev.key === 'n') proximaPendente()
      else return
      ev.preventDefault()
    }
    window.addEventListener('keydown', aoTeclar)
    return () => window.removeEventListener('keydown', aoTeclar)
  }, [atual, idx, marca, vai, proximaPendente])

  if (!sessoes) {
    return erro
      ? <div className="notice error" role="alert"><AlertCircle size={18} /><span>Não foi possível carregar a amostra: {erro}</span></div>
      : <div className="notice" role="status"><LoaderCircle size={17} className="animate-spin" /> Carregando a amostra de avaliação...</div>
  }
  if (!revisor) return <EscolhaRevisor onEscolher={escolhe} progresso={progresso} />
  if (!atual) {
    return erro
      ? <div className="notice error" role="alert"><AlertCircle size={18} /><span>{erro}</span></div>
      : <div className="notice" role="status"><LoaderCircle size={17} className="animate-spin" /> Carregando seus rótulos...</div>
  }

  const nome = REVISORES.find(r => r.id === revisor)?.nome
  const visiveis = ordem.filter(id => filtro === 'todas' ? true : filtro === 'pendentes' ? !rotuloDe(id) : porId[id].honeypot === filtro)
  const ini = atual.eventos.length ? instante(atual.eventos[0].t) : instante(atual.timestamp)
  const contagem = {}
  atual.eventos.forEach(e => { const k = evNome(atual.honeypot, e); contagem[k] = (contagem[k] || 0) + 1 })
  const escolhido = rotuloDe(atual.id)

  return (
    <div className="rot">
      <div className="rot-barra">
        <div className="rot-quem"><UserRound size={16} /> Rotulando como <strong>{nome}</strong><button onClick={troca}>trocar</button></div>
        <div className="rot-progresso" role="progressbar" aria-valuemin={0} aria-valuemax={ordem.length} aria-valuenow={feitas} aria-label="Sessões rotuladas">
          <span className="rot-trilho"><i style={{ width: `${(feitas / ordem.length) * 100}%` }} /></span>
          <span className="rot-num">{feitas}/{ordem.length}</span>
        </div>
        <span className={`rot-salvo ${salvando ? 'ocupado' : ''}`} role="status">{salvando ? <><LoaderCircle size={13} className="animate-spin" /> Salvando</> : <><Check size={13} /> Salvo</>}</span>
      </div>
      <div className="notice rot-aviso"><EyeOff size={17} /><span>Revisão cega: a previsão do modelo não aparece aqui. Não abra as outras telas do painel até terminar.</span></div>
      {erro && <div className="notice error" role="alert"><AlertCircle size={18} /><span>{erro}</span></div>}

      <div className="rot-mesa">
        <nav className="rot-fila" aria-label="Fila de sessões">
          <div className="rot-filtros">
            {[['todas', 'Todas'], ['pendentes', 'Sem rótulo'], ['cowrie', 'Cowrie'], ['dionaea', 'Dionaea']].map(([v, t]) =>
              <button key={v} aria-pressed={filtro === v} onClick={() => setFiltro(v)}>{t}</button>)}
          </div>
          <ol>
            {visiveis.map(id => {
              const i = ordem.indexOf(id), r = rotuloDe(id)
              return (
                <li key={id}>
                  <button aria-current={i === idx} onClick={() => vai(i)}>
                    <span className="rot-n">{String(i + 1).padStart(3, '0')}</span>
                    <span className={`rot-mk ${r ? (NOME_ESPECIAL[r] ? 'especial' : 'feito') : ''}`} />
                    <span className="rot-rot"><b>{porId[id].honeypot}</b>{r ? ` · ${NOME_ESPECIAL[r] || r}` : ''}</span>
                  </button>
                </li>
              )
            })}
          </ol>
        </nav>

        <article className="rot-ficha" ref={fichaRef} aria-label="Sessão em revisão">
          <section>
            <div className="rot-id">
              <h2>Sessão {idx + 1} de {ordem.length}</h2>
              <span className={`rot-hp ${atual.honeypot}`}>{atual.honeypot}</span>
              <span className="rot-sid">{atual.id}</span>
            </div>
            <label className="rot-salto"><span>Ir para</span>
              <select value={idx} onChange={ev => vai(Number(ev.target.value))}>
                {ordem.map((id, i) => <option key={id} value={i}>{i + 1} · {porId[id].honeypot}{rotuloDe(id) ? ' ✓' : ''}</option>)}
              </select>
            </label>
            <dl className="rot-meta">
              <div><dt>Início (UTC)</dt><dd>{atual.timestamp.replace('T', ' ').replace(/\.\d+Z?$/, '')}</dd></div>
              <div><dt>Duração</dt><dd>{Number(atual.f.session_duration_s || 0).toFixed(2)} s</dd></div>
              <div><dt>Origem</dt><dd>{atual.src_ip}{atual.country ? ` · ${atual.country}` : ''}</dd></div>
              {atual.protocol && <div><dt>Serviço</dt><dd>{atual.protocol}</dd></div>}
            </dl>
            <div className="rot-feats">
              {FEATS[atual.honeypot].map(([k, nomeF, binaria]) => {
                const v = atual.f[k]
                if (v === undefined || v === '') return null
                if (binaria) return Number(v) ? <span key={k} className="rot-feat on">{nomeF}</span> : null
                return <span key={k} className="rot-feat">{nomeF} <b>{v}</b></span>
              })}
            </div>
            <p className="rot-nota">Contagens calculadas pelo pipeline. Se divergirem dos eventos abaixo, vale o evento.</p>
          </section>

          <section>
            <h3>{atual.truncado ? `Eventos · ${atual.total} no log, mostrando os ${atual.eventos.length} primeiros` : `Eventos · ${atual.total}`}</h3>
            <div className="rot-resumo">
              {Object.entries(contagem).sort((a, b) => b[1] - a[1]).map(([k, v]) => <span key={k}>{k} <b>×{v}</b></span>)}
            </div>
            <div className="rot-eventos" tabIndex={0} aria-label="Eventos da sessão">
              <table>
                <thead><tr><th>Tempo</th><th>Evento</th><th>Detalhe</th></tr></thead>
                <tbody>
                  {atual.eventos.map((e, i) => (
                    <tr key={i}>
                      <td className="t" title={e.t}>+{((instante(e.t) - ini) / 1000).toFixed(3)} s</td>
                      <td className={`ev ${evTom(atual.honeypot, e)}`}>{evNome(atual.honeypot, e)}</td>
                      <td className="det">{evDetalhe(atual.honeypot, e)}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          </section>

          <section className="rot-decisao">
            <h3>Sua decisão</h3>
            <div className="rot-classes">
              {CLASSES[atual.honeypot].map(([id, def], i) => (
                <button key={id} className="rot-classe" aria-pressed={escolhido === id} onClick={() => marca(atual.id, id)}>
                  <kbd>{i + 1}</kbd><span className="nome mono">{id}</span><span className="def">{def}</span>
                </button>
              ))}
            </div>
            <div className="rot-classes">
              {ESPECIAIS.map(([id, nomeE, def, tecla]) => (
                <button key={id} className="rot-classe especial" aria-pressed={escolhido === id} onClick={() => marca(atual.id, id)}>
                  <kbd>{tecla}</kbd><span className="nome">{nomeE}</span><span className="def">{def}</span>
                </button>
              ))}
            </div>
            <label className="rot-obs">
              <span>Observação (opcional): o que pesou na decisão, divergências entre contagem e evento</span>
              <textarea value={rotulos[atual.id]?.observacao || ''} maxLength={2000} onChange={ev => anota(atual.id, ev.target.value)} />
            </label>
            <div className="rot-nav">
              <div>
                <button className="secondary-button" onClick={() => vai(idx - 1)} disabled={idx === 0}><ChevronLeft size={15} /> Anterior</button>
                <button className="secondary-button" onClick={() => vai(idx + 1)} disabled={idx >= ordem.length - 1}>Próxima <ChevronRight size={15} /></button>
                <button className="primary-button" onClick={proximaPendente} disabled={feitas === ordem.length}><SkipForward size={15} /> Próxima sem rótulo</button>
              </div>
              <span className="rot-atalhos"><kbd>1</kbd>–<kbd>{CLASSES[atual.honeypot].length}</kbd> classe · <kbd>0</kbd> nenhuma · <kbd>i</kbd> inconclusivo · <kbd>←</kbd><kbd>→</kbd> navegar · <kbd>n</kbd> próxima sem rótulo</span>
            </div>
          </section>
        </article>
      </div>
    </div>
  )
}
