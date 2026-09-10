import { useState } from 'react'
import { ArrowRight, ShieldCheck, Eye, EyeOff, KeyRound, User, Radar, Activity, Hexagon, LoaderCircle, AlertCircle } from 'lucide-react'

export function Brand() {
  return <div className="brand"><span className="brand-symbol"><Hexagon size={31} strokeWidth={1.7} /><span /></span><span>Bee<span className="brand-accent">IA</span><small>THREAT INTELLIGENCE</small></span></div>
}

export default function Login({ onLogin }) {
  const [username, setUsername] = useState('')
  const [password, setPassword] = useState('')
  const [visible, setVisible] = useState(false)
  const [loading, setLoading] = useState(false)
  const [error, setError] = useState('')

  const offline = err => err instanceof TypeError || err.name === 'TimeoutError'

  // A senha vai para o servidor e volta a chave da API. Ela nunca e guardada
  // no navegador — o que fica na sessao e a chave, como antes.
  async function signIn(event) {
    event.preventDefault()
    setLoading(true)
    setError('')
    try {
      const response = await fetch('/api/login', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ username: username.trim(), password }),
        signal: AbortSignal.timeout(20000),
      })
      if (response.status === 401) throw new Error('Usuário ou senha inválidos.')
      if (response.status === 429) throw new Error('Muitas tentativas seguidas. Espere alguns minutos e tente de novo.')
      if (response.status === 503) throw new Error('O login ainda não foi configurado neste servidor.')
      if (!response.ok) throw new Error('O serviço está indisponível. Tente novamente em instantes.')
      const { key } = await response.json()
      if (!key) throw new Error('O servidor não devolveu uma chave de acesso válida.')
      onLogin(key)
    } catch (err) {
      setError(offline(err) ? 'Não foi possível conectar ao servidor. Verifique se o backend está disponível.' : err.message)
    } finally { setLoading(false) }
  }

  // Ambiente local sem BEEIA_API_KEY: entra sem credencial nenhuma.
  async function signInLocal() {
    setLoading(true)
    setError('')
    try {
      const response = await fetch('/api/stats', { signal: AbortSignal.timeout(15000) })
      if (response.status === 401 || response.status === 403) throw new Error('Este ambiente exige usuário e senha.')
      if (!response.ok) throw new Error('O serviço está indisponível. Tente novamente em instantes.')
      const stats = await response.json()
      if (typeof stats.total_attacks !== 'number') throw new Error('Não foi possível validar a resposta do servidor.')
      onLogin('')
    } catch (err) {
      setError(offline(err) ? 'Não foi possível conectar ao servidor. Verifique se o backend está disponível.' : err.message)
    } finally { setLoading(false) }
  }

  return <div className="login-page">
    <section className="login-story">
      <Brand />
      <div className="login-message"><div className="eyebrow"><span className="small-dot" /> INTELIGÊNCIA QUE PROTEGE</div>
        <h1>Antecipe ameaças.<br />Entenda cada <em>ataque.</em></h1>
        <p>Transforme os sinais dos seus honeypots em inteligência para proteger o que importa.</p>
      </div>
      <div className="radar-art" aria-hidden="true"><div className="radar-grid" /><div className="radar-ring ring-one" /><div className="radar-ring ring-two" /><div className="radar-ring ring-three" /><div className="radar-axis axis-h" /><div className="radar-axis axis-v" /><div className="radar-sweep" /><span className="radar-point point-one" /><span className="radar-point point-two" /><span className="radar-point point-three" /><div className="radar-center"><ShieldCheck size={39} strokeWidth={1.4} /></div><div className="radar-tag"><Activity size={14} /> VISIBILIDADE EM TEMPO REAL</div></div>
      <div className="login-features"><span><Radar size={17} /> Monitoramento contínuo</span><span><ShieldCheck size={17} /> Análise com IA</span></div>
      <footer>BeeIA <span>Plataforma de análise de ameaças</span></footer>
    </section>
    <section className="login-form-side">
      <div className="login-form-wrap"><div className="login-icon"><KeyRound size={24} /></div><div className="eyebrow">ACESSO AO PAINEL</div><h2>Bem-vindo de volta.</h2><p className="login-intro">Entre para acompanhar a segurança do seu ambiente.</p>
        <form onSubmit={signIn}>
          <label htmlFor="login-user">Usuário</label>
          <div className="login-input"><User size={18} /><input id="login-user" type="text" value={username} onChange={event => setUsername(event.target.value)} placeholder="Seu usuário" autoComplete="username" required disabled={loading} autoFocus /></div>
          <label htmlFor="login-password">Senha</label>
          <div className="login-input"><KeyRound size={18} /><input id="login-password" type={visible ? 'text' : 'password'} value={password} onChange={event => setPassword(event.target.value)} placeholder="Sua senha" autoComplete="current-password" required disabled={loading} aria-describedby="password-help" /><button type="button" onClick={() => setVisible(!visible)} aria-label={visible ? 'Ocultar senha' : 'Mostrar senha'} aria-pressed={visible}>{visible ? <EyeOff size={18} /> : <Eye size={18} />}</button></div>
          <p id="password-help" className="field-help">Use as credenciais fornecidas pelo administrador do ambiente.</p>
          {error && <div className="notice error" role="alert"><AlertCircle size={17} /><span>{error}</span></div>}
          <button className="primary-button login-submit" disabled={loading}>{loading ? <><LoaderCircle className="animate-spin" size={18} /> Validando acesso...</> : <>Entrar no painel <ArrowRight size={18} /></>}</button>
        </form>
        <div className="login-divider"><span>Ambiente de desenvolvimento</span></div>
        <button className="local-login" disabled={loading} onClick={signInLocal}>Acessar ambiente local <ArrowRight size={15} /></button>
        <p className="local-help">Disponível apenas quando o servidor permite acesso sem credenciais.</p>
        <div className="login-note"><ShieldCheck size={18} /><span>Sua senha não fica guardada no navegador — só o acesso desta sessão.</span></div>
      </div><div className="login-bottom">HONEYPOT MONITORING <span>POWERED BY BeeIA</span></div>
    </section>
  </div>
}
