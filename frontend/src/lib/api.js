// Ponto único de acesso à API key do backend (BEEIA_API_KEY no backend,
// VITE_API_KEY no frontend). Evita duplicar essa lógica em App.jsx,
// Report.jsx e useWebSocket.js.
//
// Nota de segurança: como isso roda no navegador, a chave embutida no bundle
// é visível para qualquer um que acesse a página — ela não substitui uma
// camada de autenticação de acesso ao próprio dashboard (ver
// md-usotcc/proteger-dashboard.md). É defesa em profundidade contra bots e
// acesso direto à API, não um segredo de verdade.

export const API_KEY = import.meta.env.VITE_API_KEY || ''

export function authFetch(path, options = {}) {
  const headers = new Headers(options.headers || {})
  if (API_KEY) headers.set('X-API-Key', API_KEY)
  return fetch(path, { ...options, headers })
}

export function wsUrl(path = '/ws') {
  const base = `ws://${window.location.host}${path}`
  return API_KEY ? `${base}?api_key=${encodeURIComponent(API_KEY)}` : base
}
