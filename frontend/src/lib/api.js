const SESSION_KEY = 'beeia-session'
let session = (() => {
  try { return JSON.parse(sessionStorage.getItem(SESSION_KEY)) } catch { return null }
})()
export function getSession() { return session }
export function saveSession(key) {
  session = { key }
  try { sessionStorage.setItem(SESSION_KEY, JSON.stringify(session)) } catch {}
}
export function clearSession() {
  session = null
  try { sessionStorage.removeItem(SESSION_KEY) } catch {}
}
export async function authFetch(path, options = {}) {
  const headers = new Headers(options.headers || {})
  if (session?.key) headers.set('X-API-Key', session.key)
  const response = await fetch(path, { ...options, headers })
  if (response.status === 401) {
    clearSession()
    window.dispatchEvent(new Event('beeia:unauthorized'))
  }
  return response
}
export function wsUrl(path = '/ws') {
  const protocol = window.location.protocol === 'https:' ? 'wss:' : 'ws:'
  const base = `${protocol}//${window.location.host}${path}`
  return session?.key ? `${base}?api_key=${encodeURIComponent(session.key)}` : base
}
