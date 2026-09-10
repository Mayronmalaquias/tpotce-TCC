import { useEffect, useRef, useState } from 'react'
import { wsUrl } from '../lib/api'
export function useWebSocket(onMessage) {
  const [connected, setConnected] = useState(false)
  const callback = useRef(onMessage)
  callback.current = onMessage
  useEffect(() => {
    let active = true
    let socket
    let retry
    const connect = () => {
      if (!active) return
      // wsUrl() precisa ser chamado aqui, e nao no carregamento do modulo: a
      // chave da sessao so existe depois do login, e uma URL calculada cedo
      // demais conectaria sem credencial e seria recusada.
      try {
        socket = new WebSocket(wsUrl())
      } catch (err) {
        // O construtor lanca (ex.: mixed content). Sem este catch o erro sobe
        // pelo useEffect, o React desmonta o dashboard inteiro e sobra tela
        // branca — em vez disso, avisa e tenta de novo.
        console.error('[BeeIA] Falha ao abrir WebSocket:', err)
        setConnected(false)
        retry = setTimeout(connect, 5000)
        return
      }
      socket.onopen = () => { if (active) setConnected(true) }
      socket.onmessage = (event) => {
        if (!active) return
        try { callback.current(JSON.parse(event.data)) } catch {}
      }
      socket.onclose = () => {
        if (!active) return
        setConnected(false)
        retry = setTimeout(connect, 5000)
      }
      socket.onerror = () => socket.close()
    }
    connect()
    return () => {
      active = false
      clearTimeout(retry)
      socket?.close()
    }
  }, [])
  return connected
}
