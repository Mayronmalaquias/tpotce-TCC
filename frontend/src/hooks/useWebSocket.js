import { useEffect, useRef, useState } from 'react'
import { wsUrl } from '../lib/api'

const WS_URL = wsUrl()

export function useWebSocket(onMessage) {
  const [connected, setConnected] = useState(false)
  const ws = useRef(null)
  const retryRef = useRef(null)

  const connect = () => {
    if (ws.current?.readyState === WebSocket.OPEN) return

    // O construtor lanca (ex.: mixed content) — sem isso o erro sobe pelo
    // useEffect e o React desmonta o dashboard inteiro, deixando tela branca.
    let socket
    try {
      socket = new WebSocket(WS_URL)
    } catch (err) {
      console.error('[BeeIA] Falha ao abrir WebSocket:', err)
      setConnected(false)
      retryRef.current = setTimeout(connect, 5000)
      return
    }
    ws.current = socket

    socket.onopen = () => {
      setConnected(true)
      if (retryRef.current) {
        clearTimeout(retryRef.current)
        retryRef.current = null
      }
    }

    socket.onmessage = (e) => {
      try {
        onMessage(JSON.parse(e.data))
      } catch {}
    }

    socket.onclose = () => {
      setConnected(false)
      retryRef.current = setTimeout(connect, 5000)
    }

    socket.onerror = () => socket.close()
  }

  useEffect(() => {
    connect()
    return () => {
      clearTimeout(retryRef.current)
      ws.current?.close()
    }
  }, [])

  return connected
}
