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
      socket = new WebSocket(wsUrl())
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
