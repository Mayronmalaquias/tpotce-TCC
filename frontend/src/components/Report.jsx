import { useState } from 'react'
import { FileText, RefreshCw, AlertCircle } from 'lucide-react'

function renderInline(text) {
  const parts = text.split(/(\*\*[^*]+\*\*)/g)
  return parts.map((part, i) =>
    part.startsWith('**') && part.endsWith('**')
      ? <strong key={i} className="text-slate-100">{part.slice(2, -2)}</strong>
      : <span key={i}>{part}</span>
  )
}

function ReportBody({ text }) {
  const blocks = text.trim().split(/\n\s*\n/)
  return (
    <div className="space-y-3 text-sm text-slate-300 leading-relaxed">
      {blocks.map((block, i) => {
        const lines = block.split('\n').map(l => l.trim()).filter(Boolean)
        const isList = lines.length > 1 && lines.every(l => /^[-*]\s/.test(l))
        if (isList) {
          return (
            <ul key={i} className="list-disc list-inside space-y-1">
              {lines.map((l, j) => <li key={j}>{renderInline(l.replace(/^[-*]\s/, ''))}</li>)}
            </ul>
          )
        }
        return <p key={i}>{renderInline(lines.join(' '))}</p>
      })}
    </div>
  )
}

export default function Report() {
  const [report,  setReport]  = useState(null)
  const [loading, setLoading] = useState(false)
  const [error,   setError]   = useState(null)
  const [hours,   setHours]   = useState(24)

  const generate = async () => {
    setLoading(true)
    setError(null)
    try {
      const res  = await fetch(`/api/report?hours=${hours}`)
      const body = await res.json()
      if (!res.ok) throw new Error(body.detail || 'Falha ao gerar relatório')
      setReport(body.report)
    } catch (e) {
      setError(e.message)
    } finally {
      setLoading(false)
    }
  }

  return (
    <div className="bg-surface-800 rounded-xl border border-surface-700 flex flex-col overflow-hidden">
      <div className="px-5 py-3 border-b border-surface-700 flex items-center justify-between flex-wrap gap-2">
        <div className="flex items-center gap-2">
          <FileText size={16} className="text-cyan-400" />
          <h2 className="font-semibold text-slate-200">Relatório de Ameaças (IA)</h2>
        </div>
        <div className="flex items-center gap-2">
          <select
            value={hours}
            onChange={(e) => setHours(Number(e.target.value))}
            disabled={loading}
            className="text-xs bg-surface-700 border border-surface-600 rounded px-2 py-1 text-slate-300 disabled:opacity-50"
          >
            <option value={24}>Últimas 24h</option>
            <option value={72}>Últimos 3 dias</option>
            <option value={168}>Última semana</option>
          </select>
          <button
            onClick={generate}
            disabled={loading}
            className="text-xs px-3 py-1.5 rounded bg-cyan-900/40 text-cyan-300 border border-cyan-700 hover:bg-cyan-800/60 disabled:opacity-50 transition-colors flex items-center gap-1.5"
          >
            {loading ? <RefreshCw size={12} className="animate-spin" /> : <FileText size={12} />}
            {loading ? 'Gerando...' : 'Gerar Relatório'}
          </button>
        </div>
      </div>

      <div className="p-5">
        {error && (
          <div className="flex items-start gap-2 text-sm text-red-300 bg-red-900/20 border border-red-800 rounded-lg p-3">
            <AlertCircle size={16} className="shrink-0 mt-0.5" />
            <span>{error}</span>
          </div>
        )}
        {!error && !report && !loading && (
          <p className="text-sm text-slate-500">
            Gera um relatório em linguagem natural a partir dos ataques registrados, usando IA
            (sumário executivo, análise técnica e recomendações de mitigação).
          </p>
        )}
        {loading && (
          <div className="flex items-center gap-2 text-sm text-slate-500">
            <RefreshCw size={14} className="animate-spin" /> Analisando ataques e gerando relatório...
          </div>
        )}
        {report && !loading && <ReportBody text={report} />}
      </div>
    </div>
  )
}
