# Processo 07 — Frontend: Dashboard de Monitoramento

Módulo `frontend/` — interface web do BeeIA. Exibe ataques em tempo real via WebSocket, gráficos de análise e mapa geográfico dos atacantes.

**Stack:** React 18 · Vite · Tailwind CSS · Recharts · Leaflet

## Como rodar

```bash
cd frontend
npm install
npm run dev      # http://localhost:5173 (desenvolvimento)
npm run build    # gera dist/ para produção
npm run preview  # testa o build de produção localmente
```

> O backend precisa estar rodando em `http://localhost:8000` antes de abrir o frontend (ver [06-backend-api-tempo-real.md](06-backend-api-tempo-real.md)).

## Estrutura

```
src/
├── App.jsx                   ← layout principal e gerenciamento de estado
├── main.jsx                  ← entrada React
├── index.css                 ← Tailwind + estilos globais
│
├── components/
│   ├── Overview.jsx          ← 4 cards de métricas
│   ├── AttackFeed.jsx        ← tabela de ataques em tempo real
│   ├── Charts.jsx            ← gráfico de barras + donut
│   ├── GeoMap.jsx             ← mapa geográfico (Leaflet)
│   └── Report.jsx            ← relatório em linguagem natural (LLM)
│
└── hooks/
    └── useWebSocket.js       ← conexão WebSocket com reconexão automática
```

> O artigo do TCC1 (Seção 4.5) descreve **cinco** componentes, incluindo um `HeatMap.jsx` de mapa de calor por janela temporal/categoria — esse ainda não existe. O código atual tem cinco componentes, mas o quinto é `Report.jsx` (consumindo o módulo LLM implementado em 2026-07-28), não o `HeatMap.jsx` do artigo. Ver [10-limitacoes-e-trabalhos-futuros.md](10-limitacoes-e-trabalhos-futuros.md).

## Componentes implementados

### `Overview.jsx` — cards de métricas

| Card | Dado exibido |
|---|---|
| Total de Ataques | Acumulado total + últimas 24h |
| IPs Únicos | Origens distintas detectadas |
| Tipo Predominante | Classe com mais ocorrências |
| IPs Bloqueados | Quantidade bloqueada pelo firewall |

### `AttackFeed.jsx` — feed de ataques

Tabela que recebe novas linhas via WebSocket conforme os ataques chegam:

- IP de origem (fonte monoespaçada)
- Badge do honeypot de origem (Cowrie/Dionaea)
- Badge colorido por tipo de ataque
- Barra de confiança do modelo (vermelho ≥ 90%, laranja ≥ 70%)
- País de origem, horário da sessão
- Botão "Bloquear" para bloqueio manual via API

Cores dos badges por tipo de ataque (compartilhadas entre os honeypots quando o tipo é o mesmo, ex.: `malware_download`):

| Tipo | Honeypot | Cor |
|---|---|---|
| `brute_force` | Cowrie | Vermelho |
| `command_injection` | Cowrie | Laranja |
| `malware_download` | Cowrie + Dionaea | Roxo |
| `recon` | Cowrie | Azul |
| `port_scan` | Dionaea | Teal |
| `service_probe` | Dionaea | Amarelo |
| `exploit_attempt` | Dionaea | Rosa |

### `Charts.jsx` — gráficos

Dois gráficos com Recharts em tema escuro:

- **Barras empilhadas** — ataques por hora nas últimas 12h, agrupados por tipo.
- **Donut** — distribuição percentual dos tipos de ataque.

### `GeoMap.jsx` — mapa geográfico

Mapa interativo com tile escuro (CartoDB Dark Matter) via OpenStreetMap. Cada IP atacante é um círculo colorido pelo tipo de ataque predominante; o raio cresce com o número de ataques do mesmo IP. Clique no marcador mostra IP, cidade, país, tipo e quantidade.

### `Report.jsx` — relatório em linguagem natural (LLM)

Botão "Gerar Relatório" com seletor de período (24h / 3 dias / 1 semana). Chama `GET /api/report?hours=N` (ver [06-backend-api-tempo-real.md](06-backend-api-tempo-real.md)) e renderiza o texto retornado com um parser leve de markdown (negrito, listas). Trata estado de carregamento e erro — por exemplo, quando `ANTHROPIC_API_KEY` não está configurada no backend (resposta 503), exibe a mensagem de erro em vez de travar.

## Processo de carregamento de dados

```
Abertura da página
       │
       ├── REST: /api/stats, /api/attacks, /api/attacks/chart, /api/geo
       │         (carrega dados históricos iniciais)
       │
       └── WebSocket: ws://localhost:8000/ws
                 │
                 ├── recebe { type: "stats" }      → atualiza cards
                 ├── recebe { type: "new_attack" } → adiciona linha no feed
                 │                                   atualiza cards e mapa
                 └── recebe { type: "ip_blocked" } → marca linha como bloqueada

A cada 30 segundos: re-fetch REST para sincronizar estado completo
```

### `useWebSocket.js`

Hook que gerencia a conexão WebSocket: conecta automaticamente ao montar o componente, reconecta após 5 segundos se a conexão cair, expõe o status `connected` (booleano) para o indicador no header.

## Proxy de desenvolvimento

`vite.config.js` redireciona `/api/*` e `/ws` para `http://localhost:8000`, evitando CORS em desenvolvimento:

```js
proxy: {
  '/api': 'http://localhost:8000',
  '/ws':  { target: 'ws://localhost:8000', ws: true },
}
```

Em produção, configurar um proxy reverso (Nginx) para o mesmo efeito.

## Dependências

| Pacote | Versão | Uso |
|---|---|---|
| `react` + `react-dom` | 18.x | Framework UI |
| `recharts` | 2.x | Gráficos de barras e donut |
| `react-leaflet` + `leaflet` | 4.x + 1.9 | Mapa interativo |
| `lucide-react` | 0.4x | Ícones (Shield, Globe, Wifi…) |
| `tailwindcss` | 3.x | Utilitários CSS |
| `vite` | 5.x | Bundler e dev server |

## Convenções

- Componentes funcionais com hooks, sem gerenciador de estado global (Redux/Zustand) — estado vive em `App.jsx` e é passado via props.
- Tema escuro em todo o dashboard.

## Próximo processo

Para o embasamento teórico por trás das escolhas de honeypot, ML e LLM, veja [08-referencial-teorico.md](08-referencial-teorico.md).
