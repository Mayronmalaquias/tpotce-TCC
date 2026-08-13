# frontend — Dashboard de Monitoramento

Interface web do BeeIA. Exibe ataques em tempo real via WebSocket, gráficos de análise e mapa geográfico dos atacantes.

**Stack:** React 18 · Vite · Tailwind CSS · Recharts · Leaflet

---

## Como rodar

```bash
npm install
cp .env.example .env   # defina VITE_API_KEY com o mesmo valor de BEEIA_API_KEY do backend
npm run dev      # http://localhost:5173 (desenvolvimento)
npm run build    # gera dist/ para produção
npm run preview  # testa o build de produção localmente
```

> O backend precisa estar rodando em `http://localhost:8000` antes de abrir o frontend.

> `VITE_API_KEY` é embutida no bundle JS em tempo de build — qualquer um que acesse a página consegue extraí-la. Isso é aceitável como defesa em profundidade contra bots, mas **não substitui** proteger o acesso à própria página (ver [`md-usotcc/proteger-dashboard.md`](../md-usotcc/proteger-dashboard.md) antes de publicar).

---

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
│   ├── GeoMap.jsx            ← mapa geográfico (Leaflet)
│   └── Report.jsx            ← relatório em linguagem natural (LLM)
│
├── hooks/
│   └── useWebSocket.js       ← conexão WebSocket com reconexão automática
│
└── lib/
    └── api.js                ← authFetch()/wsUrl() — injeta a API key (VITE_API_KEY) nas chamadas
```

---

## Componentes

### `Overview.jsx` — Cards de métricas

Quatro cards no topo da página, atualizados em tempo real:

| Card | Dado exibido |
|---|---|
| Total de Ataques | Acumulado total + últimas 24h |
| IPs Únicos | Origens distintas detectadas |
| Tipo Predominante | Classe com mais ocorrências |
| IPs Bloqueados | Quantidade bloqueada pelo firewall |

### `AttackFeed.jsx` — Feed de ataques

Tabela que recebe novas linhas via WebSocket conforme os ataques chegam. Exibe:
- IP de origem (fonte monoespaçada)
- Badge colorido por tipo de ataque
- Barra de confiança do modelo (vermelho ≥ 90%, laranja ≥ 70%)
- País de origem
- Horário da sessão
- Botão "Bloquear" para bloqueio manual via API

Cores dos badges:

| Tipo | Cor |
|---|---|
| `brute_force` | Vermelho |
| `command_injection` | Laranja |
| `malware_download` | Roxo |
| `recon` | Azul |

### `Charts.jsx` — Gráficos

Dois gráficos com Recharts em tema escuro:

- **Barras empilhadas** — ataques por hora nas últimas 12h, agrupados por tipo
- **Donut** — distribuição percentual dos tipos de ataque

### `GeoMap.jsx` — Mapa geográfico

Mapa interativo com tile escuro (CartoDB Dark Matter) via OpenStreetMap. Cada IP atacante é um círculo colorido pelo tipo de ataque predominante. O raio do círculo cresce com o número de ataques do mesmo IP. Clique no marcador para ver detalhes (IP, cidade, país, tipo, quantidade).

### `Report.jsx` — Relatório em linguagem natural (LLM)

Botão "Gerar Relatório" com seletor de período (24h / 3 dias / 1 semana) que chama `GET /api/report?hours=N` no backend. Renderiza o texto retornado (sumário executivo, análise técnica, recomendações) com um parser leve de markdown (negrito `**texto**` e listas `- item`). Exibe estado de carregamento e erro (ex.: `ANTHROPIC_API_KEY` não configurada no backend → mensagem de erro amigável).

---

## Fluxo de dados

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

Hook que gerencia a conexão WebSocket:
- Conecta automaticamente ao montar o componente
- Reconecta após 5 segundos se a conexão cair
- Expõe o status `connected` (booleano) para o indicador no header

---

## Proxy de desenvolvimento

O `vite.config.js` configura proxy para que as chamadas `/api/*` e `/ws` sejam redirecionadas para `http://localhost:8000`, evitando problemas de CORS durante o desenvolvimento:

```js
proxy: {
  '/api': 'http://localhost:8000',
  '/ws':  { target: 'ws://localhost:8000', ws: true },
}
```

Em produção, configure um proxy reverso (Nginx) para o mesmo efeito.

---

## Dependências

| Pacote | Versão | Uso |
|---|---|---|
| `react` + `react-dom` | 18.x | Framework UI |
| `recharts` | 2.x | Gráficos de barras e donut |
| `react-leaflet` + `leaflet` | 4.x + 1.9 | Mapa interativo |
| `lucide-react` | 0.4x | Ícones (Shield, Globe, Wifi…) |
| `tailwindcss` | 3.x | Utilitários CSS |
| `vite` | 5.x | Bundler e dev server |
