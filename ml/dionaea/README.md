# ml/dionaea — Classificador de Ataques do Honeypot Dionaea

Modelo de Machine Learning específico para o honeypot **Dionaea** (captura de
malware via emulação de serviços vulneráveis: SMB, FTP, MSSQL, MQTT, TFTP,
HTTP...). Classifica cada sessão de ataque em uma de 4 categorias com base em
10 features comportamentais — diferentes das 13 features do Cowrie, já que o
Dionaea captura conexões/payloads, não sessões de shell interativo.

> Cada honeypot do projeto tem sua própria pasta dentro de `ml/` com modelo e
> features específicas para o tipo de tráfego que ele captura (ver
> [`ml/cowrie/README.md`](../cowrie/README.md)).

---

## Como usar

### 1. Instalar dependências

```bash
pip install -r requirements.txt
```

### 2. Treinar o modelo

```bash
# Random Forest (padrão, recomendado)
python train.py

# XGBoost (requer: pip install xgboost)
python train.py --model xgboost

# Opções avançadas
python train.py --dataset ../../data/dataset/dionaea_training_features.csv --seed 42
```

O script executa automaticamente:
1. Carrega e valida o CSV de features
2. Split estratificado 80% treino / 20% teste
3. Validação cruzada 5-fold no conjunto de treino
4. Treino final + avaliação no conjunto de teste
5. Exibe matriz de confusão e importância das features
6. Salva o modelo em `models/`

### 3. Saída

```
models/
├── dionaea_rf.joblib          ← modelo + label encoder (carregado pelo backend)
└── dionaea_rf_meta.json       ← métricas e metadados em JSON
```

---

## Classes classificadas

| Classe | Descrição | Indicadores principais |
|---|---|---|
| `port_scan` | Varredura rápida de múltiplas portas/serviços, sem payload | Alto `connection_count`/`unique_ports`, `min_connection_interval_ms` baixo |
| `service_probe` | Poucas conexões, payload pequeno/benigno, sem exploit | `has_shellcode=0`, `payload_size_avg` baixo |
| `exploit_attempt` | Payload com assinatura de shellcode/exploit conhecido (ex.: SMB) | `has_shellcode=1` |
| `malware_download` | Download de binário capturado pelo honeypot | `has_download=1` |

---

## Features de entrada (10)

```
connection_count            unique_protocols            has_shellcode
unique_ports                avg_connection_interval_ms   has_download
session_duration_s          min_connection_interval_ms   payload_size_avg
login_attempt_count
```

Todas numéricas. O modelo **não usa** IP de origem — a classificação é puramente comportamental, assim como no Cowrie.

---

## Parâmetros do Random Forest

Mesma configuração usada no Cowrie (ver [`ml/cowrie/README.md`](../cowrie/README.md)): `n_estimators=300`, `max_features="sqrt"`, `max_depth=None`, `min_samples_split=2`.

---

## Normalização de sessão (importante)

O Dionaea real trata cada conexão TCP/UDP como um objeto isolado — não existe
um conceito nativo de "sessão do atacante" como no Cowrie (que tem um shell
interativo contínuo). O BeeIA normaliza isso agrupando, sob um único
`session`, todas as conexões que um mesmo IP faz contra o Dionaea dentro de
uma janela curta (a implementação de referência está em
`data_pipeline/generate_dionaea_logs.py`). Esse agrupamento precisa ser
replicado em `backend/dionaea_watcher.py`/`backend/dionaea_classifier.py` ao
integrar o Dionaea real — ver comentários nesses arquivos.

---

## Retreinamento com dados reais

Mesmo fluxo do Cowrie: extrair features de `data/dionaea/log/dionaea.json`
real com `data_pipeline/extract_dionaea_features.py`, rotular manualmente (ou
usar pseudo-labels do modelo atual) e retreinar com `--dataset`.
