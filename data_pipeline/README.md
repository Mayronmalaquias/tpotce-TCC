# data_pipeline — Geração e Processamento de Dados

Este módulo é responsável por criar o dataset de treinamento do modelo de ML.
Funciona com **dados sintéticos** (para treino inicial) e com **logs reais** do Cowrie (para retreinamento).

---

## Arquivos

| Arquivo | O que faz |
|---|---|
| `generate_logs.py` | Gera sessões de ataque sintéticas no formato exato do Cowrie (JSONL) |
| `extract_features.py` | Lê um arquivo JSONL, agrupa por sessão e extrai 13 features numéricas |
| `build_dataset.py` | Orquestra os dois passos acima em um único comando |

> Nenhuma dependência externa — usa apenas Python stdlib (`json`, `re`, `csv`, `datetime`).

---

## Como usar

### Geração completa (sintético)

```bash
python build_dataset.py                    # 500 sessões por classe (padrão)
python build_dataset.py --sessions 1000   # mais dados
python build_dataset.py --sessions 200 --seed 7  # seed diferente
```

**Saída em `../data/dataset/`:**

```
data/dataset/
├── cowrie_logs.jsonl        ← eventos brutos (formato idêntico ao Cowrie real)
├── session_labels.csv       ← session_id,label
└── training_features.csv    ← 13 features + label, pronto para ml/cowrie/train.py
```

### Extraindo features de logs reais

O `extract_features.py` funciona com qualquer arquivo JSONL do Cowrie — inclusive os logs reais em `data/cowrie/log/cowrie.json`:

```bash
python extract_features.py
# por padrão lê: ../data/dataset/cowrie_logs.jsonl
# por padrão salva: ../data/dataset/training_features.csv
```

Para apontar para logs reais:

```python
# dentro de extract_features.py ou via importação
extract_features(
    logs_path="../data/cowrie/log/cowrie.json",
    output_path="../data/dataset/real_features.csv",
    labels_path=None,   # sem labels → coluna 'label' não será adicionada
)
```

---

## Classes de ataque geradas

| Classe | Comportamento simulado |
|---|---|
| `brute_force` | 60–300 tentativas de login rápidas (< 600ms entre elas), sem acesso ao shell |
| `command_injection` | Poucos erros de login, acesso bem-sucedido, depois reverse shell |
| `recon` | Login bem-sucedido, enumeração passiva do sistema (uname, ps, cat /etc/passwd…) |
| `malware_download` | Login bem-sucedido, wget/curl para baixar e executar payload |

---

## Features extraídas por sessão

| Feature | Tipo | O que captura |
|---|---|---|
| `login_attempt_count` | int | Volume total de tentativas de login (falhas) |
| `login_success` | 0/1 | Houve login bem-sucedido? |
| `unique_usernames` | int | Variedade de usuários tentados |
| `unique_passwords` | int | Variedade de senhas tentadas |
| `session_duration_s` | float | Duração total da sessão em segundos |
| `command_count` | int | Quantidade de comandos executados no shell |
| `avg_login_interval_ms` | float | Intervalo médio entre tentativas de login |
| `min_login_interval_ms` | float | Intervalo mínimo (< 100ms indica script automatizado) |
| `has_wget_curl` | 0/1 | Algum comando contém `wget` ou `curl`? |
| `has_reverse_shell` | 0/1 | Padrão de reverse shell detectado? (`/dev/tcp/`, `nc -e`…) |
| `has_recon_commands` | 0/1 | Comandos de enumeração detectados? |
| `has_file_download` | 0/1 | Evento `cowrie.session.file_download` presente? |
| `command_rate_per_min` | float | Taxa de comandos por minuto na sessão |

---

## Formato do JSONL gerado

Cada linha é um evento no formato nativo do Cowrie:

```json
{"eventid": "cowrie.session.connect", "session": "abc123", "timestamp": "2025-01-01T00:00:00.000Z", "src_ip": "1.2.3.4", "src_port": 54321, "dst_port": 22, "sensor": "cowrie"}
{"eventid": "cowrie.login.failed",    "session": "abc123", "timestamp": "2025-01-01T00:00:00.200Z", "src_ip": "1.2.3.4", "username": "root", "password": "123456", "sensor": "cowrie"}
{"eventid": "cowrie.session.closed",  "session": "abc123", "timestamp": "2025-01-01T00:01:40.000Z", "src_ip": "1.2.3.4", "duration": 100.0, "sensor": "cowrie"}
```

Este formato é **idêntico** ao que o Cowrie real produz — o mesmo pipeline funciona nos dois casos.
