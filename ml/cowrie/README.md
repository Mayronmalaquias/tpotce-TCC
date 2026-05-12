# ml/cowrie — Classificador de Ataques SSH/Telnet

Modelo de Machine Learning específico para o honeypot **Cowrie**.
Classifica cada sessão de ataque em uma de 4 categorias com base em 13 features comportamentais.

> Cada honeypot do projeto terá sua própria pasta dentro de `ml/` com modelo e features específicos para o tipo de tráfego que ele captura.

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
python train.py --dataset ../../data/dataset/training_features.csv --seed 42
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
├── cowrie_rf.joblib          ← modelo + label encoder (carregado pelo backend)
└── cowrie_rf_meta.json       ← métricas e metadados em JSON
```

---

## Classes classificadas

| Classe | Descrição | Indicadores principais |
|---|---|---|
| `brute_force` | Força bruta SSH — muitas tentativas rápidas sem acesso | Alto `login_attempt_count`, `min_login_interval_ms` baixo, `login_success=0` |
| `command_injection` | Acesso bem-sucedido + execução de payload malicioso | `login_success=1`, `has_reverse_shell=1` |
| `recon` | Enumeração passiva do sistema após login | `login_success=1`, `has_recon_commands=1`, sem download |
| `malware_download` | Download e execução de malware via wget/curl | `has_wget_curl=1`, `has_file_download=1` |

---

## Features de entrada (13)

```
login_attempt_count    unique_usernames       session_duration_s
login_success          unique_passwords       command_count
avg_login_interval_ms  min_login_interval_ms  command_rate_per_min
has_wget_curl          has_reverse_shell      has_recon_commands
has_file_download
```

Todas numéricas. O modelo **não usa** IP de origem — a classificação é puramente comportamental.

---

## Parâmetros do Random Forest

| Parâmetro | Valor | Motivo |
|---|---|---|
| `n_estimators` | 300 | Equilíbrio entre acurácia e tempo de treino |
| `max_features` | `"sqrt"` | Reduz correlação entre árvores |
| `max_depth` | `None` | Árvores crescem livremente (dados bem separáveis) |
| `min_samples_split` | 2 | Padrão |

---

## Retreinamento com dados reais

Após o Cowrie coletar ataques reais, use o mesmo script apontando para o CSV de features reais:

```bash
# 1. Extrair features dos logs reais
cd ../../data_pipeline
python extract_features.py
# gera: ../data/dataset/real_features.csv (sem coluna 'label')

# 2. Adicionar labels manualmente (ou usar pseudo-labels do modelo atual)
# Edite o CSV e adicione a coluna 'label' com a classificação correta

# 3. Retreinar
cd ../ml/cowrie
python train.py --dataset ../../data/dataset/real_features.csv
```

O backend recarrega o modelo automaticamente na próxima inicialização.

---

## Adicionar novo honeypot

Para cada novo honeypot (ex: Dionaea, Heralding), crie uma pasta paralela:

```
ml/
├── cowrie/      ← SSH/Telnet (atual)
│   ├── train.py
│   └── models/
├── dionaea/     ← malware/exploits (futuro)
│   ├── train.py
│   └── models/
└── heralding/   ← credenciais multi-protocolo (futuro)
    ├── train.py
    └── models/
```

Cada um terá suas próprias features específicas para o tipo de tráfego que captura.
