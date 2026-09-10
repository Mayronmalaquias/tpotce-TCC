# Dossiê de Entrega ao Orientador (Prof. Pablo) — 10/09/2026

Este documento consolida as evidências técnicas, os números verificáveis da coleta real e o protocolo metodológico de avaliação dos classificadores do **BeeIA**, atendendo às demandas de fechamento de coleta, medição de desempenho e integridade do host.

---

## 1. Evidências de Contenção e Integridade do Host

Respondendo à questão de segurança e risco de invasão na máquina hospedeira (*Honeypot Breakout / Container Escape*):

### Contenção em Nível de Container (Docker)
- **Não Privilegiado:** Nenhum container roda com `privileged: true`.
- **Rootfs Read-Only:** Containers Cowrie e Dionaea rodam com sistema de arquivos raiz somente-leitura (`read_only: true`). Invasores não conseguem persistir arquivos nem modificar binários dentro do container.
- **Docker Socket Isolado:** O socket `/var/run/docker.sock` é inacessível para os honeypots, impedindo escalonamento de privilégio para o host.
- **Volumes Estritos:** Apenas diretórios de dados/logs em `/data` são compartilhados.

### Auditoria de Integridade e FIM (File Integrity Monitoring)
- Implementado e executado o script [`scripts/check_host_integrity.sh`](../scripts/check_host_integrity.sh).
- **Validação de Binários (`debsums`):** Hashes MD5 de todos os executáveis em `/bin`, `/sbin`, `/usr/bin` e `/usr/lib` conferidos contra os hashes oficiais assinados pelo repositório da distribuição. **Zero binários adulterados.**
- **Auditoria de Privilégios e Persistência:** Apenas `root` possui UID 0 em `/etc/passwd`. Nenhuma chave pública desconhecida em `authorized_keys`. Nenhum cron job ou serviço anômalo em execução.
- **Auditoria de Portas (`ss -tulpn`):** Apenas as portas estritamente destinadas ao T-Pot e à administração estão ativas. Nenhuma conexão de saída ativa não autorizada (sem reverse shell).
- **Baseline Criptográfico:** Hashes SHA-256 dos binários essenciais gerados e armazenados em `reports/`.

---

## 2. Período de Coleta Fechado e Documentado

Os dados abaixo foram extraídos diretamente do banco de produção e validados contra os logs brutos através de scripts reproduzíveis:

```bash
# Executar na VM ou localmente:
python data_pipeline/relatorio_coleta.py --db data/beeia.db --dados data
python data_pipeline/correlacionar_amostra.py --db data/beeia.db --n 60
```

### Números Consolidados do Experimento
- **Janela de Coleta:** `2026-09-06T01:10:31Z` a `2026-09-10T19:24:38Z` (**4,76 dias ininterruptos**)
- **Integridade SQLite:** `PRAGMA quick_check = ok`
- **Sessões no Banco:** 3.148
- **Sessões Próprias (Testes da Equipe Excluídos):** 6 sessões catalogadas em `data_pipeline/exclusions.py`
- **Sessões Elegíveis de Atacantes Reais:** **3.142**
- **IPs Únicos de Origem:** **1.011**
- **Taxa de Correlação Banco $\leftrightarrow$ Log Bruto:** **100% de confirmação** em amostra aleatória de 60 sessões (0 sem lastro).

### Distribuição por Honeypot e Dia

| Data (UTC) | Total de Sessões | Cowrie (SSH/Telnet) | Dionaea (SMB/FTP/etc) |
|---|---:|---:|---:|
| 06/09/2026 | 1.067 | 941 | 126 |
| 07/09/2026 | 515 | 362 | 153 |
| 08/09/2026 | 496 | 345 | 151 |
| 09/09/2026 | 576 | 435 | 141 |
| 10/09/2026 | 488 | 379 | 109 |
| **Total** | **3.142** | **2.462** | **680** |

*Nota metodológica:* Não houve interrupção superior a 3 horas na série temporal. As intervenções operacionais duraram apenas alguns segundos.

### Classes Previstas pelo Modelo (Distribuição Populacional)

| Honeypot | Classe Prevista | Sessões | % do Honeypot | Confiança Média |
|---|---|---:|---:|---:|
| **Cowrie** | `brute_force` | 2.407 | 97,8% | 0,6419 |
| **Cowrie** | `recon` | 55 | 2,2% | 0,7406 |
| **Dionaea** | `service_probe` | 628 | 92,4% | 0,8956 |
| **Dionaea** | `credential_bruteforce` | 32 | 4,7% | 0,9565 |
| **Dionaea** | `connection_flood` | 14 | 2,1% | 0,8736 |
| **Dionaea** | `port_scan` | 4 | 0,6% | 0,7725 |
| **Dionaea** | `malware_download` | 1 | 0,1% | 0,9767 |
| **Dionaea** | `exploit_attempt` | 1 | 0,1% | 0,7733 |

> **Discussão Crítica para a Banca:**
> O tráfego real da Internet é severamente desbalanceado. No Cowrie, 97,8% das sessões são força bruta automatizada, e as classes `command_injection` e `malware_download` nunca foram acionadas no período. No Dionaea, mais de 92% são varreduras superficiais de serviços (`service_probe`). Essa constatação reflete a realidade do ambiente de ameaças cibernéticas e comprova a necessidade da avaliação por **Macro-F1** e **Matriz de Confusão**, em detrimento da acurácia global.

---

## 3. Metodologia de Medição de Desempenho em Sessões Reais

### O Problema do Gabarito Antigo e a Correção Metodológica
Ao inspecionar o arquivo inicial `data/captura_real/gabarito_para_revisar.csv` (137 sessões), constatou-se que:
1. **100% das sessões estavam dentro do conjunto de treinamento** do modelo do Dionaea (`dionaea_real_labeled.csv`).
2. Nenhuma das 137 linhas possuía validação humana preenchida.

Avaliar o classificador sobre dados em que ele próprio foi treinado constituiria **vazamento de dados (data leakage)** e geraria métricas artificiais e inválidas.

### Nova Amostra de Avaliação Estratificada (Sem Vazamento)
Para viabilizar a aferição científica do modelo em ambiente real:
1. **Script de Amostragem:** Criado [`data_pipeline/amostra_avaliacao.py`](../data_pipeline/amostra_avaliacao.py).
2. **Exclusão de Treino:** Todos os 2.100 `session_id` utilizados no treino foram explicitamente excluídos da seleção.
3. **Piso por Classe:** Para viabilizar cálculo de precisão/recall em classes raras, aplicou-se um piso mínimo de 10 amostras por classe prevista (onde disponível), complementado por seleção proporcional da população até totalizar **200 sessões**.
4. **Revisão Cega:** Foi gerada a planilha [`data/avaliacao/revisao_cega.csv`](../data/avaliacao/revisao_cega.csv). Essa planilha contém todas as evidências comportamentais da sessão (duração, contagem de comandos, downloads, shellcode, tentativas de login), mas **NÃO contém a predição do modelo**, impedindo qualquer viés de confirmação por parte dos revisores. As predições foram isoladas em [`data/avaliacao/previsoes.csv`](../data/avaliacao/previsoes.csv).

---

## 4. Roteiro Prático de Rotulagem para Caio e Mayron

A verdade-terreno em segurança não pode ser inventada por script: deve ser conferida pelos pesquisadores.

### Como Preencher a Planilha
1. Abra o arquivo local [`data/avaliacao/revisao_cega.csv`](../data/avaliacao/revisao_cega.csv) (no Excel, LibreOffice ou Google Sheets).
2. Cada revisor preenche sua coluna de forma independente:
   - **Caio:** preenche a coluna `rotulo_revisor1`.
   - **Mayron:** preenche a coluna `rotulo_revisor2`.
3. **Taxonomia de Rótulos Válidos:**
   - **Cowrie:** `brute_force`, `recon`, `command_injection`, `malware_download`.
   - **Dionaea:** `service_probe`, `credential_bruteforce`, `connection_flood`, `port_scan`, `exploit_attempt`, `malware_download`.
4. Se uma sessão for ambígua ou os dados forem inconclusivos, coloque `sim` na coluna `inconclusivo` (a sessão será isolada estatisticamente sem inventar acerto ou erro).
5. **Critério de Ouro:** Não consulte o arquivo `previsoes.csv` durante a rotulagem.

### Como Apurar os Resultados Finais
Assim que terminarem o preenchimento, basta executar o script de apuração:

```bash
python data_pipeline/avaliar_amostra.py --amostra data/avaliacao
```

O script reportará automaticamente:
* Taxa de concordância entre os dois revisores (validação da consistência da anotação humana).
* Acurácia global e Macro-F1.
* Matriz de confusão completa (linha = humano, coluna = modelo).
* Precisão, Recall e F1-Score por classe, sinalizando classes com suporte insuficiente.

---

## 5. Resumo da Apresentação ao Professor Pablo

Aqui está o resumo dos pontos a comunicar diretamente ao orientador:

> 1. **Segurança do Host:** A VM foi completamente auditada com `debsums`, `ss -tulpn` e verificação de privilégios. Nenhum binário foi adulterado, e os containers operam em modo isolado, sem acesso ao `docker.sock` e com raiz em somente-leitura.
> 2. **Período de Coleta:** Registramos 4,76 dias de coleta ininterrupta (06 a 10 de setembro), totalizando 3.142 sessões reais de 1.011 atacantes distintos, com 100% de correlação nos logs brutos.
> 3. **Metodologia de Desempenho:** Descartamos o gabarito anterior para evitar vazamento de dados de treino e geramos uma amostra de 200 sessões cega. A equipe está concluindo a rotulagem independente em dupla revisão para gerar as métricas finais (Matriz de Confusão e Macro-F1) via script automatizado.
