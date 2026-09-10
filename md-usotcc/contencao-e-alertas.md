# Contenção de saída, alertas e backup externo — 10/09/2026

Fecha os itens 1 e 3 do plano de continuidade. Todas as evidências abaixo foram
observadas na VM `<INSTANCE_ID>` (us-east-2, conta <CONTA_AWS>) e na conta
AWS correspondente, em 10/09/2026 entre 16:39 e 17:16 UTC — incluindo um reboot
planejado às 17:07 para testar a persistência.

> Este repositório é público. `<CONTA_AWS>`, `<INSTANCE_ID>`, `<IP_ADMIN>`,
> `<SECURITY_GROUP>` e `<IP_PRIVADO_HOST>` são marcadores: os valores reais estão
> em `/etc/beeia-security/operations.json` na VM, nas saídas da stack
> `beeia-security-operations` e no console da AWS. Ao montar o anexo de evidências
> do TCC, substitua os marcadores em uma cópia **fora do Git**.

---

## 1. Contenção de saída dos honeypots

### O que foi aplicado

`scripts/honeypot_firewall.py` monta uma tabela nftables própria,
`table inet beeia_containment`, instalada em `/opt/beeia-security/`. A tabela é
separada das tabelas do Docker: o `apply` faz `delete table` + recriação em uma
única transação `nft -f`, validada antes com `nft --check`. As regras do Docker
não são editadas, então `DOCKER-USER` e o encaminhamento do Docker continuam
intactos e a contenção não é desfeita quando o Docker recria suas cadeias.

Política, em ambas as cadeias com hook (`input` e `forward`, prioridade
`filter - 10`, antes das regras do Docker):

1. Tráfego vindo de ponte confiável (`@trusted_bridges`) retorna sem restrição.
2. Tráfego de resposta (`ct direction reply ct state established,related`) retorna.
   É isso que preserva as respostas dos honeypots às conexões **recebidas**.
3. O resto é registrado (`log prefix "BEEIA_DENY "`, limitado a 3/min) e descartado.

As cadeias casam `iifname "br-*"` e `iifname "docker0"`. Qualquer ponte Docker
nova entra em quarentena automaticamente, sem precisar editar configuração.
A família `inet` cobre IPv4 e IPv6 na mesma regra.

Exceção explícita, em `/etc/beeia-security/containment.json`:

```json
{ "trusted_bridges": ["br-ba3b15d61db8"] }
```

`br-ba3b15d61db8` é a ponte do container `nginx` do dashboard, que precisa
alcançar o backend no host. O nome é validado contra `br-[0-9a-f]{12}`; curinga,
interface arbitrária e injeção de sintaxe são recusados (teste em
`scripts/test_honeypot_firewall.py`). Se o Docker recriar essa rede com outro ID,
o nome muda: atualize o JSON e reaplique, ou o dashboard para de responder.

### Persistência entre reinícios

| Mecanismo | Estado observado |
|---|---|
| `beeia-containment.service` | `enabled`, `active`, `RemainAfterExit=yes`, `WantedBy=multi-user.target` |
| Ordem em relação ao Docker | `Before=docker.service` na unidade |
| `/etc/systemd/system/docker.service.d/beeia-containment.conf` | `Requires=` + `After=beeia-containment.service` |

O `Requires=` torna o arranjo **fail-closed**: se a contenção não aplicar, o
Docker não sobe e os honeypots ficam fora do ar em vez de expostos sem bloqueio.

Efeito colateral medido: reiniciar `beeia-containment.service` propaga restart
para `docker.service` e reinicia os containers. Foi o que ocorreu às 16:48 UTC de
10/09/2026 — **interrupção de coleta de poucos segundos, registrada aqui** por ser
exigência do plano de coleta. Reaplique a contenção apenas quando necessário.

### Teste de reboot — 10/09/2026, 17:07 UTC

A VM foi reiniciada de propósito para observar a persistência, em vez de inferi-la.
Linha do tempo lida do journal do boot:

| Instante (UTC) | Evento |
|---|---|
| 17:07:14 | `systemctl reboot` emitido |
| 17:07:34 | novo boot |
| 17:07:38.075 | `beeia-containment.service` iniciando |
| 17:07:38.662 | *Containment applied atomically; Docker tables preserved* |
| 17:07:38.674 | contenção concluída |
| 17:07:39.777 | `docker.service` iniciando |
| 17:07:43.386 | Docker pronto, containers carregados |

A contenção terminou **1,1 s antes** de o Docker começar: não existe janela em que
os containers rodem sem bloqueio.

A impressão digital regravada no boot é **byte a byte igual** à de antes do reboot
(`19cd96b21ac48111760a8fea427d35f72f50e09885b6a9deed199b732d6e8a86`), ou seja, as
regras foram reconstruídas idênticas. `check` passou.

O teste de saída foi repetido depois do reboot com o mesmo roteiro: internet TCP e
HTTP, DNS externo, metadados AWS, host (2222 e 8000), rede privada e resolução de
nome continuaram **bloqueados nos dois honeypots**, e o host continuou saindo.

Voltaram ativos sem intervenção: contenção, Docker, `beeia-backend`, os quatro
containers e os três timers. Dashboard respondeu 401 pelo domínio e as portas 21,
22, 23 e 445 aceitaram conexão da internet.

### Verificação contínua

`honeypot_firewall.py check` compara a tabela ativa com a impressão digital
SHA-256 gravada em `/etc/beeia-security/firewall.sha256` no momento do `apply`.
A impressão ignora contadores e handles, então tráfego normal não gera alarme
falso, mas qualquer mudança de regra, política, cadeia ou conjunto é detectada.

O mesmo comando recusa arranjos de rede que burlariam a política: honeypot sem
rede isolada, honeypot em `network_mode: host`, honeypot na ponte confiável, ou
rede cujo `com.docker.network.bridge.name` não corresponde à ponte esperada.
O watchdog roda esse `check` a cada cinco minutos (seção 2).

### Teste controlado — 10/09/2026, 16:41 UTC

Executado com `nsenter` no *network namespace* de cada honeypot. Apenas tentativa
de conexão TCP/UDP, **sem envio de payload**.

| Destino | Cowrie | Dionaea |
|---|---|---|
| Internet TCP `1.1.1.1:443` | bloqueado | bloqueado |
| Internet HTTP `93.184.216.34:80` | bloqueado | bloqueado |
| DNS externo UDP `8.8.8.8:53` | bloqueado | bloqueado |
| Metadados AWS `169.254.169.254:80` | bloqueado | bloqueado |
| Host — SSH admin `<IP_PRIVADO_HOST>:2222` | bloqueado | bloqueado |
| Host — backend `<IP_PRIVADO_HOST>:8000` | bloqueado | bloqueado |
| Gateway da própria ponte Docker | bloqueado | bloqueado |
| Rede privada VPC `172.31.0.1:22` | bloqueado | bloqueado |
| Resolução de nome (`example.com`) | sem resolução | sem resolução |

Todos os bloqueios terminaram em timeout (`rc=124`), não em recusa. O host, que
não é contido, continua alcançando a internet — é ele que envia backup e alertas.

Contadores logo após o teste: **76 pacotes descartados** na regra de drop e
**59 pacotes de resposta liberados** na regra de reply. Registro no kernel:
14 linhas `BEEIA_DENY` nos dez minutos anteriores.

### O que continua funcionando

- Cowrie (22) e Dionaea (445) aceitam conexão de fora; a regra de reply garante
  que respondem normalmente.
- Coleta ativa durante todo o procedimento: 3.090 sessões às 16:05 UTC,
  3.098 às 16:48 UTC.
- Dashboard: `https://honeypot.mirondev.com:64298/` respondeu **401** (Basic Auth
  exigida) de fora da VM; nginx → backend responde 401 localmente.
- SSH administrativo na porta 2222 não foi afetado.

### Limites desta contenção

- `tpotinit` roda com `network_mode: host`, `NET_ADMIN` e socket do Docker.
  **Não é coberto** por esta tabela — é componente privilegiado da infraestrutura,
  não um honeypot. A contenção protege contra saída dos honeypots, não contra
  abuso do tpotinit.
- O host não é contido, por necessidade operacional.
- Root no host pode remover a tabela. O `check` a cada cinco minutos detecta e
  alerta, mas não impede.
- Bloquear saída não impede escape de container; reduz o valor de um escape.

---

## 2. Alertas por email e backup externo automático

### Infraestrutura AWS

Stack CloudFormation `beeia-security-operations` (us-east-2), definida em
`scripts/aws/security-operations.template.json`. Status `CREATE_COMPLETE`.

| Recurso | Configuração |
|---|---|
| Bucket `beeia-security-backups-<CONTA_AWS>` | privado (todos os bloqueios de acesso público), versionamento, SSE-AES256, Object Lock GOVERNANCE 14 dias, ciclo de vida 30 dias, política que nega tráfego sem TLS, `DeletionPolicy: Retain` |
| Tópico SNS `beeia-security-alerts` | duas assinaturas de email |
| Alarme `beeia-security-heartbeat` | métrica `BeeIA/Security Heartbeat`, 3 períodos de 5 min, `TreatMissingData: breaching`, ações em ALARM e em OK |
| Política IAM na role `beeia-ec2-ssm-role` | `s3:PutObject/GetObject/GetObjectVersion` **somente** no prefixo `<INSTANCE_ID>/*`; `sns:Publish` só nesse tópico; `cloudwatch:PutMetricData` restrito ao namespace `BeeIA/Security` |

Não há chave de acesso estática na VM: tudo usa a role da instância.

> **Pendência que só os destinatários podem resolver.** As duas assinaturas
> (emails institucionais dos autores, cadastrados na criação da stack) estão em
> `PendingConfirmation`. Cada um recebeu da AWS um email
> *"AWS Notification - Subscription Confirmation"* e precisa clicar em
> **Confirm subscription**. Enquanto isso não acontecer, os alertas são aceitos
> pelo SNS mas **não chegam a ninguém**. Conferir com:
>
> ```bash
> aws sns list-subscriptions-by-topic --profile beeia-security --region us-east-2 \
>   --topic-arn arn:aws:sns:us-east-2:<CONTA_AWS>:beeia-security-alerts \
>   --query "Subscriptions[].{Email:Endpoint,Arn:SubscriptionArn}" --output table
> ```

### Unidades na VM

`scripts/security_operations.py` em `/opt/beeia-security/`, configuração em
`/etc/beeia-security/operations.json` (modo 0600), estado em `/var/lib/beeia-ops`.

| Unidade | Cadência | Função |
|---|---|---|
| `beeia-watchdog.timer` | a cada 5 min | supervisão + heartbeat externo |
| `beeia-backup.timer` | diário, 03:15 UTC | backup externo + verificação de restauração |
| `beeia-notify-failure@.service` | sob demanda | `OnFailure` de integridade e de backup |
| `beeia-integrity.service.d/notifications.conf` | drop-in | liga o `OnFailure` ao monitor de integridade que já existia |

O que o watchdog verifica e alerta:

- relatório de integridade com mais de 2h ou com `status` diferente de `unchanged`;
- backup com mais de 26h, com erro, ou sem `restore_verified`;
- `beeia-integrity.timer`, `beeia-backup.timer`, `beeia-containment.service` e
  `beeia-backend.service` inativos;
- `beeia-integrity.service` ou `beeia-backup.service` com resultado de falha;
- `honeypot_firewall.py check` com saída diferente de zero;
- menos de 10% ou 512 MB livres em disco.

Repetição é suprimida por assinatura do conjunto de problemas, com lembrete a
cada 6h; quando tudo volta ao normal, sai uma mensagem de recuperação. As
mensagens não incluem saída de serviço nem credenciais.

O heartbeat resolve o ponto cego apontado no plano — alguém precisa saber quando
o monitor *para de executar*. O alarme vive **fora** da VM e trata ausência de
métrica como falha, então silêncio da VM também gera email.

### Backup e verificação de restauração

Cada execução: snapshot do SQLite pela API de backup (`PRAGMA quick_check` mais
contagem de linhas), cópia de backend, `frontend/src`, `scripts`, modelos, logs
de Cowrie e Dionaea, configuração do Compose/Nginx e o estado do monitor de
integridade; manifesto com SHA-256 por arquivo; `tar.gz` com modo 0600.

Exclusões: `.env*`, `*.pem`, `*.key`, `*.p12`, `*.pfx`, `credentials`,
`nginxpasswd`, `lswebpasswd`, `downloads/`, `binaries/`, `cert/`, `.ssh`, `.aws`,
`venv`, `.git`, `node_modules`. Nenhum link simbólico é seguido. O objetivo é não
enviar segredo nem malware coletado para o S3.

A verificação **baixa de volta** o objeto do S3 pelo `VersionId`, confere o
SHA-256, extrai em diretório vazio sem executar nada, recusa membro com caminho
absoluto, `..` ou duplicado, confere o inventário contra o manifesto, o hash de
cada arquivo e, no banco restaurado, `quick_check` e a contagem de linhas.
Cópias locais antigas só são apagadas depois que upload e restauração passam.

Primeira execução real, 10/09/2026:

| Campo | Valor |
|---|---|
| Início / fim | 16:46:07Z → 16:46:12Z |
| Chave | `<INSTANCE_ID>/2026/09/10/backup-20260910T164607139028Z.tar.gz` |
| VersionId | `wmR5Ozzm8bjprv.KcBRfioVqVKStHawY` |
| SHA-256 | `acc40a0ae6e7527b1cb389a0fc89be01b539ddef8700b3123a23203374c0b415` |
| Tamanho | 14.046.060 bytes, 91 arquivos |
| Linhas no banco | 3.097 |
| `restore_verified` | `true` |
| Imutável até | 2026-09-24T16:46:10Z (Object Lock GOVERNANCE) |

Inventário conferido: nenhum `.env`, `.pem`, `.key`, `credentials`, `downloads/`
ou `binaries/` no arquivo.

### Testes de alerta — 10/09/2026, 16:46 a 16:48 UTC

| Teste | Resultado |
|---|---|
| `test-alert` da VM | publicado no SNS com a role da instância |
| Watchdog em estado normal | `problems: []` |
| Falha simulada (`beeia-backup.timer` parado) | `beeia-backup.timer_inactive` detectado e publicado |
| Repetição da mesma falha | suprimida por assinatura, sem reenvio |
| Falha corrigida | mensagem de recuperação publicada |
| `beeia-notify-failure@teste.service` | executou e publicou, `Result=success` |
| Métrica no CloudWatch | `Heartbeat = 1` registrado |
| Alarme externo | transição **ALARM → OK** às 16:47:58Z |
| `NumberOfMessagesPublished` no tópico | 6 mensagens na janela |

O alarme nasce em ALARM (sem dados históricos) e migra para OK quando o heartbeat
chega — a transição observada prova o caminho inteiro: VM → CloudWatch → alarme → SNS.

### Limites destes alertas

- Sem confirmação das assinaturas, nada é entregue. É o estado atual.
- Root na VM pode adulterar o agente e continuar enviando heartbeat. O alarme
  detecta silêncio, não falsificação.
- A verificação de restauração prova que o arquivo é íntegro e restaurável, não
  que o conteúdo salvo esteja livre de comprometimento anterior.
- Object Lock GOVERNANCE pode ser contornado por quem tiver
  `s3:BypassGovernanceRetention`; a role da VM não tem essa permissão.

---

## 3. Achados encontrados no caminho e o que foi feito com eles

### Um alerta real, não simulado

No primeiro ciclo depois do reboot o watchdog acusou `integrity_not_ok`: o monitor
de integridade tinha encontrado **33 diferenças** em relação à referência das
16:09 UTC. Foi o primeiro alerta legítimo do sistema, não um teste.

Todas as diferenças foram contabilizadas por origem, sem sobra:

| Origem | Quantidade |
|---|---:|
| Arquivos que nós mesmos instalamos (`/etc/beeia-security`, `/opt/beeia-security`, unidades systemd e seus symlinks) | 19 |
| Pacote `nftables-1.0.4-3.amzn2023.0.3.x86_64`, instalado para a contenção | 13 |
| `glibc` — `/etc/ld.so.cache`, regravado ao instalar o pacote | 1 |
| **Sem explicação** | **0** |

A checagem de origem usou `rpm -qf` em cada caminho. Nenhum arquivo ficou órfão.

### Renovação da referência

Seguido o procedimento já documentado em [segurança do host](seguranca-host.md):
revisar, arquivar fora da VM, e só então renovar explicitamente.

1. Backup externo executado às 17:13:09 UTC, levando para o S3 a referência antiga
   **e** o relatório que registra a alteração
   (`.../backup-20260910T171309257624Z.tar.gz`, 13.993.047 bytes,
   `restore_verified: true`).
2. Referência antiga preservada na VM como
   `/var/lib/beeia-integrity/baseline-arquivada-20260910T160930Z.json`
   (SHA-256 `62d832ab0ddf095d5175ccd622f67fcf5e4676f42ca8295e2a12324a2de44475`).
3. Nova referência criada às 17:14:46 UTC: 35.447 entradas, SHA-256
   `00e1c5ee8970b6de4112b7104876073c97a5213d68473c213fc96158492063f0`.
4. `check` seguinte: `status=unchanged`, zero diferenças, saída 0.
5. Watchdog publicou **mensagem de recuperação** às 17:15:28 UTC e voltou a
   `problems: []`.

O ciclo inteiro — detectar, alertar, corrigir, recuperar — rodou de ponta a ponta
com dados reais. A nova referência continua sendo o estado observado de um host
já exposto, não uma instalação atestada como limpa.

### Interrupções de coleta a registrar

| Janela (UTC) | Duração | Causa |
|---|---|---|
| 10/09/2026 ~16:48 | segundos | reinício da contenção propagou restart ao Docker |
| 10/09/2026 17:07:14 – 17:07:45 | ~31 s | reboot planejado da VM |

Ingestão confirmada depois do reboot: os honeypots voltaram a escrever log e o
backend voltou a gravar no banco (3.102 → 3.104 sessões).

### Sessões de teste próprias, a excluir da avaliação

Conexões TCP feitas por nós a partir do IP administrativo (`<IP_ADMIN>`) para
verificar alcance de entrada. **Não são tráfego de atacante** e precisam sair da
amostra de avaliação:

| id | session_id | honeypot | timestamp (UTC) | classe prevista |
|---:|---|---|---|---|
| 3089 | `eb997411a1e3` | cowrie | 2026-09-10T15:58:13Z | brute_force |
| 3100 | `a4ec7910d346` | cowrie | 2026-09-10T16:49:03Z | brute_force |
| 3103 | `ee407fc4aab6` | cowrie | 2026-09-10T17:16:19Z | brute_force |
| 3104 | `435e8004bb3a` | cowrie | 2026-09-10T17:16:42Z | brute_force |

**Resolvido em 10/09/2026** com `data_pipeline/exclusions.py`. O banco operacional
**não é alterado** — as sessões continuam lá, com o log original. Quem monta
amostra de avaliação aplica o filtro; quem estuda a coleta bruta não aplica, e a
diferença entre as duas leituras é reproduzível por outra pessoa.

O módulo combina duas listas:

- os `session_id` acima, fixos no código com data e motivo (vão para o Git — são
  identificadores opacos);
- IPs em `data_pipeline/excluded_ips.local.txt`, que **não** vai para o Git
  (contém o IP administrativo) e está no `.gitignore`. Sem o arquivo o módulo
  continua funcionando, filtrando só por `session_id`.

A lista por IP é a que sustenta o filtro a longo prazo: cada verificação nova de
alcance gera sessão nova, e ela é capturada sem editar código. Execução em
10/09/2026 às 17:33 UTC: 3.111 sessões no banco, **6 excluídas**, 3.105 elegíveis
para avaliação.

```bash
python data_pipeline/exclusions.py --db data/beeia.db
```

Note que essas sessões foram classificadas como `brute_force` sendo apenas
conexões TCP abertas e fechadas, sem tentativa de login — é um erro de
classificação observável e serve de exemplo concreto na discussão de limitações.

### Divergência de versão do scikit-learn — medida e corrigida

O log do `beeia-backend` no boot mostrava `InconsistentVersionWarning`: os modelos
foram serializados com scikit-learn **1.5.2** e estavam sendo carregados com a
**1.9.0**. Causa raiz: todos os `requirements.txt` usavam intervalo
(`scikit-learn>=1.3.0`), então a instalação foi parar numa versão bem à frente.

**Antes de mudar qualquer coisa, o impacto foi medido**, porque a pergunta que
importa para o TCC é se os dados já coletados valem. Os três modelos foram
carregados nos dois ambientes — mesmo `numpy` 2.4.6 e `scipy` 1.17.1, variando só
o scikit-learn — e alimentados com a mesma matriz de 5.000 amostras (seed 42):

| Modelo | Probabilidades idênticas? |
|---|---|
| `cowrie_rf` | sim, hash idêntico |
| `dionaea_rf` | sim, hash idêntico |
| `dionaea_real_rf` | não — diferença máxima **2,22e-16** |

Para o `dionaea_real_rf`, 32 células de 30.000 diferem em **1 ULP de float64** e
**nenhum dos 5.000 rótulos muda**. Ou seja: o aviso era real, mas o efeito é
ruído de ponto flutuante. **As classificações já gravadas continuam válidas.**

Correção aplicada:

1. Versões fixadas em `backend/requirements.txt` e nos dois
   `ml/*/requirements.txt` — `scikit-learn==1.5.2`, mais `numpy`, `pandas` e
   `joblib` nas versões verificadas. O intervalo `>=` era a causa raiz.
2. `ml/cowrie/train.py` e `ml/dionaea/train.py` passam a gravar um bloco
   `environment` no `*_meta.json` com Python, scikit-learn, numpy, pandas e
   joblib. Os metadados antigos não registravam nada disso, e foi por isso que a
   divergência só apareceu como warning em tempo de execução.
3. A VM foi alinhada para `scikit-learn==1.5.2` e o backend reiniciado. O warning
   sumiu e a sessão classificada logo depois saiu com confiança `0.6433`,
   **o mesmo valor** das sessões classificadas minutos antes sob a 1.9.0.

Estado do venv antes da mudança preservado em `/tmp/freeze_antes.txt` na VM.

### Modelo Dionaea: o repositório estava atrás da VM, não o contrário

Uma versão anterior desta seção afirmava que o backend classificava com o modelo
sintético. **Isso estava errado, e a correção importa.** A afirmação veio de ler
`backend/dionaea_classifier.py` no checkout local, que está no commit `a29eb1e4`.
A VM roda `b7ac139e`, onde o Dionaea real já foi implementado. O que estava
desatualizado era o repositório.

A VM já usava `dionaea_real_rf.joblib` — 2.100 sessões reais, 6 classes, 7
features, `cv_f1_macro` 0,8426. Prova disso está no próprio banco: das 673 sessões
Dionaea, 32 estavam classificadas como `credential_bruteforce` e 14 como
`connection_flood`, rótulos que o modelo sintético **não consegue emitir** — ele
só tem 4 classes.

O que a versão de produção resolve, e que o repositório não tinha:

- **Formato do log.** O Dionaea real escreve `{"connection": {...}, "src_ip": ...}`,
  não o `{"eventid": "dionaea.connection.tcp.accept"}` do gerador sintético.
- **Sessão sintetizada.** O log real não tem campo `session` nem evento de
  encerramento. O `LogWatcher` agrupava por `ev.get("session")` e descartava o
  evento quando o campo faltava — ou seja, **100% do tráfego do Dionaea era
  ignorado em silêncio**. Agora agrupa por IP de origem e fecha por inatividade
  (`DIONAEA_SESSION_TIMEOUT_S`, padrão 300 s).
- **Sete features, não dez.** `has_download` só existe no `dionaea.sqlite`,
  `payload_size_avg` não é registrado em lugar nenhum e `has_shellcode` depende da
  tabela `emu_profiles`, vazia em 14 dias de captura. Treinar com features
  indisponíveis em produção criaria distorção entre treino e execução.

Trazidos da VM para o repositório: `backend/dionaea_classifier.py`,
`backend/main.py`, `backend/log_watcher.py`, `backend/tests/`,
`data_pipeline/extract_dionaea_real.py`, `data_pipeline/label_dionaea_real.py`,
`ml/dionaea/train_real.py`, `ml/experiments/run_experiments.py` e
`Docs/artigo-tcc2-consolidado.md`. Os dois testes que vieram junto passam.

### O bug real estava no dashboard

O frontend tinha as sete classes do Cowrie fixas em quatro componentes, e
`Charts.jsx` **descartava em silêncio** qualquer classe fora dessa lista:
`buildBarData` só somava se `attack_type in map[label]`, e `buildPieData`
iterava apenas as chaves conhecidas.

Consequência ao vivo: as **46 sessões** `credential_bruteforce` e
`connection_flood` já classificadas não apareciam em nenhum gráfico. O honeypot
capturava, o modelo classificava certo, o banco guardava — e o painel escondia.

Corrigido em `AttackFeed.jsx`, `Charts.jsx`, `GeoMap.jsx` e `Overview.jsx`: as
duas classes ganharam cor e rótulo próprios, e `Charts.jsx` passou a montar a
lista de tipos pela **união** entre os conhecidos e os presentes nos dados, com
cor e rótulo de reserva. Uma classe nova no modelo não some mais do gráfico
porque alguém esqueceu de cadastrá-la.

Build refeito e publicado em `frontend/dist` na VM em 10/09/2026 às 17:52 UTC;
o container `nginx` serve esse diretório por bind mount, sem precisar reiniciar.
Bundles antigos que tinham ficado para trás no diretório foram removidos.

---

## 4. Comandos de operação

```bash
# contenção
sudo python3 /opt/beeia-security/honeypot_firewall.py check
sudo nft list table inet beeia_containment
sudo systemctl status beeia-containment.service

# após mudar containment.json (ex.: nova ponte do nginx) — reinicia o Docker
sudo python3 /opt/beeia-security/honeypot_firewall.py apply

# alertas e backup
sudo python3 /opt/beeia-security/security_operations.py watch
sudo python3 /opt/beeia-security/security_operations.py test-alert
sudo systemctl start beeia-backup.service
sudo cat /var/lib/beeia-ops/backup-latest.json
sudo cat /var/lib/beeia-ops/watchdog-latest.json
sudo systemctl list-timers 'beeia-*'
```

---

## 5. O que fica em aberto

1. **Confirmar as duas assinaturas de email.** Bloqueia a entrega de todos os alertas.
2. **Reconciliar o repositório com a VM.** Esta divergência já causou dois
   incidentes: uma afirmação errada sobre o modelo Dionaea (seção 3) e a
   sobrescrita do `beeia.conf` de produção, que derrubou o certificado TLS válido
   por alguns minutos em 10/09/2026.

   Levantamento feito em 10/09/2026, normalizando quebras de linha. **A
   divergência é mútua** — cada lado tem conteúdo que o outro não tem, então isto
   é um merge a ser decidido por vocês, não uma cópia de mão única:

   | Arquivo | Situação |
   |---|---|
   | `README.md`, `frontend/README.md` | repositório maior |
   | `PROJECT_CONTEXT.md`, `Docs/Process/README.md`, `Docs/Process/11-cronograma-e-status.md` | VM maior |
   | `data_pipeline/build_dataset.py`, `data_pipeline/generate_logs.py` | VM maior |
   | `Docs/Process/13-deploy-publicacao-aws.md`, `md-usotcc/publicar-aws.md` | só na VM |
   | `frontend/src/*`, `ml/*/train.py`, `md-usotcc/*` | repositório à frente (mudanças desta sessão) |

   Antes de afirmar qualquer coisa sobre como o sistema se comporta, comparar o
   arquivo na VM com o do repositório. E **antes de sobrescrever um arquivo na
   VM, diferenciar primeiro** — foi a lição dos dois incidentes.
3. Porta 2222 já está restrita a `<IP_ADMIN>/32` no security group — a
   afirmação de `verificacao-vm-2026-09-10.md` de que estava em `0.0.0.0/0` está
   desatualizada. O dashboard em 64298 continua aberto para `0.0.0.0/0`, protegido
   só por Basic Auth: restringir por IP ou VPN é o próximo passo natural.
4. Divergências de pacotes Python (`python3-cffi`, `python3-cryptography`) e
   `sshd_config` continuam sem investigação. Item 2 do plano original.
5. Itens 4, 5 e 6 do plano (fechar período de coleta, avaliar classificadores em
   sessões reais, preparar entrega) seguem pendentes. Ver
   [plano de avaliação](proxima-etapa-coleta-real.md).
