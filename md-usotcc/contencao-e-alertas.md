# Contenção de saída, alertas e backup externo — 10/09/2026

Fecha os itens 1 e 3 do plano de continuidade. Todas as evidências abaixo foram
observadas na VM `<INSTANCE_ID>` (us-east-2, conta <CONTA_AWS>) e na conta
AWS correspondente, em 10/09/2026 entre 16:39 e 16:53 UTC.

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

O reinício completo da VM ainda **não** foi testado. `enabled` mais o drop-in
indicam que as regras voltam no boot, mas isso é inferência, não observação.

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

## 3. Comandos de operação

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

## 4. O que fica em aberto

1. **Confirmar as duas assinaturas de email.** Bloqueia a entrega de todos os alertas.
2. **Testar reinício completo da VM** para observar (não inferir) que a contenção
   volta antes do Docker. Custa uma interrupção curta de coleta.
3. Porta 2222 já está restrita a `<IP_ADMIN>/32` no security group — a
   afirmação de `verificacao-vm-2026-09-10.md` de que estava em `0.0.0.0/0` está
   desatualizada. O dashboard em 64298 continua aberto para `0.0.0.0/0`, protegido
   só por Basic Auth: restringir por IP ou VPN é o próximo passo natural.
4. Divergências de pacotes Python (`python3-cffi`, `python3-cryptography`) e
   `sshd_config` continuam sem investigação. Item 2 do plano original.
5. Itens 4, 5 e 6 do plano (fechar período de coleta, avaliar classificadores em
   sessões reais, preparar entrega) seguem pendentes. Ver
   [plano de avaliação](proxima-etapa-coleta-real.md).
