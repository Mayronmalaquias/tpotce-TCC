# Verificação e atualização da VM — 10/09/2026

## Resultado observado

- Host: Amazon Linux 2023; acesso administrativo confirmado na porta 2222.
  A porta 64295 da documentação antiga não respondeu. Porta 22 pertence ao Cowrie.
- Diretório: `/home/ec2-user/beeia`; backend servido por `beeia-backend.service`.
- Commit de produção: `b7ac139e`, com avanços de ingestão, rotação de logs e
  treinamento Dionaea ausentes no checkout local `a29eb1e4`.
- Não havia diretório `scripts`, serviço/timer BeeIA de integridade nem instalação
  AIDE nos caminhos verificados. O script local anterior não fazia comparação contínua.

## Implantado e validado

Foi publicada a interface do commit `fcae21fd` com login por chave e dashboard
atualizado. Backend, modelos, dados e configuração específica do Nginx foram
preservados. A implantação é uma atualização seletiva sobre `b7ac139e`, registrada
em `/home/ec2-user/beeia/deployment-20260910.json`; não é um reset para o checkout local.

O monitor `host_integrity.py` foi instalado em `/opt/beeia-security`, com timer
horário habilitado e ativo. A referência criada em 10/09/2026 às 16:09:30 UTC
inventariou **35.415 entradas**. A primeira comparação terminou às 16:10:04 UTC:
`status=unchanged`, zero diferenças, zero erros e saída 0. Próxima execução
observada: 17:01:23 UTC (14:01:23 de Brasília); agendamentos seguintes são horários.

SHA-256 da referência inicial:
`62d832ab0ddf095d5175ccd622f67fcf5e4676f42ca8295e2a12324a2de44475`.

A referência representa o estado observado após exposição, **não uma instalação
atestada como limpa**. Não havia referência de instalação disponível para comparação.
As divergências anteriores identificadas abaixo não desaparecem por criar um baseline.

Validações executadas:

- Build Vite concluído; aviso de bundle acima de 500 kB.
- Testes do monitor passaram no Linux: inclusão, remoção, conteúdo, permissões,
  links, falha de leitura, referência ausente/inválida e recusa de sobrescrita.
- Sintaxe Bash e unidades systemd verificadas.
- API sem chave: HTTP 401; com chave existente: HTTP 200.
- WebSocket autenticado: HTTP 101.
- HTML servido pelo Nginx corresponde ao SHA-256 do novo build instalado.
- HTTPS público respondeu 401 sem autenticação, com validação TLS do cliente ativa.
- Coleta permaneceu ativa: snapshot com 3.090 sessões e checagem posterior com 3.092.

## Backup e evidências

Backup remoto protegido:
`/var/backups/beeia/20260910-before-integrity-update/`.
Inclui projeto anterior, configuração, modelos, logs e banco SQLite copiado pela
API de backup consistente. Os logs foram copiados durante coleta ativa; não são um
snapshot atômico de todos os arquivos. Backups possuem manifesto SHA-256 verificado.

Referência, relatório do monitor, auditoria e resumo agregado foram copiados,
com autorização explícita, para:
`data/operations/20260910/beeia-integrity-evidence-20260910.tar.gz`.

SHA-256 conferido localmente e na VM:
`d22c3122a1e2cc17e01b5eb60d471629ff13a7714f98d20d742a44c574d42e3e`.

Esse arquivo local contém metadados sensíveis de infraestrutura. Não contém PEM,
senhas, `.env` ou malware; não deve ser publicado no Git. A exportação externa não
é automática. Os backups completos com configurações permanecem na VM.

## Achados que continuam abertos

1. ~~**Saída para internet permitida**~~ — **corrigido em 10/09/2026, 16:41 UTC.**
   O achado original era real: DOCKER-USER continha somente RETURN e ambos os
   honeypots abriam conexão TCP para `1.1.1.1:443`. Foi aplicada uma tabela
   nftables própria (`inet beeia_containment`), fail-closed e persistente, e o
   teste foi repetido: internet, host, rede privada, metadados AWS, DNS externo e
   resolução de nome ficaram inacessíveis nos dois honeypots, enquanto as
   respostas às conexões recebidas continuam funcionando. Evidência e limites em
   [contenção e alertas](contencao-e-alertas.md).
2. ~~2222 aberta para `0.0.0.0/0`~~ — **desatualizado.** O security group
   `<SECURITY_GROUP>` restringe a porta 2222 a `<IP_ADMIN>/32`, verificado
   em 10/09/2026. Permanece aberto o dashboard em 64298 (`0.0.0.0/0`), protegido
   apenas por Basic Auth: restringir por IP administrativo ou VPN é o próximo passo.
3. A verificação RPM de pacotes críticos apontou alteração em `sshd_config`.
   A verificação completa também apontou configurações/metadados alterados e
   arquivos ausentes de `python3-cffi` e `python3-cryptography`. Há versões via
   pip em `/usr/local/lib64/python3.9/site-packages` (cffi 2.0.0 e cryptography 50.0.0).
   Essa coexistência explica uma hipótese operacional, mas não atesta autoria ou
   legitimidade das mudanças. Revisar histórico de administração e normalizar pacotes.
4. ~~O monitor não envia notificações externas~~ — **corrigido em 10/09/2026.**
   `beeia-watchdog.timer` verifica a cada cinco minutos integridade, backup,
   serviços, contenção e disco, publica alerta por email via SNS e envia heartbeat
   para um alarme CloudWatch que trata **ausência de métrica como falha**. Backup
   diário vai para bucket S3 privado, versionado e imutável, com restauração
   verificada a cada execução. **Pendência:** as duas assinaturas de email seguem
   em `PendingConfirmation` — até os destinatários confirmarem, nada é entregue.
   Detalhes em [contenção e alertas](contencao-e-alertas.md).
5. Acesso root ao host pode adulterar o próprio monitor e continuar enviando
   heartbeat. O alarme externo detecta silêncio, não falsificação. Comparação com
   cópia externa e investigação independente continuam necessárias diante de suspeitas.

## Coleta disponível e próximo passo

Snapshot consistente de 10/09/2026 às 16:05:56 UTC:

| Indicador | Valor |
|---|---:|
| Sessões classificadas no banco | 3.090 |
| IPs distintos | 987 |
| Sessões Cowrie | 2.423 |
| Sessões Dionaea | 667 |

Primeiro timestamp no banco: 06/09/2026 às 01:10:31 UTC.
Último: 10/09/2026 às 15:58:13 UTC. `PRAGMA quick_check` retornou `ok`.
São registros do banco operacional; a contagem sozinha não demonstra proveniência
ou acerto de cada classificação e não equivale a uma semana completa de coleta.

Contenção de saída e alertas externos foram fechados em 10/09/2026
([evidência](contencao-e-alertas.md)). Prioridade imediata agora: confirmar as
assinaturas de email, revisar as alterações de pacotes do host (achado 3) e, em
seguida, consolidar o período de coleta e selecionar
amostra independente para rotulagem manual e avaliação dos classificadores.
O modelo Dionaea já tem trabalho de treino real em produção: verificar separação
entre treino e avaliação, evitando avaliar nas mesmas sessões usadas para treinar.
Ver [plano de avaliação](proxima-etapa-coleta-real.md).
