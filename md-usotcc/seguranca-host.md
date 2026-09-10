# Integridade e contenção do host BeeIA

O script antigo `scripts/check_host_integrity.sh` é uma auditoria manual auxiliar:
produz hashes novos sem comparar com uma referência fixa. Não comprova ausência de invasão.

## Monitor contínuo

`scripts/host_integrity.py` mantém referência SHA-256 e compara conteúdo, permissões,
proprietário/grupo e destinos de links. Detecta inclusões, remoções e alterações em
executáveis, bibliotecas, /usr/local, /boot, /etc, cron, chaves SSH dos usuários
existentes e no próprio monitor. Links não são percorridos; as raízes reais padrão
em /usr também são inventariadas. Aplicações fora dessas raízes exigem ajuste de escopo.
Logs e downloads dos honeypots não integram a referência do host.

Uma referência criada depois da exposição registra o estado atual, não o estado
da instalação. Antes dela, preservar evidências e revisar pacotes, logins, contas,
serviços, persistência e rede. Indícios de comprometimento exigem investigação e
possível reconstrução a partir de imagem confiável.

Um invasor com root pode adulterar o monitor e o banco de pacotes. Manter cópia da
referência e dos relatórios fora da VM, sob controle separado. O próprio debsums
[documenta seu uso limitado como ferramenta de segurança](https://manpages.debian.org/unstable/debsums/debsums.1.en.html).

## Instalação no host Linux, fora dos containers

Após a auditoria inicial, no diretório do projeto:

```bash
sudo bash scripts/install_host_integrity.sh
sudo systemctl enable beeia-integrity.timer
sudo python3 /opt/beeia-security/host_integrity.py init
sudo python3 /opt/beeia-security/host_integrity.py check
sudo systemctl start beeia-integrity.timer
sudo systemctl start beeia-integrity.service
sudo systemctl list-timers beeia-integrity.timer
sudo journalctl -u beeia-integrity.service --since today
sudo cat /var/lib/beeia-integrity/latest.json
sudo sha256sum /var/lib/beeia-integrity/baseline.json
```

O instalador não cria nem substitui referências. `init` recusa sobrescrita e
inventários incompletos. O timer verifica a cada hora, com atraso aleatório de até
dois minutos e recuperação após desligamento. Saídas: 0 sem alterações, 1 alterações,
2 erro/checagem incompleta. Alterações e erros deixam o serviço falho no systemd.

Relatórios: /var/lib/beeia-integrity/reports/ e latest.json. Se a execução falhar
antes de gerar relatório, latest.json pode ser antigo: verificar checked_at,
resultado do serviço e journal. Não há envio de email ou alerta externo; acompanhar
o serviço e exportar evidências regularmente. Monitorar disco e definir retenção
após preservação externa: relatórios não são apagados automaticamente.

Atualizações legítimas também alteram hashes. Revisar diferenças, arquivar a
referência e relatórios externamente, documentar a manutenção e só então renovar
explicitamente a referência. Nunca recriá-la automaticamente no timer.

## Contenção observada no Compose

Cowrie e Dionaea têm raiz somente leitura, redes distintas e não montam o socket
Docker. Essas medidas reduzem risco, mas não garantem ausência de escape.
Dionaea recebe NET_ADMIN. O tpotinit usa rede do host, NET_ADMIN e socket Docker:
é componente privilegiado da infraestrutura. Montagem de socket com :ro não torna
a API Docker somente leitura.

Redes distintas não comprovam bloqueio de saída: verificar regras efetivas no host
e na nuvem e testar cada honeypot. Porta SSH alternativa não substitui autenticação
por chave e controle de acesso.

## Bloqueio de saída e alertas

Desde 10/09/2026 o host aplica `scripts/honeypot_firewall.py` (tabela nftables
`inet beeia_containment`, fail-closed, reaplicada no boot antes do Docker) e
`scripts/security_operations.py` (watchdog a cada cinco minutos, alerta por email
via SNS, heartbeat externo e backup diário verificado em bucket S3 imutável).
Regras, testes controlados por honeypot, unidades systemd, recursos AWS e limites
estão em [contenção e alertas](contencao-e-alertas.md). Isso cobre os honeypots em
ponte Docker; o `tpotinit`, em rede do host, continua fora do escopo da contenção.

## Evidências para o TCC

Registrar início da coleta, commit implantado, digests das imagens, auditoria
inicial, origem/hash da referência, timer e relatórios. Demonstrar detecção em
arquivos temporários, sem adulterar binários reais. Distinguir código implementado,
implantação verificada e limitações. Uma checagem sem diferenças não permite afirmar
que a máquina permaneceu não comprometida durante toda a coleta.
