# Guia de Implementação e Teste: Honeypot Cowrie

Este documento descreve as etapas técnicas para a implantação do Honeypot Cowrie utilizando Docker, focado na coleta de dados para detecção de anomalias com IA.

---

## 1. Preparação da Infraestrutura

Antes de iniciar o container, é necessário preparar o ambiente de persistência de dados no host (VM Linux).

```bash
# Criar diretórios para armazenar logs e arquivos capturados
mkdir -p ~/cowrie-data/logs ~/cowrie-data/downloads

# Ajustar permissões para garantir que o Docker possa escrever nos volumes
sudo chmod -R 777 ~/cowrie-data
```

## 2. Implantação do Container (Docker)

A execução utiliza a imagem oficial do Cowrie, mapeando as portas padrão de SSH e Telnet para o serviço do Honeypot.

```bash
docker run -d \
  --name cowrie-tcc \
  --restart always \
  -p 22:2222 \
  -p 23:2223 \
  -v ~/cowrie-data/logs:/cowrie/cowrie-server/var/log/cowrie \
  -v ~/cowrie-data/downloads:/cowrie/cowrie-server/var/lib/cowrie/downloads \
  cowrie/cowrie:latest
```

### Detalhes dos Parâmetros:

* `-d`: Executa em segundo plano (detached).
* `-p 22:2222`: Redireciona o tráfego da porta 22 (SSH real) para a 2222 (SSH falso).
* `-v`: Mapeia volumes para que os logs fiquem salvos permanentemente na VM.

## 3. Protocolo de Teste e Validação

Para validar a captura de dados, deve-se simular uma intrusão a partir de uma máquina externa (ex: Windows via CMD).

### Passo A: Conexão Inicial

```bash
# No terminal da máquina atacante
ssh root@[IP_DA_VM] -p 22
```

**Nota:** Caso receba erro de "Host Identification Changed", limpe a chave com `ssh-keygen -R [IP_DA_VM]`.

### Passo B: Interação (Geração de Dados)

Uma vez dentro do shell falso, execute comandos para gerar logs de atividade:

```bash
whoami
ls -la
cat /etc/passwd
exit
```

## 4. Verificação de Resultados (Análise Forense)

Após o encerramento da sessão, os logs estarão disponíveis na VM para análise.

### Visualizar Log de Comandos (JSON)

Este arquivo é o dataset principal para o treinamento da Inteligência Artificial.

```bash
cat ~/cowrie-data/logs/cowrie.json
```

### Campos Importantes para IA:

* `eventid`: Tipo de evento (login, comando, download).
* `input`: O comando exato digitado pelo usuário/bot.
* `src_ip`: Origem do ataque.
* `timestamp`: Momento exato da interação.

## 5. Manutenção

```bash
# Verificar status
docker ps

# Verificar logs do sistema
docker logs cowrie-tcc

# Reiniciar serviço
docker restart cowrie-tcc
```

---

### Próximo passo para o seu TCC

Agora que a coleta está automatizada, você pode avançar para a etapa de tratamento dos logs e modelagem de detecção de anomalias com IA.
