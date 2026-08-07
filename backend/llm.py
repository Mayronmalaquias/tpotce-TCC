"""
BeeIA — Módulo LLM: geração de relatórios em linguagem natural.

Recebe estatísticas agregadas do banco (distribuição de tipos, IPs mais
ativos, países de origem, features médias comportamentais) e usa a API da
Anthropic para gerar um relatório com sumário executivo, análise técnica e
recomendações de mitigação priorizadas — conforme descrito no artigo do TCC
(Seção 4.5, "Módulo LLM — Relatórios em Linguagem Natural").
"""

import os

import anthropic

MODEL = os.getenv("LLM_MODEL", "claude-haiku-4-5")

SYSTEM_PROMPT = """Você é um analista de segurança sênior do BeeIA, um sistema de honeypots com \
classificação de ataques por Machine Learning. Você recebe estatísticas agregadas de sessões de \
ataque capturadas pelos honeypots Cowrie (SSH/Telnet) e Dionaea (SMB/FTP/MSSQL/MQTT e outros \
serviços vulneráveis emulados) e produz um relatório em português do Brasil, claro e acionável, \
para gestores que não são especialistas técnicos.

O relatório deve ter exatamente três seções, nesta ordem:

1. Sumário Executivo — 2 a 4 frases com os números principais e a gravidade geral do período.
2. Análise Técnica — padrões observados: tipos de ataque predominantes, honeypot de origem \
(Cowrie ou Dionaea), IPs/países mais ativos, indicadores comportamentais (força bruta, reverse \
shell, reconhecimento, varredura de portas, exploits, download de malware).
3. Recomendações de Mitigação — lista priorizada de 3 a 5 ações concretas, da mais urgente à \
menos urgente.

Seja direto e baseie-se apenas nos dados fornecidos. Não invente números. Se os dados forem \
insuficientes, diga isso claramente."""


def _build_prompt(data: dict) -> str:
    """Monta o prompt de usuário a partir dos dados agregados do banco."""
    lines = [
        f"Período analisado: últimas {data['period_hours']} horas.",
        f"Total de ataques (histórico completo): {data['total_attacks']}",
        f"Ataques no período: {data['attacks_period']}",
        f"IPs únicos: {data['unique_ips']}",
        f"IPs bloqueados automaticamente: {data['blocked_count']}",
        "",
        "Distribuição por honeypot de origem:",
    ]
    for honeypot, count in data.get("honeypot_counts", {}).items():
        lines.append(f"  - {honeypot}: {count}")

    lines.append("")
    lines.append("Distribuição por tipo de ataque:")
    for attack_type, count in data["attack_type_distribution"].items():
        pct = (count / data["total_attacks"] * 100) if data["total_attacks"] else 0
        lines.append(f"  - {attack_type}: {count} ({pct:.1f}%)")

    lines.append("")
    lines.append("Top IPs por volume de ataques:")
    for ip in data["top_ips"]:
        lines.append(
            f"  - {ip['src_ip']} ({ip.get('country') or 'país desconhecido'}): "
            f"{ip['count']} ataques, tipos: {ip.get('attack_types') or '-'}, "
            f"bloqueado: {'sim' if ip.get('blocked') else 'não'}"
        )

    if data["countries"]:
        lines.append("")
        lines.append("Países de origem mais frequentes:")
        for country, count in data["countries"].items():
            lines.append(f"  - {country}: {count}")

    feat = data["avg_features"]
    lines.append("")
    lines.append("Indicadores comportamentais médios das sessões:")
    lines.append(f"  - Tentativas de login por sessão: {feat['avg_login_attempts']:.1f}")
    lines.append(f"  - Comandos executados por sessão: {feat['avg_command_count']:.1f}")
    lines.append(f"  - Duração média da sessão: {feat['avg_session_duration_s']:.1f}s")
    lines.append(f"  - Sessões com reverse shell: {feat['reverse_shell_pct']:.1f}%")
    lines.append(f"  - Sessões com wget/curl: {feat['wget_curl_pct']:.1f}%")
    lines.append(f"  - Sessões com comandos de reconhecimento: {feat['recon_pct']:.1f}%")
    lines.append(f"  - Sessões com download de arquivo: {feat['file_download_pct']:.1f}%")

    return "\n".join(lines)


def generate_report(data: dict) -> str:
    """Gera o relatório em linguagem natural a partir dos dados agregados do banco.

    Lança RuntimeError se ANTHROPIC_API_KEY não estiver configurada.
    """
    if not os.getenv("ANTHROPIC_API_KEY"):
        raise RuntimeError(
            "ANTHROPIC_API_KEY não configurada. Defina-a no .env para habilitar o módulo LLM."
        )

    if data["total_attacks"] == 0:
        return (
            "Sumário Executivo: nenhum ataque foi registrado até o momento. "
            "O sistema está ativo e monitorando, mas ainda não há dados suficientes "
            "para uma análise técnica ou recomendações específicas."
        )

    client = anthropic.Anthropic()
    prompt = _build_prompt(data)

    response = client.messages.create(
        model=MODEL,
        max_tokens=1500,
        system=SYSTEM_PROMPT,
        messages=[{"role": "user", "content": prompt}],
    )

    return "".join(block.text for block in response.content if block.type == "text")
