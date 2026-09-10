# Próxima etapa: validar a coleta real e os resultados

Plano de trabalho após a primeira semana de exposição. As datas efetivas devem
ser extraídas dos logs da VM; o cronograma antigo do TCC1 não define esta etapa.

## 1. Preservar e auditar antes de atualizar

- Registrar commit, alterações locais, serviços, imagens/digests e período de uptime.
- Preservar logs brutos, configurações e modelos; fazer backup consistente do SQLite
  pela API de backup do SQLite, evitando copiar apenas o arquivo principal em uso.
- Guardar backup e hashes fora da VM; não versionar chaves, .env ou downloads de malware.
- Auditar host, logins, persistência, pacotes, isolamento e regras de saída efetivas.
- Inicializar referência de integridade após revisão, anotando que ela é posterior
  à exposição. Verificar timer, primeira execução e exportação externa de evidências.
- Comparar instalação com repositório antes de atualizar; preservar configurações e
  dados, preparar retorno à versão anterior e verificar saúde após a atualização.

## 2. Fechar o período de coleta

Extrair início/fim em UTC, eventos, sessões, IPs únicos, distribuição por honeypot
e por dia, intervalos sem coleta e erros de ingestão. Distinguir eventos de sessões,
logs brutos de registros classificados e tráfego externo de testes próprios.
Não usar o limite de 100 registros do dashboard como total do experimento.

Correlacionar uma amostra entre log original, sessão, banco e dashboard usando
timestamp, honeypot e identificador de sessão. Documentar rotação, duplicações,
sessões incompletas e exclusões. Nenhum total foi verificado na VM nesta preparação.

## 3. Avaliar os classificadores em dados reais

Selecionar amostra estratificada por dia, honeypot e classe prevista. Guardar IDs e
critério de seleção para reprodução. Rotular manualmente a partir dos eventos,
preferencialmente por dois revisores, sem mostrar a previsão na primeira revisão.
Registrar ambiguidades e desacordos; permitir inconclusivo, sem forçar rótulos.

Calcular matriz de confusão, precisão, recall, F1 por classe e macro-F1, com tamanho
da amostra e limitações. Uma amostra balanceada artificialmente não representa a
frequência das classes na população: reportar a estratégia de amostragem.
Separar esses resultados dos testes sintéticos e da confiança prevista pelo modelo.
Manter avaliação final separada de dados usados para ajustar modelos ou regras.

## 4. Entregar evidências ao orientador

Preparar relatório com período real, proveniência dos dados, auditoria e suas
limitações, evidência do monitor periódico, gráficos derivados dos dados exportados,
erros de classificação revisados e comparação entre resultados sintéticos e reais.
Medir latência com teste controlado identificado e relógios sincronizados; não
repetir alegações de latência ou acurácia sem medição reproduzível.

Critério para avançar: coleta rastreável, contenção verificada, monitor operacional
e primeira avaliação manual concluída. Só então decidir se os erros observados
justificam retreino ou ajustes de features.
