# Próximo passo: validação PAdES com Demoiselle Signer

Esta versão adiciona dependências do Demoiselle Signer e tenta validar a assinatura PAdES extraindo do PDF:

- conteúdo assinado
- assinatura embutida

A validação usa o Demoiselle por reflexão para reduzir risco de erro de compilação por mudança de API.

## Resultado esperado

Se o Demoiselle validar a assinatura e identificar certificado ICP-Brasil, o retorno deve indicar:

```json
{
  "result": "valid_icp_brasil",
  "valid": true,
  "icpBrasil": true,
  "validationLevel": "demoiselle_pades"
}
```

Se a assinatura for detectada, mas a validação não for concluída, o retorno continuará controlado, com `warnings` explicando o motivo.

## Teste obrigatório

Compare os resultados com o VALIDAR do ITI antes de usar como validação final.
