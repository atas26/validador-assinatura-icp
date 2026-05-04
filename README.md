# validador-assinatura-icp

Microserviço Java para prova de conceito de validação de assinatura digital PAdES usando PDFBox e Demoiselle Signer.

## Endpoints

- `GET /api/health`
- `POST /api/validate-signature`, com campo multipart `file`

## Render

Configurar como Docker.

Variáveis:

```env
PORT=8080
JAVA_TOOL_OPTIONS=-Dfile.encoding=UTF-8
MAX_FILE_SIZE=50MB
```

## Observação

Esta versão é uma prova de conceito. Teste com amostra representativa antes de usar em produção. O retorno deve ser conferido com VALIDAR/ITI durante a fase de homologação.
