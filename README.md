# validador-assinatura-icp

Microserviço Java inicial para triagem de assinatura digital embutida em PDF.

## Endpoints

- `GET /api/health`
- `POST /api/validate-signature`, campo multipart `file`

## Estado atual

Esta base publica o microserviço Java no Render e identifica assinaturas digitais embutidas no PDF usando Apache PDFBox.

Ela ainda não faz validação ICP-Brasil definitiva. A próxima fase é integrar Demoiselle Signer na classe `SignatureValidationService`.

## Teste local com Docker

```bash
docker build -t validador-assinatura-icp .
docker run -p 8080:8080 validador-assinatura-icp
```

Teste:

```bash
curl http://localhost:8080/api/health
```

Envio de PDF:

```bash
curl -F "file=@documento.pdf" http://localhost:8080/api/validate-signature
```
