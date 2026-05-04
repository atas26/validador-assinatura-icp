# Passo a passo no Render

1. Crie um repositório no GitHub chamado `validador-assinatura-icp`.
2. Suba todos os arquivos deste pacote para a raiz do repositório.
3. No Render, clique em `New`.
4. Clique em `Web Service`.
5. Selecione o repositório `validador-assinatura-icp`.
6. Configure:

```text
Name: validador-assinatura-icp
Language: Docker
Branch: main
Root Directory: vazio
Plan: Free
```

7. Em variáveis de ambiente, use:

```text
PORT=8080
JAVA_TOOL_OPTIONS=-Dfile.encoding=UTF-8
MAX_FILE_SIZE=50MB
```

8. Clique em `Deploy Web Service`.
9. Ao terminar, teste:

```text
https://SEU-ENDERECO.onrender.com/api/health
```

10. Resultado esperado:

```json
{"ok":true,"service":"validador-assinatura-icp"}
```
