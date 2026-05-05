@echo off
echo.
echo ============================================
echo TESTE DO VALIDADOR DE ASSINATURA ICP-BRASIL
echo ============================================
echo.

node -v >nul 2>&1
if errorlevel 1 (
  echo ERRO: Node.js nao encontrado.
  echo Instale o Node.js LTS e tente novamente.
  pause
  exit /b 1
)

if not exist "test-cases.json" (
  echo ERRO: Arquivo test-cases.json nao encontrado.
  echo.
  echo Como corrigir:
  echo 1. Copie o arquivo test-cases.example.json.
  echo 2. Renomeie a copia para test-cases.json.
  echo 3. Ajuste os nomes dos PDFs usados nos testes.
  echo.
  pause
  exit /b 1
)

if not exist "scripts\test-signature-api.mjs" (
  echo ERRO: Script scripts\test-signature-api.mjs nao encontrado.
  echo Verifique se voce esta na pasta correta dos testes.
  pause
  exit /b 1
)

if not exist "test-pdfs" (
  echo ERRO: Pasta test-pdfs nao encontrada.
  pause
  exit /b 1
)

echo Rodando testes contra o Render...
echo.

node scripts/test-signature-api.mjs --base-url https://validador-assinatura-icp.onrender.com --cases test-cases.json --pdf-dir test-pdfs

echo.
echo ============================================
echo FIM DO TESTE
echo ============================================
echo.
echo Se apareceu "4 passou; 0 falhou; 0 ignorado", esta tudo certo.
echo Se apareceu FAIL, ERROR ou SKIP, envie o print antes de publicar.
echo.
pause
