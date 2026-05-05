# Testes automatizados do validador de assinatura ICP-Brasil

Este diretório contém uma rotina simples de testes para o serviço `validador-assinatura-icp`.

O objetivo é verificar, antes de novas publicações, se o serviço continua validando corretamente os principais cenários de assinatura digital em PDF.

## O que os testes verificam

A rotina chama o endpoint:

```text
/api/validate-signature
