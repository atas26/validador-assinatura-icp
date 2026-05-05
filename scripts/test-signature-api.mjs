#!/usr/bin/env node
import fs from 'node:fs/promises';
import path from 'node:path';
import process from 'node:process';

function getArg(name, fallback) {
  const idx = process.argv.indexOf(name);
  if (idx >= 0 && process.argv[idx + 1]) return process.argv[idx + 1];
  return fallback;
}

function normalizeBaseUrl(value) {
  return String(value || '').replace(/\/+$/, '');
}

function asArray(value) {
  if (Array.isArray(value)) return value;
  if (value === undefined || value === null) return [];
  return [value];
}

function getNested(obj, dottedPath) {
  return dottedPath.split('.').reduce((acc, key) => {
    if (acc === undefined || acc === null) return undefined;
    if (/^\d+$/.test(key) && Array.isArray(acc)) return acc[Number(key)];
    return acc[key];
  }, obj);
}

function assertEqual(label, actual, expected, failures) {
  if (expected === undefined) return;
  if (actual !== expected) {
    failures.push(`${label}: esperado ${JSON.stringify(expected)}, recebido ${JSON.stringify(actual)}`);
  }
}

function assertOneOf(label, actual, expectedList, failures) {
  const list = asArray(expectedList);
  if (!list.length) return;
  if (!list.includes(actual)) {
    failures.push(`${label}: esperado um de ${JSON.stringify(list)}, recebido ${JSON.stringify(actual)}`);
  }
}

function assertIncludes(label, actual, expectedText, failures) {
  if (!expectedText) return;
  if (!String(actual || '').includes(expectedText)) {
    failures.push(`${label}: esperado conter ${JSON.stringify(expectedText)}, recebido ${JSON.stringify(actual)}`);
  }
}

function evaluateCase(testCase, json) {
  const failures = [];

  assertOneOf('result', json.result, testCase.expectedResultOneOf, failures);
  assertEqual('valid', json.valid, testCase.expectedValid, failures);
  assertEqual('icpBrasil', json.icpBrasil, testCase.expectedIcpBrasil, failures);
  assertEqual('chainValid', json.chainValid, testCase.expectedChainValid, failures);
  assertEqual('revocationChecked', json.revocationChecked, testCase.expectedRevocationChecked, failures);
  assertEqual('revoked', json.revoked, testCase.expectedRevoked, failures);
  assertOneOf('revocationMethod', json.revocationMethod, testCase.expectedRevocationMethodOneOf, failures);
  assertOneOf('standard', json.standard, testCase.expectedStandardOneOf, failures);
  assertEqual('finalDocumentAcceptable', json.finalDocumentAcceptable, testCase.expectedFinalDocumentAcceptable, failures);
  assertOneOf('postSignatureUpdateType', json.postSignatureUpdateType, testCase.expectedPostSignatureUpdateTypeOneOf, failures);
  assertEqual('timestampPresent', json.timestampPresent, testCase.expectedTimestampPresent, failures);
  assertEqual('timestampValid', json.timestampValid, testCase.expectedTimestampValid, failures);
  assertEqual('policyDeclared', json.policyDeclared, testCase.expectedPolicyDeclared, failures);
  assertEqual('policyRecognized', json.policyRecognized, testCase.expectedPolicyRecognized, failures);
  assertIncludes('message', json.message, testCase.expectedMessageIncludes, failures);

  for (const check of asArray(testCase.customChecks)) {
    const actual = getNested(json, check.path);
    if ('equals' in check) assertEqual(check.path, actual, check.equals, failures);
    if ('oneOf' in check) assertOneOf(check.path, actual, check.oneOf, failures);
    if ('includes' in check) assertIncludes(check.path, actual, check.includes, failures);
  }

  return failures;
}

async function loadCases(casesPath) {
  const raw = await fs.readFile(casesPath, 'utf8');
  const parsed = JSON.parse(raw);
  if (!Array.isArray(parsed.tests)) {
    throw new Error('O arquivo de casos deve conter um array em "tests".');
  }
  return parsed.tests;
}

async function healthCheck(baseUrl) {
  const url = `${baseUrl}/api/health`;
  const response = await fetch(url, { method: 'GET' });
  if (!response.ok) {
    throw new Error(`Health check falhou: HTTP ${response.status}`);
  }
  const text = await response.text();
  return text;
}

async function validatePdf(baseUrl, pdfPath) {
  const buffer = await fs.readFile(pdfPath);
  const blob = new Blob([buffer], { type: 'application/pdf' });
  const form = new FormData();
  form.append('file', blob, path.basename(pdfPath));

  const response = await fetch(`${baseUrl}/api/validate-signature`, {
    method: 'POST',
    body: form
  });

  const text = await response.text();
  let json;
  try {
    json = JSON.parse(text);
  } catch {
    throw new Error(`Resposta não JSON. HTTP ${response.status}. Corpo: ${text.slice(0, 500)}`);
  }

  if (!response.ok) {
    throw new Error(`HTTP ${response.status}: ${JSON.stringify(json).slice(0, 800)}`);
  }

  return json;
}

async function main() {
  const baseUrl = normalizeBaseUrl(getArg('--base-url', process.env.SIGNATURE_VALIDATOR_URL || 'http://localhost:8080'));
  const casesPath = getArg('--cases', 'test-cases.json');
  const pdfDir = getArg('--pdf-dir', 'test-pdfs');

  console.log(`Base URL: ${baseUrl}`);
  console.log(`Casos: ${casesPath}`);
  console.log(`PDFs: ${pdfDir}`);

  const health = await healthCheck(baseUrl);
  console.log(`Health OK: ${health.slice(0, 200)}`);

  const tests = await loadCases(casesPath);
  let passed = 0;
  let failed = 0;
  let skipped = 0;

  for (const testCase of tests) {
    const label = testCase.name || testCase.file;
    const pdfPath = path.resolve(pdfDir, testCase.file);

    try {
      await fs.access(pdfPath);
    } catch {
      skipped += 1;
      console.log(`SKIP ${label}: arquivo não encontrado em ${pdfPath}`);
      continue;
    }

    try {
      const json = await validatePdf(baseUrl, pdfPath);
      const failures = evaluateCase(testCase, json);

      if (failures.length) {
        failed += 1;
        console.log(`FAIL ${label}`);
        failures.forEach(item => console.log(`  - ${item}`));
        console.log(`  result=${json.result}; standard=${json.standard}; valid=${json.valid}; icpBrasil=${json.icpBrasil}; revocation=${json.revocationMethod}/${json.revoked}; timestamp=${json.timestampPresent}/${json.timestampValid}; policy=${json.policyDeclared}/${json.policyRecognized}`);
      } else {
        passed += 1;
        console.log(`PASS ${label} | result=${json.result} | standard=${json.standard}`);
      }
    } catch (err) {
      failed += 1;
      console.log(`ERROR ${label}: ${err.message}`);
    }
  }

  console.log('');
  console.log(`Resumo: ${passed} passou; ${failed} falhou; ${skipped} ignorado.`);

  if (failed > 0) process.exit(1);
}

main().catch(err => {
  console.error(`Erro geral: ${err.message}`);
  process.exit(1);
});
