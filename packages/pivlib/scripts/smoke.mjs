import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { dirname, resolve } from 'node:path';

import { detect, parseCert, classifyPivRole, parseChuid } from '../dist/index.node.js';

const here = dirname(fileURLToPath(import.meta.url));
const fixtures = resolve(here, '../../../tests/fixtures');

let pass = 0;
let fail = 0;

function check(name, cond, detail) {
  if (cond) {
    pass++;
    console.log(`  ok  ${name}`);
  } else {
    fail++;
    console.log(`  FAIL ${name}${detail ? ` — ${detail}` : ''}`);
  }
}

async function smoke() {
  // We ship a tiny synthetic DER blob so the smoke test passes even without
  // real-world fixtures. Replace with real PIV certs once they're in tests/fixtures/.
  console.log('• detect — empty input rejects');
  let caught = false;
  try {
    detect(new Uint8Array(0));
  } catch {
    caught = true;
  }
  check('empty rejects', caught);

  console.log('• detect — DER passthrough');
  // SEQUENCE { OCTET STRING {} } — 4 bytes total
  const der = new Uint8Array([0x30, 0x02, 0x04, 0x00]);
  const r = detect(der);
  check('format is der', r.format.kind === 'der');
  check('normalized non-empty', r.normalized_der.length > 0);

  console.log('• detect — base64 envelope with whitespace');
  // 0x30 0x02 0x04 0x00 → "MAIEAA==" → wrap with whitespace
  const b64 = '  MAIE\nAA==\n';
  const r2 = detect(b64);
  check('format is base64-of-der', r2.format.kind === 'base64-of-der');
  check('warns about whitespace', r2.warnings.some(w => w.includes('whitespace')));

  console.log(`\n${pass} passed, ${fail} failed`);
  if (fail > 0) process.exit(1);
}

smoke().catch((e) => {
  console.error('smoke crashed:', e);
  process.exit(2);
});
