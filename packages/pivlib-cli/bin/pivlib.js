#!/usr/bin/env node
// Tiny launcher: resolves the platform-specific binary subpackage and execs it.
// Subpackages are declared as optionalDependencies; npm installs the one whose
// os/cpu fields match the host, so require.resolve succeeds for exactly one.

const { execFileSync } = require('node:child_process');

const PLATFORMS = {
  'darwin-x64': 'pivlib-cli-darwin-x64',
  'darwin-arm64': 'pivlib-cli-darwin-arm64',
  'linux-x64': 'pivlib-cli-linux-x64-gnu',
  'linux-arm64': 'pivlib-cli-linux-arm64-gnu',
  'win32-x64': 'pivlib-cli-win32-x64-msvc',
};

const key = `${process.platform}-${process.arch}`;
const pkg = PLATFORMS[key];

if (!pkg) {
  console.error(
    `pivlib: unsupported platform ${key}.\n` +
      `Supported: ${Object.keys(PLATFORMS).join(', ')}.\n` +
      `Build from source: https://github.com/ariugwu/pivlib`,
  );
  process.exit(1);
}

const ext = process.platform === 'win32' ? '.exe' : '';
let binary;
try {
  binary = require.resolve(`${pkg}/bin/pivlib${ext}`);
} catch (err) {
  console.error(
    `pivlib: failed to locate native binary in ${pkg}.\n` +
      `This usually means the optional dependency wasn't installed.\n` +
      `Try: npm install --include=optional pivlib-cli\n\n` +
      String(err),
  );
  process.exit(1);
}

try {
  execFileSync(binary, process.argv.slice(2), { stdio: 'inherit' });
} catch (err) {
  const code = typeof err.status === 'number' ? err.status : 1;
  process.exit(code);
}
