// BugFound browser adapter backed by Google's chrome-devtools-mcp CLI.
// No browser extension; the CLI drives Chrome over DevTools Protocol.
//
// Usage: node chrome-mcp-wrapper.js <action> <url> [selector] [output]
//
// Security: every value from argv stays a separate argv token and no shell is
// involved. URLs are parsed and restricted to http/https without control
// characters or whitespace; selectors are embedded in generated JavaScript
// with JSON.stringify (no quote blacklist and no shell interpolation).

const { spawnSync } = require('child_process');
const path = require('path');

const [action = 'navigate', url = '', selector = '', output = ''] = process.argv.slice(2);
const prefix = __dirname;

function emit(value) {
  process.stdout.write(JSON.stringify(value));
}

function fail(reason) {
  emit({ ok: false, reason });
  process.exit(0);
}

function validUrl(raw) {
  if (!raw || /[\s\u0000-\u001f\u007f]/.test(raw)) return false;
  let parsed;
  try {
    parsed = new URL(raw);
  } catch {
    return false;
  }
  return parsed.protocol === 'http:' || parsed.protocol === 'https:';
}

function cliPath() {
  try {
    const pkgPath = require.resolve('chrome-devtools-mcp/package.json', {
      paths: [prefix, process.cwd()],
    });
    const pkg = require(pkgPath);
    const bin = typeof pkg.bin === 'string' ? pkg.bin : pkg.bin && pkg.bin['chrome-devtools'];
    return bin ? path.resolve(path.dirname(pkgPath), bin) : null;
  } catch {
    return null;
  }
}

const cli = cliPath();

function run(args) {
  if (!cli) return { status: 1, stdout: '', stderr: 'chrome-devtools-mcp CLI not installed' };
  const result = spawnSync(process.execPath, [cli, ...args], {
    cwd: prefix,
    encoding: 'utf8',
    timeout: 60000,
    maxBuffer: 2 * 1024 * 1024,
    shell: false,
    env: { ...process.env, CI: '1' },
  });
  const stdout = (result.stdout || '').slice(0, 8000);
  const stderr =
    (result.error ? String(result.error.message) + '\n' : '') +
    (result.stderr || '').slice(0, 1000);
  return { status: result.status, stdout, stderr };
}

if (!url) fail('url is required');
if (!validUrl(url)) fail('url must be an http/https URL without control chars or whitespace');
if (!['navigate', 'click', 'screenshot'].includes(action)) fail('unsupported action');

const nav = run(['navigate_page', '1', '--url', url, '--output-format', 'md']);
if (action === 'navigate') {
  if (nav.status !== 0) {
    emit({ ok: false, reason: 'navigate failed', stderr: nav.stderr });
  } else {
    const snap = run(['take_snapshot', '1', '--output-format', 'md']);
    emit({ ok: snap.status === 0, stdout: snap.stdout, stderr: snap.stderr });
  }
  process.exit(0);
}

if (action === 'screenshot') {
  const shot = run([
    'take_screenshot',
    '1',
    '--filePath',
    output || 'screenshot.png',
    '--output-format',
    'md',
  ]);
  emit({ ok: shot.status === 0, stdout: shot.stdout, stderr: shot.stderr });
  process.exit(0);
}

if (!selector) fail('selector is required for click');
// JSON.stringify yields a valid JS string literal for any selector value.
const jsSelector = JSON.stringify(selector)
  .replace(/\u2028/g, '\\u2028')
  .replace(/\u2029/g, '\\u2029');
const script = `document.querySelector(${jsSelector}).click(); return 'clicked';`;
const clicked = run(['evaluate_script', script, '--output-format', 'md']);
emit({ ok: clicked.status === 0, stdout: clicked.stdout, stderr: clicked.stderr });
