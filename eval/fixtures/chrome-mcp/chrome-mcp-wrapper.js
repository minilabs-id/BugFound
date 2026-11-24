// BugFound browser adapter backed by Google's chrome-devtools-mcp CLI.
// No browser extension; the CLI drives Chrome over DevTools Protocol.
//
// Usage: node chrome-mcp-wrapper.js <action> <url> [selector] [output]

const { spawnSync } = require('child_process');
const path = require('path');

const [action = 'navigate', url = '', selector = '', output = ''] = process.argv.slice(2);
const prefix = __dirname;

const npmCli = process.platform === 'win32' ? 'npx.cmd' : 'npx';

function run(args) {
  const result = spawnSync(npmCli, ['chrome-devtools', ...args], {
    cwd: prefix,
    encoding: 'utf8',
    timeout: 60000,
    maxBuffer: 2 * 1024 * 1024,
    shell: process.platform === 'win32',
    env: { ...process.env, CI: '1' },
  });
  const stdout = (result.stdout || '').slice(0, 8000);
  const stderr = (result.stderr || '').slice(0, 1000);
  return { status: result.status, stdout, stderr };
}

function emit(value) {
  process.stdout.write(JSON.stringify(value));
}

if (!url) {
  emit({ ok: false, reason: 'url is required' });
  process.exit(0);
}

if (!['navigate', 'click', 'screenshot'].includes(action)) {
  emit({ ok: false, reason: 'unsupported action' });
  process.exit(0);
}

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
  const shot = run(['take_screenshot', '1', '--filePath', output || 'screenshot.png', '--output-format', 'md']);
  emit({ ok: shot.status === 0, stdout: shot.stdout, stderr: shot.stderr });
  process.exit(0);
}

if (!selector || /['"\n\r]/.test(selector)) {
  emit({ ok: false, reason: 'selector is required and must not contain quotes' });
  process.exit(0);
}
const script = `document.querySelector('${selector}').click(); return 'clicked';`;
const clicked = run(['evaluate_script', script, '--output-format', 'md']);
emit({ ok: clicked.status === 0, stdout: clicked.stdout, stderr: clicked.stderr });
