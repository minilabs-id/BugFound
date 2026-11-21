// AgentBug Playwright adapter.
//
// Usage: node playwright-wrapper.js <action> <url> [selector] [output]
// Actions: navigate | click | screenshot
//
// This binary is registered by the operator through
// [external_tools.commands] playwright = "node <wrapper> {action} {url} {selector}".
// It is still subject to AgentBug's scope, method and ROE gates; installing it
// is not an authorization bypass. Output is bounded JSON on stdout.

const { chromium } = require('playwright');

(async () => {
  const [action = 'navigate', url = '', selector = '', output = ''] = process.argv.slice(2);
  if (!url) {
    console.log(JSON.stringify({ ok: false, reason: 'url is required' }));
    process.exit(0);
  }
  const browser = await chromium.launch({ headless: true });
  try {
    const page = await browser.newPage();
    const response = await page.goto(url, {
      waitUntil: 'domcontentloaded',
      timeout: 15000,
    });
    const title = await page.title().catch(() => '');
    const body = (await page.locator('body').innerText().catch(() => '')).slice(0, 8000);
    let clicked = false;
    if (action === 'click') {
      if (!selector) {
        console.log(JSON.stringify({ ok: false, reason: 'selector is required for click' }));
        return;
      }
      await page.click(selector, { timeout: 5000 });
      clicked = true;
    }
    let screenshot = '';
    if (action === 'screenshot') {
      screenshot = output || 'screenshot.png';
      await page.screenshot({ path: screenshot, fullPage: false });
    }
    console.log(
      JSON.stringify({
        ok: true,
        action,
        url,
        status: response ? response.status() : 0,
        title: title.slice(0, 300),
        clicked,
        screenshot,
        body,
      }),
    );
  } finally {
    await browser.close();
  }
})().catch((error) => {
  console.log(JSON.stringify({ ok: false, reason: String(error && error.message ? error.message : error).slice(0, 500) }));
  process.exit(0);
});
