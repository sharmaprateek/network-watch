import { chromium } from 'playwright';

const url = process.env.NW_URL || 'http://192.168.235.175:8787/';
const out = process.env.NW_OUT || 'docs/assets/dashboard.png';

const browser = await chromium.launch();
const page = await browser.newPage({ viewport: { width: 1400, height: 900 } });

await page.goto(url, { waitUntil: 'networkidle', timeout: 60_000 });
await page.waitForTimeout(1000);

// Prefer full page so the header + key sections appear.
await page.screenshot({ path: out, fullPage: true });

await browser.close();
console.log(`Wrote ${out} from ${url}`);
