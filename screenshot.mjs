import puppeteer from 'puppeteer-core';
import fs from 'fs';
import path from 'path';

const outDir = '/home/nonrootiamatto01/.gemini/antigravity/brain/94edefdc-363e-4953-988a-cb6db0f000f1';
if (!fs.existsSync(outDir)) {
  fs.mkdirSync(outDir, { recursive: true });
}

async function run() {
  const browser = await puppeteer.launch({
    executablePath: '/usr/bin/chromium',
    args: ['--no-sandbox', '--disable-setuid-sandbox']
  });
  
  const page = await browser.newPage();
  await page.setViewport({ width: 1280, height: 800 });

  // 1. Home
  await page.goto('http://localhost:5173/');
  await new Promise(r => setTimeout(r, 2000));
  await page.screenshot({ path: path.join(outDir, '01_Home.png') });
  console.log('Saved 01_Home.png');

  // 2. Subscription
  await page.goto('http://localhost:5173/subscription');
  await new Promise(r => setTimeout(r, 2000));
  await page.screenshot({ path: path.join(outDir, '02_Subscription.png') });
  console.log('Saved 02_Subscription.png');

  // 3. Login Page
  await page.goto('http://localhost:5173/login');
  await new Promise(r => setTimeout(r, 2000));
  await page.screenshot({ path: path.join(outDir, '03_Login.png') });
  console.log('Saved 03_Login.png');

  // 4. Admin Login
  await page.type('input[placeholder="Enter username"]', 'admin');
  await page.type('input[placeholder="Enter password"]', 'admin');
  await page.click('button[type="submit"]');
  await new Promise(r => setTimeout(r, 3000)); // wait for dashboard

  // 5. Admin Dashboard
  await page.screenshot({ path: path.join(outDir, '04_Admin_Dashboard.png') });
  console.log('Saved 04_Admin_Dashboard.png');

  // 6. Admin Projects
  await page.goto('http://localhost:5173/projects');
  await new Promise(r => setTimeout(r, 2000));
  await page.screenshot({ path: path.join(outDir, '05_Admin_Projects.png') });
  console.log('Saved 05_Admin_Projects.png');

  // 7. Admin Scan
  await page.goto('http://localhost:5173/scan');
  await new Promise(r => setTimeout(r, 2000));
  await page.screenshot({ path: path.join(outDir, '06_Admin_Scan.png') });
  console.log('Saved 06_Admin_Scan.png');

  // 8. Admin Vulnerabilities
  await page.goto('http://localhost:5173/vulnerabilities');
  await new Promise(r => setTimeout(r, 2000));
  await page.screenshot({ path: path.join(outDir, '07_Admin_Vulnerabilities.png') });
  console.log('Saved 07_Admin_Vulnerabilities.png');

  // 9. Admin Settings
  await page.goto('http://localhost:5173/settings');
  await new Promise(r => setTimeout(r, 2000));
  await page.screenshot({ path: path.join(outDir, '08_Admin_Settings.png') });
  console.log('Saved 08_Admin_Settings.png');

  // Logout (clear local storage and reload login)
  await page.evaluate(() => localStorage.clear());
  
  // 10. Client Login
  await page.goto('http://localhost:5173/login');
  await new Promise(r => setTimeout(r, 2000));
  
  // Try to find Client login tab if exists. Assuming there's a button/tab with text 'Client Portal'
  const buttons = await page.$$('button');
  for (const btn of buttons) {
    const text = await page.evaluate(el => el.textContent, btn);
    if (text === 'Client Portal') {
      await btn.click();
      await new Promise(r => setTimeout(r, 1000));
      break;
    }
  }
  
  await page.type('input[type="email"]', 'john@techcorp.com');
  
  await page.click('button[type="submit"]');
  await new Promise(r => setTimeout(r, 3000));

  // 11. Client Dashboard
  await page.screenshot({ path: path.join(outDir, '09_Client_Dashboard.png') });
  console.log('Saved 09_Client_Dashboard.png');

  await browser.close();
}

run().catch(console.error);
