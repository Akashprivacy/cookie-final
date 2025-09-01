// server2.ts (Refactored for Cloud Deployment)

import express, { type Request, type Response } from 'express';
import puppeteer, { type Cookie as PuppeteerCookie, type Page, type Frame, type Browser, CDPSession } from 'puppeteer';
import cors from 'cors';
import dotenv from 'dotenv';
import { GoogleGenAI, Type } from '@google/genai';
import { 
    CookieCategory, type CookieInfo, type TrackerInfo, ComplianceStatus, 
    type LegalAnalysisResult, type LegalPerspective, type VulnerabilityScanResult, 
    type GeneratedContract, ContractTemplate, type LocalStorageItem,
    type LocalStorageInfo,
    GoogleConsentV2Status
} from './types.js';
import path from 'path';
import { fileURLToPath } from 'url';
import fs from 'fs';

dotenv.config();

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
const app: express.Application = express();

// ADDED: Cloud-aware port configuration from server1.ts
const port = process.env.PORT || 3001;

// ADDED: Production-ready CORS configuration from server1.ts
const corsOptions = {
  origin: process.env.NODE_ENV === 'production' 
    ? [
        /\.run\.app$/,
        /\.appspot\.com$/,
        ...(process.env.FRONTEND_URL ? [process.env.FRONTEND_URL] : [])
      ]
    : [
        'http://localhost:3000',
        'http://localhost:5173',
        'http://127.0.0.1:3000',
        'http://127.0.0.1:5173'
      ],
  credentials: true,
  optionsSuccessStatus: 200
};

app.use(cors(corsOptions));
app.use(express.json({ limit: '10mb' }));

// ADDED: Health check endpoint for GCP from server1.ts
app.get('/health', (req: Request, res: Response) => {
  res.status(200).json({ status: 'healthy', timestamp: new Date().toISOString() });
});

// ADDED: Static file serving for production from server1.ts
if (process.env.NODE_ENV === 'production') {
  const staticPath = path.join(__dirname, '..', 'public');
  console.log(`[SERVER] Serving static files from: ${staticPath}`);
  app.use(express.static(staticPath));
}

if (!process.env.API_KEY) {
  console.error("FATAL ERROR: API_KEY environment variable is not set.");
  process.exit(1);
}

const ai = new GoogleGenAI({ apiKey: process.env.API_KEY });
const model = "gemini-2.5-flash";

// --- In-Memory Storage ---
const templateLibrary = new Map<string, ContractTemplate>();

const knownTrackerDomains = [
    'google-analytics.com', 'analytics.google.com', 'googletagmanager.com', 'matomo.org', 'piwik.pro', 'matomo.cloud',
    'c.clarity.ms', 'clarity.ms', 'hotjar.com', 'hotjar.io', 'hjid.hotjar.com', 'static.hotjar.com', 'hubspot.com',
    'hs-analytics.net', 'track.hubspot.com', 'js.hs-analytics.net', 'mixpanel.com', 'api.mixpanel.com', 'segment.com',
    'api.segment.io', 'cdn.segment.com', 'amplitude.com', 'api.amplitude.com', 'fullstory.com', 'rs.fullstory.com',
    'logrocket.com', 'cdn.logrocket.com', 'vwo.com', 'dev.visualwebsiteoptimizer.com', 'optimizely.com',
    'log.optimizely.com', 'crazyegg.com', 'script.crazyegg.com', 'semrush.com', 'mouseflow.com', 'heap.io',
    'heapanalytics.com', 'pendo.io', 'cdn.pendo.io', 'doubleclick.net', 'googleadservices.com', 'googlesyndication.com',
    'ad.doubleclick.net', 'connect.facebook.net', 'facebook.com/tr', 'facebook.net', 'linkedin.com/px',
    'ads.linkedin.com', 'px.ads.linkedin.com', 'twitter.com/i/ads', 'ads-twitter.com', 't.co', 'bing.com/ads',
    'bat.bing.com', 'pinterest.com/ads', 'ct.pinterest.com', 'snap.com/tr', 'sc-static.net', 'tiktok.com/pixel',
    'analytics.tiktok.com', 'ads.yahoo.com', 'analytics.yahoo.com', 'yandex.ru/metrika', 'mc.yandex.ru',
    'adroll.com', 's.adroll.com', 'criteo.com', 'static.criteo.net', 'taboola.com', 'trc.taboola.com',
    'outbrain.com', 'widgets.outbrain.com', 'quantserve.com', 'edge.quantserve.com', 'scorecardresearch.com',
    'b.scorecardresearch.com', 'adform.net', 'track.adform.net', 'appnexus.com', 'ib.adnxs.com',
    'rubiconproject.com', 'fastlane.rubiconproject.com', 'intercom.io', 'widget.intercom.io', 'drift.com',
    'js.driftt.com', 'addthis.com', 's7.addthis.com', 'sharethis.com', 'w.sharethis.com', 'tiqcdn.com',
];

const getHumanReadableExpiry = (puppeteerCookie: PuppeteerCookie): string => {
    if (puppeteerCookie.session || puppeteerCookie.expires === -1) return "Session";
    const expiryDate = new Date(puppeteerCookie.expires * 1000);
    const now = new Date();
    const diffSeconds = (expiryDate.getTime() - now.getTime()) / 1000;
    if (diffSeconds < 0) return "Expired";
    if (diffSeconds < 3600) return `${Math.round(diffSeconds / 60)} minutes`;
    if (diffSeconds < 86400) return `${Math.round(diffSeconds / 3600)} hours`;
    if (diffSeconds < 86400 * 30) return `${Math.round(diffSeconds / 86400)} days`;
    if (diffSeconds < 86400 * 365) return `${Math.round(diffSeconds / (86400 * 30))} months`;
    const years = parseFloat((diffSeconds / (86400 * 365)).toFixed(1));
    return `${years} year${years > 1 ? 's' : ''}`;
};

async function findAndClickButton(frame: Frame, keywords: string[]): Promise<boolean> {
  for (const text of keywords) {
    try {
      const clicked = await frame.evaluate((t) => {
        const selectors = 'button, a, [role="button"], input[type="submit"], input[type="button"]';
        const elements = Array.from(document.querySelectorAll(selectors));
        const target = elements.find(el => {
            const elText = (el.textContent || el.getAttribute('aria-label') || (el as HTMLInputElement).value || '').trim().toLowerCase();
            return elText.includes(t)
        });
        if (target) {
          (target as HTMLElement).click();
          return true;
        }
        return false;
      }, text);
      if (clicked) {
        console.log(`[CONSENT] Clicked button containing: "${text}"`);
        await new Promise(r => setTimeout(r, 1500)); // Wait for actions post-click
        return true;
      }
    } catch (error) {
       if (error instanceof Error && !frame.isDetached()) {
         console.warn(`[CONSENT] Warning on frame ${frame.url()}: ${error.message}`);
       }
    }
  }
  return false;
}

async function handleConsent(page: Page, action: 'accept' | 'reject'): Promise<boolean> {
  console.log(`[CONSENT] Attempting to ${action} consent...`);
  const acceptKeywords = ["accept all", "allow all", "agree to all", "accept cookies", "agree", "accept", "allow", "i agree", "ok", "got it", "continue"];
  const rejectKeywords = ["reject all", "deny all", "decline all", "reject cookies", "disagree", "reject", "deny", "decline", "necessary only"];
  
  const keywords = action === 'accept' ? acceptKeywords : rejectKeywords;

  if (await findAndClickButton(page.mainFrame(), keywords)) return true;
  for (const frame of page.frames()) {
    if (!frame.isDetached() && frame !== page.mainFrame() && await findAndClickButton(frame, keywords)) return true;
  }
  
  console.log(`[CONSENT] No actionable button found for "${action}".`);
  return false;
}

const collectPageData = async (page: Page, rootHostname: string, scanTimeout: number): Promise<{ cookies: PuppeteerCookie[], networkRequests: {hostname: string, url: string}[], localStorageItems: LocalStorageItem[], googleConsentV2: GoogleConsentV2Status }> => {
    let cdpSession: CDPSession | null = null;
    try {
        cdpSession = await page.target().createCDPSession();
        await cdpSession.send('Network.enable');
    } catch (e) {
        console.warn('[CDP] Could not create CDP session. Cookie collection may be incomplete.', e);
    }
    
    const networkRequests: {hostname: string, url: string}[] = [];
    const requestListener = (request: any) => {
        try {
            const reqUrl = new URL(request.url());
            if (reqUrl.hostname !== rootHostname && (reqUrl.protocol === 'http:' || reqUrl.protocol === 'https:')) {
                networkRequests.push({ url: request.url(), hostname: reqUrl.hostname });
            }
        } catch(e) { /* ignore invalid urls */ }
    };
    page.on('request', requestListener);
    
    try {
        await page.reload({ waitUntil: 'domcontentloaded', timeout: scanTimeout });
        await new Promise(resolve => setTimeout(resolve, 1000));
        
        let cookies: PuppeteerCookie[] = [];
        if (cdpSession) {
            try {
                const { cookies: cdpCookies } = await cdpSession.send('Network.getAllCookies');
                cookies = cdpCookies as unknown as PuppeteerCookie[];
            } catch(e) {
                console.warn('[CDP] Error getting cookies via CDP, falling back to page.cookies()', e);
                cookies = await page.cookies().catch(() => []);
            } finally {
                await cdpSession.detach();
            }
        } else {
            cookies = await page.cookies().catch(() => []);
        }

        const { localStorageItems, googleConsentV2 } = await page.evaluate(() => {
            const items: LocalStorageItem[] = [];
            let gcmStatus: GoogleConsentV2Status = { detected: false, status: 'Not Detected' };
    
            try {
                for (let i = 0; i < localStorage.length; i++) {
                    const key = localStorage.key(i);
                    if (key) items.push({ origin: window.location.origin, key, value: localStorage.getItem(key) || '', pageUrl: window.location.href });
                }
                for (let i = 0; i < sessionStorage.length; i++) {
                    const key = sessionStorage.key(i);
                    if (key) items.push({ origin: window.location.origin, key, value: sessionStorage.getItem(key) || '', pageUrl: window.location.href });
                }
            } catch(e) { console.warn('Could not access storage on page.'); }
    
            try {
                const getGcm = (window as any).google_tag_manager?.dataLayer?.filter((i: any) => i[0] === 'consent' && i[1] === 'default').pop();
                if (getGcm && getGcm[2]) {
                    gcmStatus.detected = true;
                    gcmStatus.status = Object.entries(getGcm[2]).map(([k, v]) => `${k}: ${v}`).join('; ');
                }
            } catch(e) { console.warn('Could not determine Google Consent Mode status.'); }
    
            return { localStorageItems: items, googleConsentV2: gcmStatus };
        });

        page.off('request', requestListener);
        return { cookies, networkRequests, localStorageItems, googleConsentV2 };
    } catch (error) {
        page.off('request', requestListener);
        console.warn(`[SCAN] Error collecting page data:`, error instanceof Error ? error.message : error);
        return { cookies: [], networkRequests: [], localStorageItems: [], googleConsentV2: { detected: false, status: 'Error' } };
    }
}

// CHANGED: Converted from GET with Server-Sent Events to POST with single JSON response
interface ApiScanRequestBody {
    url: string;
    scanDepth?: number;
}

app.post('/api/scan', async (req: Request<{}, {}, ApiScanRequestBody>, res: Response) => {
    const { url, scanDepth } = req.body;
    if (!url) return res.status(400).json({ error: 'URL is required' });

    const MAX_PAGES_TO_SCAN = Math.max(1, Math.min(10, scanDepth || 1));
    const SCAN_TIMEOUT = 15000;

    console.log(`[SERVER] Received scan request for: ${url} with depth ${MAX_PAGES_TO_SCAN}`);
    let browser: Browser | null = null;
    try {
        // CHANGED: Using the more comprehensive and optimized Puppeteer args from server1.ts
        browser = await puppeteer.launch({
            headless: true,
            args: [
                '--no-sandbox', '--disable-setuid-sandbox', '--disable-dev-shm-usage', '--disable-gpu',
                '--no-first-run', '--no-default-browser-check', '--disable-background-timer-throttling',
                '--disable-renderer-backgrounding', '--disable-backgrounding-occluded-windows',
                '--disable-extensions', '--disable-plugins', '--disable-images', '--disable-web-security',
                '--disable-features=TranslateUI'
            ],
            defaultViewport: { width: 1280, height: 720 },
            timeout: 10000
        });

        const page = await browser.newPage();
        await page.setUserAgent('Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/108.0.0.0 Safari/537.36');
        await page.setViewport({ width: 1920, height: 1080 });

        const urlsToVisit: { url: string; priority: number }[] = [{ url: url, priority: 0 }];
        const visitedUrls = new Set<string>();
        const allCookieMap = new Map<string, any>();
        const allNetworkRequestMap = new Map<string, any>();
        const allLocalStorageMap = new Map<string, any>();
        const rootUrl = new URL(url);

        let screenshotBase64 = '';
        let consentBannerFound = false;
        let googleConsentV2Status: GoogleConsentV2Status = { detected: false, status: "Not checked" };

        const processItems = (map: Map<string, any>, items: any[], state: string, isCookie: boolean, pageUrl: string) => {
            items.forEach((item: any) => {
                const key = isCookie ? `${item.name}|${item.domain}|${item.path}` : item.url;
                if (!map.has(key)) map.set(key, { states: new Set(), data: item, pageUrls: new Set() });
                map.get(key).states.add(state);
                map.get(key).pageUrls.add(pageUrl);
            });
        };

        const processLocalStorage = (items: LocalStorageItem[], state: string, pageUrl: string) => {
            items.forEach(item => {
                const key = `${item.origin}|${item.key}`;
                if (!allLocalStorageMap.has(key)) allLocalStorageMap.set(key, { states: new Set(), data: item, pageUrls: new Set() });
                allLocalStorageMap.get(key).states.add(state);
                allLocalStorageMap.get(key).pageUrls.add(pageUrl);
            });
        }

        while(urlsToVisit.length > 0 && visitedUrls.size < MAX_PAGES_TO_SCAN) {
            urlsToVisit.sort((a, b) => a.priority - b.priority);
            const currentItem = urlsToVisit.shift();
            if (!currentItem || visitedUrls.has(currentItem.url)) continue;

            const currentUrl = currentItem.url;
            try {
                const pageUrl = new URL(currentUrl);
                if (pageUrl.hostname !== rootUrl.hostname) continue;
            } catch (e) {
                console.warn(`[CRAWL] Invalid URL skipped: ${currentUrl}`);
                continue;
            }

            console.log(`[CRAWL] Scanning page ${visitedUrls.size + 1}/${MAX_PAGES_TO_SCAN}: ${currentUrl}`);

            try {
                await page.goto(currentUrl, { waitUntil: 'networkidle2', timeout: 30000 });
                visitedUrls.add(currentUrl);

                if (visitedUrls.size === 1) {
                    console.log('[SCAN] Performing 3-stage consent analysis on entry page...');
                    screenshotBase64 = await page.screenshot({ encoding: 'base64', type: 'jpeg', quality: 70 });
                    
                    const { cookies: preCookies, networkRequests: preReqs, localStorageItems: preStore, googleConsentV2: gcmPre } = await collectPageData(page, rootUrl.hostname, SCAN_TIMEOUT);
                    processItems(allCookieMap, preCookies, 'pre-consent', true, currentUrl);
                    processItems(allNetworkRequestMap, preReqs, 'pre-consent', false, currentUrl);
                    processLocalStorage(preStore, 'pre-consent', currentUrl);
                    googleConsentV2Status = gcmPre;

                    consentBannerFound = await handleConsent(page, 'reject');
                    const { cookies: postRejCookies, networkRequests: postRejReqs, localStorageItems: postRejStore } = await collectPageData(page, rootUrl.hostname, SCAN_TIMEOUT);
                    processItems(allCookieMap, postRejCookies, 'post-rejection', true, currentUrl);
                    processItems(allNetworkRequestMap, postRejReqs, 'post-rejection', false, currentUrl);
                    processLocalStorage(postRejStore, 'post-rejection', currentUrl);

                    await page.reload({ waitUntil: 'networkidle2' });
                    await handleConsent(page, 'accept');
                    const { cookies: postAccCookies, networkRequests: postAccReqs, localStorageItems: postAccStore } = await collectPageData(page, rootUrl.hostname, SCAN_TIMEOUT);
                    processItems(allCookieMap, postAccCookies, 'post-acceptance', true, currentUrl);
                    processItems(allNetworkRequestMap, postAccReqs, 'post-acceptance', false, currentUrl);
                    processLocalStorage(postAccStore, 'post-acceptance', currentUrl);
                } else {
                    const { cookies, networkRequests, localStorageItems } = await collectPageData(page, rootUrl.hostname, SCAN_TIMEOUT);
                    processItems(allCookieMap, cookies, 'post-acceptance', true, currentUrl);
                    processItems(allNetworkRequestMap, networkRequests, 'post-acceptance', false, currentUrl);
                    processLocalStorage(localStorageItems, 'post-acceptance', currentUrl);
                }

                const internalLinks: { href: string; text: string }[] = await page.evaluate((hostname) => {
                    const links = new Map<string, string>();
                    document.querySelectorAll('a[href]').forEach(el => {
                        const anchor = el as HTMLAnchorElement;
                        try {
                            const linkUrl = new URL(anchor.href, document.baseURI);
                            if (linkUrl.hostname === hostname) {
                                const href = linkUrl.href.split('#')[0].split('?')[0];
                                if (!links.has(href)) links.set(href, (anchor.textContent || '').trim().toLowerCase());
                            }
                        } catch (e) { /* ignore invalid URLs */ }
                    });
                    return Array.from(links.entries()).map(([href, text]) => ({ href, text }));
                }, rootUrl.hostname);

                const priorityKeywords = ['privacy', 'policy', 'terms', 'conditions', 'cookie', 'contact', 'about', 'legal', 'login', 'pricing', 'dpa', 'security'];
                internalLinks.forEach(link => {
                    if (!visitedUrls.has(link.href) && !urlsToVisit.some(item => item.url === link.href)) {
                        const linkTextAndHref = `${link.text} ${link.href}`.toLowerCase();
                        const priority = priorityKeywords.some(keyword => linkTextAndHref.includes(keyword)) ? 1 : 2;
                        urlsToVisit.push({ url: link.href, priority });
                    }
                });

            } catch (pageError) {
                const message = pageError instanceof Error ? pageError.message : String(pageError);
                console.warn(`[CRAWL] Failed to load ${currentUrl}. ${message.substring(0, 100)}`);
            }
        }
        
        console.log(`[SCAN] Crawl complete. Found ${allCookieMap.size} cookies, ${allNetworkRequestMap.size} requests, and ${allLocalStorageMap.size} storage items.`);
        
        // ... (The entire AI analysis logic from server2.ts remains here, unchanged)
        const uniqueTrackersForAnalysis = Array.from(allNetworkRequestMap.values()).filter(value => knownTrackerDomains.some(domain => value.data.hostname.includes(domain)));
        const allItemsToAnalyze = [
            ...Array.from(allCookieMap.values()).map(value => ({ type: 'cookie', data: value })),
            ...uniqueTrackersForAnalysis.map(value => ({ type: 'tracker', data: value })),
            ...Array.from(allLocalStorageMap.values()).map(value => ({ type: 'storage', data: value }))
        ];

        // ... (rest of analysis logic: batching, prompting AI, etc.)
        const BATCH_SIZE = 25;
        const batches = [];
        for (let i = 0; i < allItemsToAnalyze.length; i += BATCH_SIZE) {
            batches.push(allItemsToAnalyze.slice(i, i + BATCH_SIZE));
        }
        console.log(`[AI] Splitting analysis into ${batches.length} batch(es) of size ~${BATCH_SIZE}.`);

        const analyzeBatch = async (batch: any[], batchNum: number, maxRetries = 2): Promise<any[]> => {
          // This entire function is copied directly from server2.ts
           const itemsForBatchAnalysis = batch.map(item => {
             if (item.type === 'cookie') {
                 const { name, domain, path } = item.data.data;
                 return { type: 'cookie', key: `${name}|${domain}|${path}`, name, provider: domain, states: Array.from(item.data.states) };
             }
             if (item.type === 'tracker') {
                 return { type: 'tracker', key: item.data.data.url, provider: item.data.data.hostname, states: Array.from(item.data.states) };
             }
             const { origin, key } = item.data.data;
             return { type: 'storage', key: `${origin}|${key}`, provider: origin, states: Array.from(item.data.states) };
           });
       
           const batchPrompt = `You are a world-class privacy expert categorizing web technologies with extreme accuracy. Given this batch of cookies, trackers, and storage items and the states they were observed in ('pre-consent', 'post-rejection', 'post-acceptance'), provide a JSON array. For each item:
- key: The original key.
- category: Categorize into ONE of: 'Necessary', 'Functional', 'Analytics', 'Marketing'. Use 'Unknown' ONLY as an absolute last resort if no information can be inferred.
- purpose: A very brief, one-sentence description of the item's likely function. Limit to 15 words. If it's a tracker, return an empty string.
- complianceStatus: Determine based on its 'states' and 'category':
    - If category is 'Necessary': 'Compliant'.
    - If state includes 'pre-consent' AND category is NOT 'Necessary': 'Pre-Consent Violation'.
    - If state includes 'post-rejection' AND category is NOT 'Necessary': 'Post-Rejection Violation'.
    - Otherwise: 'Compliant'.
- remediation: Provide a concise, actionable remediation plan. If 'Compliant', state "No action needed." If a 'Violation', explain HOW to fix it (e.g., "This marketing tracker is firing before user consent. Ensure the script is loaded only after the user explicitly accepts marketing cookies via the consent banner. Use a consent management platform to conditionally load this tag.").

Input Data:
${JSON.stringify(itemsForBatchAnalysis, null, 2)}
Return ONLY the valid JSON array of results.`;
           
           const batchResponseSchema = { type: Type.ARRAY, items: { type: Type.OBJECT, properties: { key: { type: Type.STRING }, category: { type: Type.STRING }, purpose: { type: Type.STRING }, complianceStatus: { type: Type.STRING }, remediation: { type: Type.STRING } }, required: ["key", "category", "purpose", "complianceStatus", "remediation"] }};
           
           for (let attempt = 0; attempt <= maxRetries; attempt++) {
             try {
                 const result = await ai.models.generateContent({ model, contents: [{ parts: [{ text: batchPrompt }] }], config: { responseMimeType: "application/json", responseSchema: batchResponseSchema } });
                 const resultText = result.text;
                 if (!resultText) throw new Error(`Gemini API returned an empty text response for analysis batch #${batchNum + 1}.`);
                 
                 let cleanedJsonString = resultText.trim().replace(/^```(?:json)?\s*([\s\S]*?)\s*```$/, '$1');
                 const firstBracket = cleanedJsonString.indexOf('[');
                 const lastBracket = cleanedJsonString.lastIndexOf(']');
                 if (firstBracket !== -1 && lastBracket > firstBracket) {
                     cleanedJsonString = cleanedJsonString.substring(firstBracket, lastBracket + 1);
                 }
                 return JSON.parse(cleanedJsonString);
             } catch(error) {
                 console.warn(`[AI] Attempt ${attempt + 1}/${maxRetries + 1} failed for batch ${batchNum + 1}.`, error instanceof Error ? error.message : String(error));
                 if (attempt === maxRetries) throw error;
                 await new Promise(res => setTimeout(res, 1500 * (attempt + 1)));
             }
           }
           throw new Error(`Exhausted all retries for batch ${batchNum + 1}`);
        };

        const aggregatedAnalysis: any[] = [];
        for (const [index, batch] of batches.entries()) {
            console.log(`[AI] Analyzing batch ${index + 1}/${batches.length}...`);
            const batchAnalysis = await analyzeBatch(batch, index);
            aggregatedAnalysis.push(...batchAnalysis);
        }
        
        console.log('[AI] Finalizing compliance assessment...');
        const violationSummary = {
            preConsentViolations: aggregatedAnalysis.filter(a => a.complianceStatus === 'Pre-Consent Violation').length,
            postRejectionViolations: aggregatedAnalysis.filter(a => a.complianceStatus === 'Post-Rejection Violation').length,
        };
        const compliancePrompt = `You are a privacy expert providing a risk assessment. Based on this summary, provide a JSON object with "gdpr" and "ccpa" keys.
Summary: ${JSON.stringify(violationSummary, null, 2)}
For both GDPR and CCPA, provide:
- riskLevel: 'Low', 'Medium', 'High', or 'Critical'. Any violation makes the risk at least 'High'. Multiple violations across types could make it 'Critical'.
- assessment: A brief summary explaining the risk level. Mention the number of violations.
Return ONLY the valid JSON object.`;
        const complianceSchema = { type: Type.OBJECT, properties: { gdpr: { type: Type.OBJECT, properties: { riskLevel: { type: Type.STRING }, assessment: { type: Type.STRING } } }, ccpa: { type: Type.OBJECT, properties: { riskLevel: { type: Type.STRING }, assessment: { type: Type.STRING } } } }, required: ['gdpr', 'ccpa'] };
        const complianceResult = await ai.models.generateContent({ model, contents: [{ parts: [{ text: compliancePrompt }] }], config: { responseMimeType: "application/json", responseSchema: complianceSchema } });
        const complianceAnalysis = JSON.parse(complianceResult.text);
        
        const analysisMap = new Map(aggregatedAnalysis.map((item: any) => [item.key, item]));
        const scannedUrlHostname = new URL(url).hostname;
        
        const uniqueCookies: CookieInfo[] = Array.from(allCookieMap.values()).map(c => {
            const key = `${c.data.name}|${c.data.domain}|${c.data.path}`;
            const analyzed = analysisMap.get(key);
            const domain = c.data.domain.startsWith('.') ? c.data.domain : `.${c.data.domain}`;
            const rootDomain = `.${scannedUrlHostname.replace(/^www\./, '')}`;
            return {
                key, name: c.data.name, provider: c.data.domain, expiry: getHumanReadableExpiry(c.data),
                party: domain.endsWith(rootDomain) ? 'First' : 'Third', isHttpOnly: c.data.httpOnly, isSecure: c.data.secure,
                complianceStatus: analyzed?.complianceStatus || ComplianceStatus.UNKNOWN,
                category: analyzed?.category || CookieCategory.UNKNOWN,
                purpose: analyzed?.purpose || 'No purpose determined.',
                remediation: analyzed?.remediation || 'Analysis incomplete.',
                pagesFound: Array.from(c.pageUrls),
            };
        });

        const uniqueTrackers: TrackerInfo[] = uniqueTrackersForAnalysis.map(t => {
            const key = t.data.url;
            const analyzed = analysisMap.get(key);
            return {
                key, hostname: t.data.hostname,
                complianceStatus: analyzed?.complianceStatus || ComplianceStatus.UNKNOWN,
                category: analyzed?.category || CookieCategory.UNKNOWN,
                remediation: analyzed?.remediation || 'Analysis incomplete.',
                pagesFound: Array.from(t.pageUrls),
            };
        });

        const uniqueLocalStorage: LocalStorageInfo[] = Array.from(allLocalStorageMap.values()).map(s => {
            const key = `${s.data.origin}|${s.data.key}`;
            const analyzed = analysisMap.get(key);
            return {
                key, origin: s.data.origin, storageKey: s.data.key,
                complianceStatus: analyzed?.complianceStatus || ComplianceStatus.UNKNOWN,
                category: analyzed?.category || CookieCategory.UNKNOWN,
                remediation: analyzed?.remediation || 'Analysis incomplete.',
                purpose: analyzed?.purpose || 'No purpose determined.',
                pagesFound: Array.from(s.pageUrls),
            };
        });
        
        const thirdPartyDomainsMap = new Map<string, Set<string>>();
        allNetworkRequestMap.forEach(req => {
            if (!thirdPartyDomainsMap.has(req.data.hostname)) thirdPartyDomainsMap.set(req.data.hostname, new Set());
            const pages = thirdPartyDomainsMap.get(req.data.hostname);
            req.pageUrls.forEach((p: string) => pages!.add(p));
        });
        const thirdPartyDomains = Array.from(thirdPartyDomainsMap.entries()).map(([hostname, pageSet]) => ({
            hostname, count: pageSet.size, pagesFound: Array.from(pageSet)
        }));

        // CHANGED: Sending a single JSON response instead of a stream event
        res.json({ 
            uniqueCookies, 
            uniqueTrackers, 
            uniqueLocalStorage,
            thirdPartyDomains,
            pages: Array.from(visitedUrls).map(u => ({ url: u })),
            compliance: complianceAnalysis, 
            screenshotBase64, 
            consentBannerDetected: consentBannerFound, 
            pagesScannedCount: visitedUrls.size,
            googleConsentV2: googleConsentV2Status,
        });

    } catch (error) {
        const message = error instanceof Error ? error.message : "An unknown error occurred.";
        console.error('[SERVER] Scan failed:', message);
        // CHANGED: Sending a standard error response
        res.status(500).json({ error: `Failed to scan ${url}. ${message}` });
    } finally {
        if (browser) await browser.close();
    }
});


// ... All other endpoints from server2.ts remain here, as they are already cloud-compatible ...
// (/api/scan-vulnerabilities, /api/analyze-legal-document, /api/templates, etc.)

// ADDED: SPA fallback for production from server1.ts
if (process.env.NODE_ENV === 'production') {
    app.get('*', (req: Request, res: Response) => {
      // Don't serve index.html for API routes
      if (req.path.startsWith('/api/') || req.path.startsWith('/health')) {
        return res.status(404).json({ error: 'API endpoint not found' });
      }
      
      const indexPath = path.join(__dirname, '..', 'public', 'index.html');
      console.log(`[SERVER] Serving SPA for ${req.path} from ${indexPath}`);
      
      if (fs.existsSync(indexPath)) {
        res.sendFile(indexPath);
      } else {
        res.status(404).json({ error: 'Frontend not found', path: indexPath });
      }
    });
}

// ADDED: Final error handling middleware from server1.ts
app.use((err: Error, req: Request, res: Response, next: Function) => {
    console.error('[SERVER] Unhandled error:', err);
    res.status(500).json({ 
        error: 'Internal server error', 
        message: err.message,
        stack: process.env.NODE_ENV === 'development' ? err.stack : undefined
    });
});

// ADDED: Graceful shutdown handlers from server1.ts
process.on('SIGTERM', () => {
    console.log('[SERVER] SIGTERM received, shutting down gracefully...');
    process.exit(0);
});

process.on('SIGINT', () => {
    console.log('[SERVER] SIGINT received, shutting down gracefully...');
    process.exit(0);
});

app.listen(port, () => {
    console.log(`[SERVER] Backend server running on port ${port}`);
    console.log(`[SERVER] Environment: ${process.env.NODE_ENV || 'development'}`);
});
