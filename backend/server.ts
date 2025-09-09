// FIX: Use `express.Request` and `express.Response` to avoid type conflicts and ensure correct Express types are used.
// By using the default express import, we can use `express.Request` and `express.Response` to avoid ambiguity with global types.
import express, { type Request, type Response } from 'express';
// FIX: Puppeteer Cookie type is slightly different from what page.cookies() returns. Cast through unknown.
import puppeteer, { type Cookie as PuppeteerCookie, type Page, type Frame, type Browser, CDPSession } from 'puppeteer';
import cors from 'cors';
import dotenv from 'dotenv';
import { GoogleGenAI, Type } from '@google/genai';
import {
    CookieCategory, type CookieInfo, type TrackerInfo, type ScanResultData, ComplianceStatus,
    type LegalAnalysisResult, type LegalPerspective, type VulnerabilityScanResult,
    type VulnerabilityCategory, type GeneratedContract, ContractTemplate, type NetworkRequestItem, type LocalStorageItem,
    type LocalStorageInfo,
    GoogleConsentV2Status,
    ComplianceInfo
} from './types.js';
import { findCookieInDatabase } from './cookieDatabase.js';
import path from 'path';
import { fileURLToPath } from 'url';
import fs from 'fs';

dotenv.config();

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
const app: express.Application = express();

// GCP Cloud Run uses PORT environment variable, fallback to 3001 for local development
const port = process.env.PORT || 3001;

// CORS configuration for GCP deployment
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

// Health check endpoint for GCP
app.get('/health', (req: Request, res: Response) => {
    res.status(200).json({ status: 'healthy', timestamp: new Date().toISOString() });
});

app.get('/debug-routes', (req: Request, res: Response) => {
    type RouteInfo = { method: string; path: string };
    const routes: RouteInfo[] = [];

    (app._router.stack as any[]).forEach((middleware: any) => {
        if (middleware.route) { // Route is directly registered on app
            routes.push({
                method: Object.keys(middleware.route.methods).join(', ').toUpperCase(),
                path: middleware.route.path
            });
        } else if (middleware.name === 'router' && middleware.handle?.stack) { // Router middleware 
            (middleware.handle.stack as any[]).forEach((handler: any) => {
                if (handler.route) {
                    routes.push({
                        method: Object.keys(handler.route.methods).join(', ').toUpperCase(),
                        path: handler.route.path
                    });
                }
            });
        }
    });

    res.json({
        message: "Routes are being registered!",
        environment: process.env.NODE_ENV || 'development',
        cwd: process.cwd(),
        filename: __filename,
        dirname: __dirname,
        routes
    });
});

// Serve static files in production
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
                try {
                    await frame.page().waitForNetworkIdle({ timeout: 3000 });
                } catch (e) {
                    console.log(`[CONSENT] Network did not become idle after action. Continuing.`);
                }
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

const detectCMP = async (page: Page): Promise<string> => {
    try {
        const cmp = await page.evaluate(() => {
            if ((window as any).OneTrust) return 'OneTrust';
            if ((window as any).Cookiebot) return 'Cookiebot';
            if ((window as any).CookieYes) return 'CookieYes';
            if ((window as any).Osano) return 'Osano';
            if ((window as any).didomiOnReady) return 'Didomi';
            if (document.getElementById('CybotCookiebotDialog')) return 'Cookiebot';
            if (document.getElementById('onetrust-banner-sdk')) return 'OneTrust';
            if (document.querySelector('[class*="CookieConsent"]')) return 'CookieConsent'; // Generic fallback
            return 'Unknown';
        });
        return cmp;
    } catch (e) {
        console.warn('[CMP] Could not detect CMP:', e);
        return 'Unknown';
    }
};

const getOneTrustClassifications = async (page: Page): Promise<Map<string, string>> => {
    const oneTrustMap = new Map<string, string>();
    try {
        const isOneTrust = await page.evaluate(() => !!(window as any).OneTrust);
        if (!isOneTrust) return oneTrustMap;

        const domainData = await page.evaluate(() => (window as any).OneTrust.GetDomainData());
        if (domainData && domainData.Groups) {
            for (const group of domainData.Groups) {
                if (group.Cookies && group.GroupName) {
                    for (const cookie of group.Cookies) {
                        if (cookie.Name) {
                            oneTrustMap.set(cookie.Name, group.GroupName);
                        }
                    }
                }
            }
        }
    } catch (e) {
        console.warn('[CMP] Failed to get OneTrust classifications:', e);
    }
    return oneTrustMap;
};

const collectPageData = async (page: Page, rootHostname: string): Promise<{ cookies: PuppeteerCookie[], networkRequests: {hostname: string, url: string}[], localStorageItems: LocalStorageItem[], googleConsentV2: GoogleConsentV2Status }> => {
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

    await page.reload({ waitUntil: 'networkidle2' });

    try {
        await page.evaluate(() => window.scrollTo(0, document.body.scrollHeight));
        await page.waitForNetworkIdle({ timeout: 2000 });
        await page.evaluate(() => window.scrollTo(0, 0));
    } catch (e) {
        console.log(`[CRAWL] Could not scroll or wait for idle on ${page.url()}`);
    }

    let cookies: PuppeteerCookie[] = [];
    if (cdpSession) {
        try {
            const { cookies: cdpCookies } = await cdpSession.send('Network.getAllCookies');
            cookies = cdpCookies as unknown as PuppeteerCookie[];
        } catch(e) {
            console.error('[CDP] Error getting cookies via CDP, falling back to page.cookies()', e);
            cookies = await page.cookies();
        } finally {
            await cdpSession.detach();
        }
    } else {
        cookies = await page.cookies();
    }

    const { localStorageItems, googleConsentV2 } = await page.evaluate(() => {
        const items: LocalStorageItem[] = [];
        let gcmStatus: GoogleConsentV2Status = { detected: false, status: 'Not Detected' };

        try {
            for (let i = 0; i < localStorage.length; i++) {
                const key = localStorage.key(i);
                if (key) {
                    items.push({ origin: window.location.origin, key, value: localStorage.getItem(key) || '', pageUrl: window.location.href });
                }
            }
            for (let i = 0; i < sessionStorage.length; i++) {
                const key = sessionStorage.key(i);
                if (key) {
                    items.push({ origin: window.location.origin, key, value: sessionStorage.getItem(key) || '', pageUrl: window.location.href });
                }
            }
        } catch(e) {
            console.warn('Could not access storage on page.');
        }

        // --- Improved GCMv2 Detection Logic ---
        // Primary, more reliable method: Check the internal google_tag_data state
        try {
            const gcs = (window as any).google_tag_data?.ics?.entries;
            if (gcs && typeof gcs === 'object' && Object.keys(gcs).length > 0) {
                gcmStatus.detected = true;
                const firstStateKey = Object.keys(gcs)[0];
                const state = gcs[firstStateKey];
                if (state && typeof state === 'object') {
                    gcmStatus.status = Object.entries(state)
                        .map(([k, v]) => `${k}: ${v}`)
                        .join('; ');
                } else {
                    gcmStatus.status = "Detected, but state format is unexpected."
                }
            }
        } catch (e) {
           // This check can fail if the object doesn't exist; we'll proceed to the fallback.
        }

        // Fallback method: Check the dataLayer for the default command
        if (!gcmStatus.detected) {
            const dataLayer = (window as any).dataLayer || (window as any).google_tag_manager?.dataLayer;
            if (Array.isArray(dataLayer)) {
                try {
                    const consentDefault = dataLayer.filter((i: any) =>
                        Array.isArray(i) && i.length > 2 && i[0] === 'consent' && i[1] === 'default'
                    ).pop();

                    if (consentDefault && typeof consentDefault[2] === 'object') {
                        gcmStatus.detected = true;
                        const consentState = consentDefault[2];
                        gcmStatus.status = Object.keys(consentState)
                            .map(k => `${k}: ${consentState[k]}`)
                            .join('; ');
                    }
                } catch (e) {
                    console.warn('Could not parse GCM status from dataLayer.');
                }
            }
        }

        return { localStorageItems: items, googleConsentV2: gcmStatus };
    });

    page.off('request', requestListener); // Clean up listener
    return { cookies, networkRequests, localStorageItems, googleConsentV2 };
}

// --- Sitemap Discovery Helpers ---
const parseSitemap = async (sitemapUrl: string): Promise<string[]> => {
    try {
        const response = await fetch(sitemapUrl, { headers: { 'User-Agent': 'CookieCare-Bot/1.0' } });
        if (!response.ok) return [];
        const sitemapText = await response.text();

        const urlRegex = /<loc>(.*?)<\/loc>/g;
        let match;
        const urls = [];
        while ((match = urlRegex.exec(sitemapText)) !== null) {
            urls.push(match[1]);
        }
        
        // Check if it's a sitemap index file and recursively parse nested sitemaps
        if (sitemapText.includes('<sitemapindex')) {
            const nestedSitemaps = urls;
            const allUrls: string[] = [];
            await Promise.all(nestedSitemaps.map(async (nestedUrl) => {
                const nestedUrls = await parseSitemap(nestedUrl);
                allUrls.push(...nestedUrls);
            }));
            return allUrls;
        }
        
        return urls;

    } catch (error) {
        console.warn(`[SITEMAP] Failed to parse sitemap at ${sitemapUrl}:`, error);
        return [];
    }
};

const discoverSitemapUrls = async (rootUrl: URL): Promise<string[]> => {
    const sitemapLocations = new Set<string>();
    try {
        // 1. Check robots.txt for "Sitemap:" directive
        const robotsUrl = new URL('/robots.txt', rootUrl);
        const robotsResponse = await fetch(robotsUrl.toString(), { headers: { 'User-Agent': 'CookieCare-Bot/1.0' }});
        if (robotsResponse.ok) {
            const robotsText = await robotsResponse.text();
            const sitemapRegex = /^Sitemap:\s*(.*)$/gim;
            let match;
            while ((match = sitemapRegex.exec(robotsText)) !== null) {
                sitemapLocations.add(match[1].trim());
            }
        }
    } catch (e) {
        console.warn('[SITEMAP] Could not fetch or parse robots.txt');
    }

    // 2. Fallback to common location if not found in robots.txt
    if (sitemapLocations.size === 0) {
        sitemapLocations.add(new URL('/sitemap.xml', rootUrl).toString());
    }
    
    const allPageUrls = new Set<string>();
    for (const sitemapUrl of sitemapLocations) {
        const pageUrls = await parseSitemap(sitemapUrl);
        pageUrls.forEach(url => allPageUrls.add(url));
    }
    
    return Array.from(allPageUrls);
};

const normalizeUrlPath = (path: string): string => {
    const commonPrefixes = ['/jobs', '/careers', '/products', '/blog', '/news', '/articles', '/listing', '/en-us/jobs'];

    for (const prefix of commonPrefixes) {
        if (path.startsWith(prefix + '/')) {
            const pathParts = path.substring(1).split('/');
            const prefixParts = prefix.substring(1).split('/');
            const basePath = `/${prefixParts.join('/')}`;
            return `${basePath}/[slug]`;
        }
    }

    return path
        .replace(/\/\d{4,}/g, '/[longnumber]')
        .replace(/\/[a-zA-Z0-9-]{20,}/g, '/[slug]');
};


// FIX: Use explicit `express.Request` and `express.Response` types for route handlers.
app.get('/api/scan', async (req: Request, res: Response) => {
    const rawUrl = req.query.url as string;
    const depth = req.query.depth as 'lite' | 'medium' | 'deep' | undefined;

    res.setHeader('Content-Type', 'text/event-stream');
    res.setHeader('Cache-Control', 'no-cache');
    res.setHeader('Connection', 'keep-alive');
    res.flushHeaders();

    const sendEvent = (data: object) => {
        res.write(`data: ${JSON.stringify(data)}\n\n`);
    };

    if (!rawUrl) {
        sendEvent({ type: 'error', message: 'URL is required' });
        return res.end();
    }

    const url = decodeURIComponent(rawUrl);

    try {
        new URL(url);
    } catch(e) {
        console.error(`[SERVER] Scan failed: Invalid URL provided "${url}"`);
        sendEvent({ type: 'error', message: `Failed to scan ${url}. Invalid URL` });
        return res.end();
    }

    console.log(`[SERVER] Received scan request for: ${url}`);
    let browser: Browser | null = null;
    // FIX: Wrap main browser session in a try/finally to guarantee it closes, preventing file lock errors.
    try {
        const depthLimits = { lite: 10, medium: 50, deep: 100 };
        const maxPages = depthLimits[depth || 'lite'];
        sendEvent({ type: 'log', message: `Scan initiated for ${url} (Depth: ${depth || 'lite'}, up to ${maxPages} pages)` });

        browser = await puppeteer.launch({
            headless: true,
            args: [
              '--no-sandbox',
              '--disable-setuid-sandbox',
              '--disable-dev-shm-usage',
              '--disable-gpu',
              '--no-first-run',
              '--no-default-browser-check',
              '--disable-background-timer-throttling',
              '--disable-renderer-backgrounding',
              '--disable-backgrounding-occluded-windows',
              '--disable-extensions',
              '--disable-plugins',
            ],
            defaultViewport: { width: 1280, height: 720 },
            timeout: 10000
        });
        const page = await browser.newPage();
        await page.setUserAgent('Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/108.0.0.0 Safari/536');
        await page.setViewport({ width: 1920, height: 1080 });

        const urlsToVisit: { url: string; priority: number }[] = [{ url: url, priority: 0 }];
        const visitedUrls = new Set<string>();
        const allCookieMap = new Map<string, any>();
        const allNetworkRequestMap = new Map<string, any>();
        const allLocalStorageMap = new Map<string, any>();
        const rootUrl = new URL(url);
        const domainParts = rootUrl.hostname.split('.');
        const mainDomain = domainParts.slice(Math.max(domainParts.length - 2, 0)).join('.');


        let screenshotBase64 = '';
        let consentBannerFound = false;
        let cookiePolicyDetected = false;
        let googleConsentV2Status: GoogleConsentV2Status = { detected: false, status: "Not checked" };
        let cmpProvider = 'Unknown';
        let oneTrustClassifications = new Map<string, string>();
        const processedUrlPatterns = new Map<string, number>();
        const MAX_PATTERN_VISITS = 3;

        // --- Sitemap Discovery ---
        sendEvent({ type: 'log', message: 'Searching for sitemap for comprehensive crawling...' });
        try {
            const sitemapPageUrls = await discoverSitemapUrls(rootUrl);
            if (sitemapPageUrls.length > 0) {
                sendEvent({ type: 'log', message: `Found sitemap! Added ${sitemapPageUrls.length} URLs to the crawl queue.` });
                sitemapPageUrls.forEach(pageUrl => {
                    if (!urlsToVisit.some(item => item.url === pageUrl)) {
                        urlsToVisit.push({ url: pageUrl, priority: 0 }); // Highest priority
                    }
                });
            } else {
                sendEvent({ type: 'log', message: 'No sitemap found. Proceeding with standard link-following crawl.' });
            }
        } catch (error) {
            console.warn('[SITEMAP] Error during sitemap discovery:', error);
            sendEvent({ type: 'log', message: 'Could not process sitemap. Proceeding with standard crawl.' });
        }

        const processItems = (map: Map<string, any>, items: any[], state: string, isCookie: boolean, pageUrl: string) => {
            items.forEach((item: any) => {
                const key = isCookie ? `${item.name}|${item.domain}|${item.path}` : item.url;
                if (!map.has(key)) {
                    map.set(key, { states: new Set(), data: item, pageUrls: new Set() });
                }
                map.get(key).states.add(state);
                map.get(key).pageUrls.add(pageUrl);
            });
        };

        const processLocalStorage = (items: LocalStorageItem[], state: string, pageUrl: string) => {
            items.forEach(item => {
                const key = `${item.origin}|${item.key}`;
                if (!allLocalStorageMap.has(key)) {
                    allLocalStorageMap.set(key, { states: new Set(), data: item, pageUrls: new Set() });
                }
                allLocalStorageMap.get(key).states.add(state);
                allLocalStorageMap.get(key).pageUrls.add(pageUrl);
            });
        }

        while(urlsToVisit.length > 0 && visitedUrls.size < maxPages) {
            urlsToVisit.sort((a, b) => a.priority - b.priority);
            const currentItem = urlsToVisit.shift();
            if (!currentItem || visitedUrls.has(currentItem.url)) {
                continue;
            }

            const currentUrl = currentItem.url;

            const currentUrlPath = new URL(currentUrl).pathname;
            const normalizedPath = normalizeUrlPath(currentUrlPath);
            const patternCount = processedUrlPatterns.get(normalizedPath) || 0;

            if (patternCount >= MAX_PATTERN_VISITS) {
                sendEvent({ type: 'log', message: `Skipping similar URL: ${currentUrl}` });
                continue;
            }
            processedUrlPatterns.set(normalizedPath, patternCount + 1);

            try {
                const pageUrl = new URL(currentUrl);
                if (!pageUrl.hostname.endsWith(mainDomain)) {
                    continue;
                }
            } catch (e) {
                console.warn(`[CRAWL] Invalid URL skipped: ${currentUrl}`);
                continue;
            }

            sendEvent({ type: 'log', message: `[${visitedUrls.size + 1}/${maxPages}] Scanning: ${currentUrl}` });

            try {
                await page.goto(currentUrl, { waitUntil: 'networkidle2', timeout: 30000 });
                visitedUrls.add(currentUrl);

                if (!cookiePolicyDetected) {
                    const policyLinkFound = await page.evaluate(() => {
                        const links = Array.from(document.querySelectorAll('a'));
                        const policyKeywords = ['cookie policy', 'privacy policy', 'cookie statement'];
                        return links.some(link => {
                            const text = (link.textContent || '').toLowerCase().trim();
                            return policyKeywords.some(keyword => text.includes(keyword));
                        });
                    });
                    if (policyLinkFound) {
                        cookiePolicyDetected = true;
                        sendEvent({ type: 'log', message: `Cookie/Privacy Policy link found on ${currentUrl}` });
                    }
                }

                if (visitedUrls.size === 1) {
                    cmpProvider = await detectCMP(page);
                    sendEvent({ type: 'log', message: `Detected Consent Management Platform: ${cmpProvider}` });
                    if (cmpProvider === 'OneTrust') {
                        sendEvent({ type: 'log', message: `Attempting to extract OneTrust classifications...` });
                        oneTrustClassifications = await getOneTrustClassifications(page);
                    }

                    sendEvent({ type: 'log', message: 'Performing 3-stage consent analysis on entry page...'});
                    screenshotBase64 = await page.screenshot({ encoding: 'base64', type: 'jpeg', quality: 70 });

                    const { cookies: preConsentCookies, networkRequests: preConsentRequests, localStorageItems: preConsentStorage, googleConsentV2: gcmPre } = await collectPageData(page, rootUrl.hostname);
                    processItems(allCookieMap, preConsentCookies, 'pre-consent', true, currentUrl);
                    processItems(allNetworkRequestMap, preConsentRequests, 'pre-consent', false, currentUrl);
                    processLocalStorage(preConsentStorage, 'pre-consent', currentUrl);
                    if (gcmPre.detected) googleConsentV2Status = gcmPre;

                    consentBannerFound = await handleConsent(page, 'reject');
                    const { cookies: postRejectCookies, networkRequests: postRejectRequests, localStorageItems: postRejectStorage, googleConsentV2: gcmPostReject } = await collectPageData(page, rootUrl.hostname);
                    processItems(allCookieMap, postRejectCookies, 'post-rejection', true, currentUrl);
                    processItems(allNetworkRequestMap, postRejectRequests, 'post-rejection', false, currentUrl);
                    processLocalStorage(postRejectStorage, 'post-rejection', currentUrl);
                    if (!googleConsentV2Status.detected && gcmPostReject.detected) googleConsentV2Status = gcmPostReject;

                    await page.reload({ waitUntil: 'networkidle2' });
                    await handleConsent(page, 'accept');
                    const { cookies: postAcceptCookies, networkRequests: postAcceptRequests, localStorageItems: postAcceptStorage, googleConsentV2: gcmPostAccept } = await collectPageData(page, rootUrl.hostname);
                    processItems(allCookieMap, postAcceptCookies, 'post-acceptance', true, currentUrl);
                    processItems(allNetworkRequestMap, postAcceptRequests, 'post-acceptance', false, currentUrl);
                    processLocalStorage(postAcceptStorage, 'post-acceptance', currentUrl);
                    if (!googleConsentV2Status.detected && gcmPostAccept.detected) googleConsentV2Status = gcmPostAccept;

                } else {
                    const { cookies, networkRequests, localStorageItems, googleConsentV2 } = await collectPageData(page, rootUrl.hostname);
                    processItems(allCookieMap, cookies, 'post-acceptance', true, currentUrl);
                    processItems(allNetworkRequestMap, networkRequests, 'post-acceptance', false, currentUrl);
                    processLocalStorage(localStorageItems, 'post-acceptance', currentUrl);
                    if (!googleConsentV2Status.detected && googleConsentV2.detected) googleConsentV2Status = googleConsentV2;
                }

                const internalLinks: { href: string; text: string }[] = await page.evaluate((domain) => {
                    const links = new Map<string, string>();
                    document.querySelectorAll('a[href]').forEach(el => {
                        const anchor = el as HTMLAnchorElement;
                        try {
                            const linkUrl = new URL(anchor.href, document.baseURI);
                            if (linkUrl.hostname.endsWith(domain)) {
                                const href = linkUrl.href.split('#')[0].split('?')[0];
                                 if (!links.has(href)) {
                                     links.set(href, (anchor.textContent || '').trim().toLowerCase());
                                 }
                            }
                        } catch (e) { /* ignore invalid URLs */ }
                    });
                    return Array.from(links.entries()).map(([href, text]) => ({ href, text }));
                }, mainDomain);

                const priorityKeywords = [
                    'privacy', 'policy', 'terms', 'conditions', 'cookie',
                    'contact', 'about', 'legal', 'login', 'signin', 'signup',
                    'pricing', 'dpa', 'data-processing', 'security', 'disclaimer',
                    'imprint', 'impressum', 'user-agreement', 'terms-of-service', 'terms-of-use'
                ];
                internalLinks.forEach(link => {
                    if (!visitedUrls.has(link.href) && !urlsToVisit.some(item => item.url === link.href)) {
                        const linkTextAndHref = `${link.text} ${link.href}`.toLowerCase();
                        const priority = priorityKeywords.some(keyword => linkTextAndHref.includes(keyword)) ? 1 : 2;
                        urlsToVisit.push({ url: link.href, priority });
                    }
                });

            } catch (pageError) {
                const message = pageError instanceof Error ? pageError.message : String(pageError);
                sendEvent({ type: 'log', message: `Warning: Failed to load ${currentUrl}. ${message.substring(0, 100)}` });
            }
        }

        sendEvent({ type: 'log', message: `Crawl complete. Found ${allCookieMap.size} unique cookies, ${allNetworkRequestMap.size} third-party requests, and ${allLocalStorageMap.size} storage items.` });
        sendEvent({ type: 'log', message: `Submitting all findings to AI for analysis... (This may take a moment)` });

        const allItemsToAnalyze = [
            ...Array.from(allCookieMap.values()).map(value => ({ type: 'cookie', data: value })),
            ...Array.from(allNetworkRequestMap.values()).map(value => ({ type: 'network_request', data: value })),
            ...Array.from(allLocalStorageMap.values()).map(value => ({ type: 'storage', data: value }))
        ];

        if (allItemsToAnalyze.length === 0) {
            sendEvent({ type: 'result', payload: {
                uniqueCookies: [], uniqueTrackers: [], uniqueLocalStorage: [], thirdPartyDomains: [], pages: Array.from(visitedUrls).map(u => ({ url: u })), screenshotBase64,
                consentBannerDetected: consentBannerFound,
                cookiePolicyDetected,
                pagesScannedCount: visitedUrls.size,
                googleConsentV2: googleConsentV2Status,
                cmpProvider,
                compliance: {
                    gdpr: { riskLevel: 'Low', assessment: 'No cookies or trackers were detected.'},
                    ccpa: { riskLevel: 'Low', assessment: 'No cookies or trackers were detected.'},
                }
            }});
            return;
        }

        const BATCH_SIZE = 25;
        const batches = [];
        for (let i = 0; i < allItemsToAnalyze.length; i += BATCH_SIZE) {
            batches.push(allItemsToAnalyze.slice(i, i + BATCH_SIZE));
        }

        const analyzeBatch = async (batch: any[], batchNum: number, maxRetries = 2): Promise<any[]> => {
            // FIX: Use a map to correlate short keys sent to the AI with the original, potentially long keys (e.g., URLs).
            const keyMap = new Map<string, string>();
            const itemsForBatchAnalysis = batch.map((item, index) => {
                const shortKey = `${item.type}-${batchNum}-${index}`; // e.g., "cookie-0-1"
                if (item.type === 'cookie') {
                    const { name, domain, path } = item.data.data;
                    keyMap.set(shortKey, `${name}|${domain}|${path}`);
                    return { type: 'cookie', key: shortKey, name: name, provider: domain, states: Array.from(item.data.states) };
                }
                if (item.type === 'network_request') {
                    keyMap.set(shortKey, item.data.data.url);
                    return { type: 'network_request', key: shortKey, provider: item.data.data.hostname, states: Array.from(item.data.states) };
                }
                // for storage
                const { origin, key } = item.data.data;
                keyMap.set(shortKey, `${origin}|${key}`);
                return { type: 'storage', key: shortKey, name: key, provider: origin, states: Array.from(item.data.states) };
            });

            const batchPrompt = `You are an automated, rule-based web technology categorization engine. Your task is to process a batch of items and return a JSON array. Follow these rules with absolute precision. DO NOT deviate or use creative interpretation.

 For each item in the input, produce a JSON object with the following fields:

 1.  **key**: (String) The original key provided in the input.

 2.  **isTracker**: (Boolean, for 'network_request' type ONLY)
     * **Rule:** Set to \`true\` if the request's provider domain is primarily associated with advertising, analytics, or user behavior tracking (e.g., google-analytics.com, doubleclick.net, facebook.net, clarity.ms).
     * **Rule:** Set to \`false\` if the provider is for content delivery (CDN like cdnjs.cloudflare.com, fonts.googleapis.com), essential site APIs, or user-facing widgets (e.g., intercom.io).
     * **Default:** For 'cookie' and 'storage' types, this field MUST be \`false\`.

 3.  **category**: (String, ONE of: 'Necessary', 'Functional', 'Analytics', 'Marketing')
     * **Step A: Check for Necessary items (Highest Priority).**
         * If the item's name or provider relates to a Consent Management Platform (e.g., 'OptanonConsent', 'CookieConsent', 'cookielawinfo'), the category is ALWAYS **'Necessary'**.
         * If the item's name suggests essential security (e.g., 'csrf_token', 'session_id') or load balancing, the category is **'Necessary'**.
     * **Step B: Use \`isTracker\` for network requests.**
         * If \`type\` is 'network_request' and \`isTracker\` is \`true\`, the category MUST be **'Analytics'** or **'Marketing'**. Decide based on the provider (e.g., 'google-analytics.com' is Analytics, 'doubleclick.net' is Marketing).
         * If \`type\` is 'network_request' and \`isTracker\` is \`false\`, the category MUST be **'Functional'** or **'Necessary'**.
     * **Step C: Infer from Provider for Cookies/Storage.**
         * For providers like 'google-analytics.com', '_ga', 'matomo', 'hotjar', 'clarity.ms', the category is **'Analytics'**.
         * For providers like 'doubleclick.net', 'facebook.com', '_fbp', 'hubspot', the category is **'Marketing'**.
         * For providers of user-facing features like 'intercom', 'zendesk', or for remembering user choices like language ('lang'), the category is **'Functional'**.
     * **Default:** Use 'Unknown' ONLY if no other rule applies.

 4.  **purpose**: (String)
     * **Rule:** A brief, 15-word max description of the item's function.
     * **Rule:** For 'network_request' types, return an empty string.

 5.  **complianceStatus**: (String, ONE of: 'Compliant', 'Pre-Consent Violation', 'Post-Rejection Violation')
     * **Rule 1:** If \`category\` is **'Necessary'**, \`complianceStatus\` is ALWAYS **'Compliant'**.
     * **Rule 2:** If \`category\` is NOT **'Necessary'** AND the \`states\` array contains **'pre-consent'**, \`complianceStatus\` is **'Pre-Consent Violation'**.
     * **Rule 3:** If \`category\` is NOT **'Necessary'** AND the \`states\` array contains **'post-rejection'**, \`complianceStatus\` is **'Post-Rejection Violation'**.
     * **Rule 4:** In all other cases, \`complianceStatus\` is **'Compliant'**.

 6.  **remediation**: (String)
     * **Rule:** If \`complianceStatus\` is **'Compliant'**, return "No action needed.".
     * **Rule:** For **'Pre-Consent Violation'**, return "This [category] item was detected before user consent was given. Configure your consent management platform to block this script/cookie until the user explicitly opts in.".
     * **Rule:** For **'Post-Rejection Violation'**, return "This [category] item was detected after the user rejected consent. This technology should not be loaded when consent is denied. Check your tag manager triggers and script configurations.".

 Input Data:
 ${JSON.stringify(itemsForBatchAnalysis, null, 2)}

 Return ONLY the valid JSON array of results.`;

            const batchResponseSchema = { type: Type.ARRAY, items: { type: Type.OBJECT, properties: { key: { type: Type.STRING }, isTracker: { type: Type.BOOLEAN }, category: { type: Type.STRING }, purpose: { type: Type.STRING }, complianceStatus: { type: Type.STRING }, remediation: { type: Type.STRING } }, required: ["key", "isTracker", "category", "purpose", "complianceStatus", "remediation"] }};

            for (let attempt = 0; attempt <= maxRetries; attempt++) {
                try {
                    const result = await ai.models.generateContent({ model, contents: [{ parts: [{ text: batchPrompt }] }], config: { responseMimeType: "application/json", responseSchema: batchResponseSchema } });

                    if (result.promptFeedback?.blockReason) {
                        const blockReason = result.promptFeedback.blockReason;
                        const blockMessage = result.promptFeedback.blockReasonMessage || "No additional message.";
                        console.error(`[AI] Batch ${batchNum + 1} was blocked. Reason: ${blockReason}. Message: ${blockMessage}`);
                        throw new Error(`AI content generation was blocked due to safety settings (Reason: ${blockReason}).`);
                    }

                    const resultText = result.text;
                    if (!resultText) {
                        throw new Error(`Gemini API returned an empty text response for analysis batch #${batchNum + 1}.`);
                    }

                    let cleanedJsonString = resultText.trim().replace(/^```(?:json)?\s*([\s\S]*?)\s*```$/, '$1');
                    const firstBracket = cleanedJsonString.indexOf('[');
                    const lastBracket = cleanedJsonString.lastIndexOf(']');
                    if (firstBracket !== -1 && lastBracket > firstBracket) {
                        cleanedJsonString = cleanedJsonString.substring(firstBracket, lastBracket + 1);
                    }

                    try {
                        const analysisResults = JSON.parse(cleanedJsonString);
                        // Map the short keys back to their original long keys before returning.
                        return analysisResults.map((res: any) => {
                            if (keyMap.has(res.key)) {
                                return { ...res, key: keyMap.get(res.key) };
                            }
                            console.warn(`[AI] Could not map back key: ${res.key}`);
                            return res;
                        });
                    } catch (jsonError) {
                        console.error(`[AI] Failed to parse JSON on batch ${batchNum + 1}. Content received:`, cleanedJsonString);
                        throw new Error(`Invalid JSON response from AI on batch ${batchNum + 1}.`);
                    }
                } catch(error) {
                    console.warn(`[AI] Attempt ${attempt + 1}/${maxRetries + 1} failed for batch ${batchNum + 1}.`, error instanceof Error ? error.message : String(error));
                     if (error instanceof Error && error.message.includes("blocked due to safety settings")) {
                         throw error;
                     }
                    if (attempt === maxRetries) {
                        console.error(`[AI] Batch ${batchNum + 1} failed after ${maxRetries + 1} attempts.`);
                        throw error;
                    }
                    await new Promise(res => setTimeout(res, 1500 * (attempt + 1)));
                }
            }
            throw new Error(`Exhausted all retries for batch ${batchNum + 1}`);
        };

        const aggregatedAnalysis: any[] = [];
        for (const [index, batch] of batches.entries()) {
            sendEvent({ type: 'log', message: `Analyzing batch ${index + 1}/${batches.length}...` });
            const batchAnalysis = await analyzeBatch(batch, index);
            aggregatedAnalysis.push(...batchAnalysis);
        }

        sendEvent({ type: 'log', message: 'Finalizing compliance assessment...' });
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

        const complianceResultText = complianceResult.text;
        if (!complianceResultText) {
            throw new Error('Gemini API returned an empty response for the final compliance analysis.');
        }
        const complianceAnalysis = JSON.parse(complianceResultText);

        const analysisMap = new Map(aggregatedAnalysis.map((item: any) => [item.key, item]));
        const scannedUrlHostname = new URL(url).hostname;

        const uniqueCookies: CookieInfo[] = Array.from(allCookieMap.values()).map(c => {
            const key = `${c.data.name}|${c.data.domain}|${c.data.path}`;
            const analyzed = analysisMap.get(key);
            const databaseEntry = findCookieInDatabase(c.data.name);
            const oneTrustCat = oneTrustClassifications.get(c.data.name);
            const domain = c.data.domain.startsWith('.') ? c.data.domain : `.${c.data.domain}`;
            const rootDomain = `.${scannedUrlHostname.replace(/^www\./, '')}`;

            const aiCategory = analyzed?.category || CookieCategory.UNKNOWN;
            const dbCategory = databaseEntry?.category;
            const otCategory = oneTrustCat;

            const isConsideredNecessary =
                (aiCategory === CookieCategory.NECESSARY || aiCategory === CookieCategory.UNKNOWN) &&
                (!dbCategory || dbCategory.toLowerCase() === 'necessary' || dbCategory.toLowerCase() === 'functional') &&
                (!otCategory || otCategory.toLowerCase().includes('necessary') || otCategory.toLowerCase().includes('strictly') || otCategory.toLowerCase().includes('essential'));

            let finalComplianceStatus: ComplianceStatus = ComplianceStatus.COMPLIANT;
            if (!isConsideredNecessary) {
                if (c.states.has('pre-consent')) {
                    finalComplianceStatus = ComplianceStatus.PRE_CONSENT_VIOLATION;
                } else if (c.states.has('post-rejection')) {
                    finalComplianceStatus = ComplianceStatus.POST_REJECTION_VIOLATION;
                }
            }

            const originalRemediation = analyzed?.remediation || 'Analysis incomplete.';
            let finalRemediation = originalRemediation;
            if (finalComplianceStatus === ComplianceStatus.PRE_CONSENT_VIOLATION) {
                 finalRemediation = `This ${aiCategory} item was detected before user consent was given. Configure your consent management platform to block this script/cookie until the user explicitly opts in.`;
            } else if (finalComplianceStatus === ComplianceStatus.POST_REJECTION_VIOLATION) {
                 finalRemediation = `This ${aiCategory} item was detected after the user rejected consent. This technology should not be loaded when consent is denied. Check your tag manager triggers and script configurations.`;
            } else if (finalComplianceStatus === ComplianceStatus.COMPLIANT) {
                finalRemediation = "No action needed.";
            }

            return {
                key, name: c.data.name, provider: c.data.domain, expiry: getHumanReadableExpiry(c.data),
                party: domain.endsWith(rootDomain) ? 'First' : 'Third',
                isHttpOnly: c.data.httpOnly, isSecure: c.data.secure,
                complianceStatus: finalComplianceStatus,
                category: aiCategory,
                purpose: analyzed?.purpose || 'No purpose determined.',
                remediation: finalRemediation,
                pagesFound: Array.from(c.pageUrls),
                databaseClassification: dbCategory || undefined,
                oneTrustClassification: otCategory || undefined,
            };
        });

        const analyzedTrackersWithInfo: (TrackerInfo & { key: string })[] = [];
        Array.from(allNetworkRequestMap.values()).forEach(req => {
            const key = req.data.url;
            const analyzed = analysisMap.get(key);
            if (analyzed && analyzed.isTracker) {
                analyzedTrackersWithInfo.push({
                    key, // the full url
                    hostname: req.data.hostname,
                    complianceStatus: (analyzed.complianceStatus as ComplianceStatus) || ComplianceStatus.UNKNOWN,
                    category: analyzed.category || CookieCategory.UNKNOWN,
                    remediation: analyzed.remediation || 'Analysis incomplete.',
                    pagesFound: Array.from(req.pageUrls),
                });
            }
        });

        const groupedTrackersMap = new Map<string, TrackerInfo>();
        const complianceSeverity: Record<string, number> = {
            [ComplianceStatus.PRE_CONSENT_VIOLATION]: 3,
            [ComplianceStatus.POST_REJECTION_VIOLATION]: 2,
            [ComplianceStatus.COMPLIANT]: 1,
            [ComplianceStatus.UNKNOWN]: 0,
        };

        analyzedTrackersWithInfo.forEach(tracker => {
            const existing = groupedTrackersMap.get(tracker.hostname);
            if (!existing) {
                groupedTrackersMap.set(tracker.hostname, {
                    key: tracker.hostname,
                    hostname: tracker.hostname,
                    category: tracker.category,
                    complianceStatus: tracker.complianceStatus,
                    remediation: tracker.remediation,
                    pagesFound: [...tracker.pagesFound],
                });
            } else {
                const combinedPages = new Set([...existing.pagesFound, ...tracker.pagesFound]);
                existing.pagesFound = Array.from(combinedPages);

                const existingSeverity = complianceSeverity[existing.complianceStatus as ComplianceStatus] || 0;
                const newSeverity = complianceSeverity[tracker.complianceStatus as ComplianceStatus] || 0;

                if (newSeverity > existingSeverity) {
                    existing.complianceStatus = tracker.complianceStatus;
                    existing.remediation = tracker.remediation;
                }
            }
        });

        const uniqueTrackers: TrackerInfo[] = Array.from(groupedTrackersMap.values());

        const uniqueLocalStorage: LocalStorageInfo[] = Array.from(allLocalStorageMap.values()).map(s => {
            const key = `${s.data.origin}|${s.data.key}`;
            const analyzed = analysisMap.get(key);
            return {
                key,
                origin: s.data.origin,
                storageKey: s.data.key,
                complianceStatus: analyzed?.complianceStatus || ComplianceStatus.UNKNOWN,
                category: analyzed?.category || CookieCategory.UNKNOWN,
                remediation: analyzed?.remediation || 'Analysis incomplete.',
                purpose: analyzed?.purpose || 'No purpose determined.',
                pagesFound: Array.from(s.pageUrls),
            };
        });

        const thirdPartyDomainsMap = new Map<string, Set<string>>();
        allNetworkRequestMap.forEach(req => {
            if (!thirdPartyDomainsMap.has(req.data.hostname)) {
                thirdPartyDomainsMap.set(req.data.hostname, new Set());
            }
            const pages = thirdPartyDomainsMap.get(req.data.hostname);
            req.pageUrls.forEach((p: string) => pages!.add(p));
        });

        const thirdPartyDomains = Array.from(thirdPartyDomainsMap.entries()).map(([hostname, pageSet]) => ({
            hostname,
            count: pageSet.size,
            pagesFound: Array.from(pageSet)
        }));

        sendEvent({ type: 'result', payload: {
            uniqueCookies,
            uniqueTrackers,
            uniqueLocalStorage,
            thirdPartyDomains,
            pages: Array.from(visitedUrls).map(u => ({ url: u })),
            compliance: complianceAnalysis,
            screenshotBase64,
            consentBannerDetected: consentBannerFound,
            cookiePolicyDetected,
            pagesScannedCount: visitedUrls.size,
            googleConsentV2: googleConsentV2Status,
            cmpProvider,
        }});

    } catch (error) {
        const message = error instanceof Error ? error.message : "An unknown error occurred.";
        console.error('[SERVER] Scan failed:', message);
        sendEvent({ type: 'error', message: `Failed to scan ${url}. ${message}` });
    } finally {
        if (browser) await browser.close();
        res.end();
    }
});

app.post('/api/scan-vulnerabilities', async (req: Request, res: Response) => {
    const { url } = req.body;
    if (!url) return res.status(400).json({ error: 'URL is required' });

    console.log(`[SERVER] Received vulnerability scan request for: ${url}`);
    let browser: Browser | null = null;
    try {
        browser = await puppeteer.launch({
            headless: true,
            args: [
              '--no-sandbox',
              '--disable-setuid-sandbox',
              '--disable-dev-shm-usage',
              '--disable-gpu',
              '--no-first-run',
              '--no-default-browser-check',
              '--disable-background-timer-throttling',
              '--disable-renderer-backgrounding',
              '--disable-backgrounding-occluded-windows',
              '--disable-extensions',
              '--disable-plugins',
              '--disable-images', // Skip loading images for faster scan
              '--disable-web-security',
              '--disable-features=TranslateUI'
            ],
            defaultViewport: { width: 1280, height: 720 },
            timeout: 10000
        });
        const page = await browser.newPage();

        const response = await page.goto(url, { waitUntil: 'domcontentloaded', timeout: 20000 });
        if (!response) throw new Error('Could not get a response from the URL.');

        const headers = response.headers();
        const cookies = await page.cookies();

        const pageData = await page.evaluate(() => {
            const comments: string[] = [];
            const walker = document.createTreeWalker(document.body, NodeFilter.SHOW_COMMENT, null);
            let node;
            let commentCount = 0;
            while((node = walker.nextNode()) && commentCount < 10) { // Limit to 10 comments
                if (node.nodeValue) {
                    comments.push(node.nodeValue.trim());
                    commentCount++;
                }
            }

            const externalScripts = Array.from(document.querySelectorAll('script[src]'))
                .slice(0, 20) // Limit to first 20 scripts
                .map(s => s.getAttribute('src'))
                .filter((src): src is string => !!src && (src.startsWith('http') || src.startsWith('//')));

            const metaTags = Array.from(document.querySelectorAll('meta'))
                .slice(0, 15) // Limit to first 15 meta tags
                .map(m => ({ name: m.name, content: m.content }));

            const insecureLinks = Array.from(document.querySelectorAll('a[target="_blank"]:not([rel~="noopener"]):not([rel~="noreferrer"])'))
                .slice(0, 10) // Limit to first 10 insecure links
                .map(a => (a as HTMLAnchorElement).href);

            const forms = Array.from(document.querySelectorAll('form'))
                .slice(0, 5) // Limit to first 5 forms
                .map(f => ({
                    action: f.getAttribute('action') || '',
                    method: f.getAttribute('method') || 'GET',
                    hasPasswordInput: !!f.querySelector('input[type="password"]'),
                }));

            return { comments, externalScripts, metaTags, insecureLinks, forms };
        });
        // SHORTER, FOCUSED PROMPT for faster AI processing
        const vulnerabilityPrompt = `You are a security expert. Analyze this website data and provide a focused security assessment.

**Data:**
- **Headers:** ${JSON.stringify(headers, null, 2)}
- **Cookies:** ${JSON.stringify(cookies.map(c => ({ name: c.name, secure: c.secure, httpOnly: c.httpOnly })), null, 2)}
- **Meta Tags:** ${JSON.stringify(pageData.metaTags, null, 2)}
- **External Scripts:** ${JSON.stringify(pageData.externalScripts, null, 2)}
- **Insecure Links:** ${JSON.stringify(pageData.insecureLinks, null, 2)}

**Instructions:**
Provide a JSON response with:
1. **overallRisk**: { level: 'Critical'|'High'|'Medium'|'Low', score: 0-10, summary: brief summary }
2. **findings**: Array of security issues found, each with: name, riskLevel, category, description, impact, evidence, remediation, references (2 refs with title/url)

Focus on: Missing security headers, insecure cookies, unsafe external scripts, and information exposure. Be concise but thorough.`;

        const vulnerabilitySchema = {
            type: Type.OBJECT,
            properties: {
                overallRisk: {
                    type: Type.OBJECT,
                    properties: {
                        level: { type: Type.STRING },
                        score: { type: Type.NUMBER },
                        summary: { type: Type.STRING },
                    },
                    required: ['level', 'score', 'summary'],
                },
                findings: {
                    type: Type.ARRAY,
                    items: {
                        type: Type.OBJECT,
                        properties: {
                            name: { type: Type.STRING },
                            riskLevel: { type: Type.STRING },
                            category: { type: Type.STRING },
                            description: { type: Type.STRING },
                            impact: { type: Type.STRING },
                            evidence: { type: Type.STRING },
                            remediation: { type: Type.STRING },
                            references: {
                                type: Type.ARRAY,
                                items: {
                                    type: Type.OBJECT,
                                    properties: {
                                        title: { type: Type.STRING },
                                        url: { type: Type.STRING },
                                    },
                                    required: ['title', 'url'],
                                },
                            },
                        },
                        required: ['name', 'riskLevel', 'category', 'description', 'impact', 'evidence', 'remediation', 'references'],
                    },
                },
            },
            required: ['overallRisk', 'findings'],
        };

        console.log('[AI] Requesting vulnerability assessment...');
        const result = await ai.models.generateContent({
            model,
            contents: [{ parts: [{ text: vulnerabilityPrompt }] }],
            config: {
                responseMimeType: "application/json",
                responseSchema: vulnerabilitySchema,
            },
        });

        const resultText = result.text;
        if (!resultText) {
            throw new Error(`Gemini API returned an empty response for vulnerability scan.`);
        }

        const vulnerabilityReport: VulnerabilityScanResult = JSON.parse(resultText);

        res.json(vulnerabilityReport);
    } catch (error) {
        const message = error instanceof Error ? error.message : "An unknown error occurred.";
        console.error('[SERVER] Vulnerability scan failed:', message);
        res.status(500).json({ error: `Failed to scan ${url} for vulnerabilities. ${message}` });
    } finally {
        if (browser) await browser.close();
    }
});

// Legal Document Analysis
interface LegalReviewBody {
    documentText: string;
    perspective: LegalPerspective;
}
app.post('/api/analyze-legal-document', async (req: Request<{}, {}, LegalReviewBody>, res: Response) => {
    const { documentText, perspective } = req.body;
    if (!documentText) return res.status(400).json({ error: 'Document text is required.' });

    try {
        console.log(`[SERVER] Received legal analysis request (perspective: ${perspective}).`);

        const legalPrompt = `
You are a world-class AI legal analyst. Your task is to perform a detailed risk analysis of the provided legal document from the perspective of a **${perspective}**.

**Document Text:**
---
${documentText}
---

**Instructions:**
1.  **Overall Risk:** Start by providing an 'overallRisk' object.
    * 'level': A single risk level ('Critical', 'High', 'Medium', 'Low') for the entire document from the chosen perspective.
    * 'summary': A concise, two-sentence executive summary explaining the primary risks or lack thereof.
2.  **Clause-by-Clause Analysis:** Provide an 'analysis' array of objects, one for each significant clause or section you identify (e.g., "Liability," "Data Processing," "Confidentiality," "Termination"). For each clause:
    * 'clause': The name of the clause (e.g., "Limitation of Liability").
    * 'summary': A brief, plain-language summary of what the clause means.
    * 'risk': A detailed explanation of the specific risks this clause poses to the **${perspective}**. Be specific.
    * 'riskLevel': The risk level for this specific clause.
    * 'recommendation': A concrete, actionable recommendation for how the **${perspective}** could negotiate or amend this clause to mitigate risk.

Your final output must be a single, valid JSON object adhering to this structure. Do not include any other text or markdown.
        `;

        const legalSchema = {
            type: Type.OBJECT,
            properties: {
                overallRisk: {
                    type: Type.OBJECT,
                    properties: {
                        level: { type: Type.STRING },
                        summary: { type: Type.STRING },
                    },
                    required: ['level', 'summary'],
                },
                analysis: {
                    type: Type.ARRAY,
                    items: {
                        type: Type.OBJECT,
                        properties: {
                            clause: { type: Type.STRING },
                            summary: { type: Type.STRING },
                            risk: { type: Type.STRING },
                            riskLevel: { type: Type.STRING },
                            recommendation: { type: Type.STRING },
                        },
                        required: ['clause', 'summary', 'risk', 'riskLevel', 'recommendation'],
                    },
                },
            },
            required: ['overallRisk', 'analysis'],
        };

        const result = await ai.models.generateContent({
            model,
            contents: [{ parts: [{ text: legalPrompt }] }],
            config: { responseMimeType: "application/json", responseSchema: legalSchema },
        });

        const resultText = result.text;
        if (!resultText) throw new Error('AI analysis returned an empty response.');

        const analysis: LegalAnalysisResult = JSON.parse(resultText);
        res.json(analysis);

    } catch (error) {
        const message = error instanceof Error ? error.message : "An unknown error occurred.";
        console.error('[SERVER] Legal analysis failed:', message);
        res.status(500).json({ error: `Failed to analyze document. ${message}` });
    }
});

// --- Template Library Endpoints ---
app.get('/api/templates', (req: Request, res: Response) => {
    console.log('[SERVER] Fetching all contract templates.');
    res.json(Array.from(templateLibrary.values()));
});

app.post('/api/templates', (req: Request<{}, {}, { name: string; content: string }>, res: Response) => {
    const { name, content } = req.body;
    if (!name || !content) {
        return res.status(400).json({ error: 'Template name and content are required.' });
    }
    const id = `${Date.now()}-${name.replace(/\s+/g, '-')}`;
    const newTemplate: ContractTemplate = { id, name, content };
    templateLibrary.set(id, newTemplate);
    console.log(`[SERVER] Added new template: ${name} (ID: ${id})`);
    res.status(201).json(newTemplate);
});

app.delete('/api/templates/:id', (req: Request<{ id: string }>, res: Response) => {
    const { id } = req.params;
    if (templateLibrary.has(id)) {
        templateLibrary.delete(id);
        console.log(`[SERVER] Deleted template with ID: ${id}`);
        res.status(204).send();
    } else {
        res.status(404).json({ error: `Template with id ${id} not found.` });
    }
});


// Contract Generation
interface GenerateContractBody {
    contractType: string;
    details: string; // Will be a stringified JSON object
    templateContent?: string;
}
app.post('/api/generate-contract', async (req: Request<{}, {}, GenerateContractBody>, res: Response) => {
    const { contractType, details, templateContent } = req.body as GenerateContractBody;
    if (!contractType || !details) return res.status(400).json({ error: 'Contract type and details are required.' });

    try {
        let generationPrompt: string;

        if (templateContent) {
            console.log(`[SERVER] Received request to generate contract from a template.`);
            generationPrompt = `
You are an expert legal AI assistant. Your task is to complete the provided contract template using the key details supplied by the user in a structured JSON format.
Diligently and accurately fill in the placeholders in the template (like "[Disclosing Party Name]", "[Effective Date]", "[Term]", etc.) with the corresponding values from the user's JSON details.
If a detail is provided by the user but has no clear placeholder in the template, try to incorporate it logically where it makes sense.
The final title should be taken from the template's likely title or a generic one if none is obvious.

**Contract Template to Complete:**
---
${templateContent}
---

**User's Key Details (JSON Format):**
---
${details}
---

Your output must be a JSON object with "title" and "content" keys. The "content" must be the fully completed contract as a well-structured HTML string. Follow these formatting rules STRICTLY:
- Use <h2> for main section headers (e.g., "1. Confidentiality").
- Use <h3> for sub-section headers if needed.
- Use <p> for all paragraphs of text. Each paragraph must be in its own tag.
- Use <strong> to emphasize important terms, party names, or dates.
- Use <ul> and <li> for any enumerated lists.
- DO NOT return a single block of text. The document must be properly structured with these HTML tags to be readable.

Return ONLY the valid JSON object.`;
        } else {
            console.log(`[SERVER] Received request to generate a ${contractType} from scratch.`);
            generationPrompt = `
You are an expert legal AI specializing in contract drafting. Generate a standard, professional **${contractType}**.
Incorporate the following key details provided by the user in a structured JSON format:
---
${details}
---
The generated contract should be robust, clear, and follow best practices.

Your output must be a JSON object with "title" (e.g., "Mutual Non-Disclosure Agreement") and "content" keys. The "content" must be the fully completed contract as a well-structured HTML string. Follow these formatting rules STRICTLY:
- Use <h2> for main section headers (e.g., "1. Confidentiality").
- Use <h3> for sub-section headers if needed.
- Use <p> for all paragraphs of text. Each paragraph must be in its own tag.
- Use <strong> to emphasize important terms, party names, or dates.
- Use <ul> and <li> for any enumerated lists.
- DO NOT return a single block of text. The document must be properly structured with these HTML tags to be readable.

Return ONLY the valid JSON object.`;
        }

        const generationSchema = {
            type: Type.OBJECT,
            properties: {
                title: { type: Type.STRING },
                content: { type: Type.STRING },
            },
            required: ['title', 'content'],
        };

        const result = await ai.models.generateContent({
            model,
            contents: [{ parts: [{ text: generationPrompt }] }],
            config: { responseMimeType: "application/json", responseSchema: generationSchema },
        });

        const resultText = result.text;
        if (!resultText) throw new Error('AI contract generation returned an empty response.');

        const contract: GeneratedContract = JSON.parse(resultText);
        res.json(contract);
    } catch (error) {
        const message = error instanceof Error ? error.message : "An unknown error occurred.";
        console.error('[SERVER] Contract generation failed:', message);
        res.status(500).json({ error: `Failed to generate contract. ${message}` });
    }
});

// AI Chat with Document
interface ChatRequestBody {
    documentText: string;
    question: string;
}
app.post('/api/chat-with-document', async (req: Request<{}, {}, ChatRequestBody>, res: Response) => {
    const { documentText, question } = req.body;
    if (!documentText || !question) {
        return res.status(400).json({ error: 'Document text and a question are required.' });
    }

    try {
        console.log('[AI] Answering/editing question about document...');
        const prompt = `You are an interactive legal AI assistant. You can answer questions or perform edits on the provided document.

**DOCUMENT TEXT:**
---
${documentText}
---

**USER'S INSTRUCTION:** "${question}"

**Your Task:**
1.  First, determine the user's intent. Is it a question (e.g., "what does this mean?") or an editing command (e.g., "rephrase this", "add a clause")?
2.  **If the intent is to ask a question:**
    * Formulate an answer based ONLY on the document's content.
    * Return a JSON object: \`{ "answer": "Your detailed answer here.", "revisedText": null }\`
3.  **If the intent is to edit the document:**
    * Perform the requested edit (rephrase, add, remove, change) to the best of your ability.
    * Return a short, conversational confirmation message in the "answer" field (e.g., "Certainly, I have rephrased the termination clause for clarity.").
    * Return the ENTIRE, full text of the newly modified document in the "revisedText" field.

Your response must be a single, valid JSON object. Do not include any other text or markdown.
        `;

        const chatSchema = {
            type: Type.OBJECT,
            properties: {
                answer: { type: Type.STRING },
                revisedText: { type: [Type.STRING, Type.NULL] },
            },
            required: ['answer', 'revisedText'],
        };

        const result = await ai.models.generateContent({
            model,
            contents: [{ parts: [{ text: prompt }] }],
            config: { responseMimeType: "application/json", responseSchema: chatSchema },
        });

        const resultText = result.text;
        if (!resultText) throw new Error('AI chat returned an empty response.');

        res.json(JSON.parse(resultText));

    } catch (error) {
        const message = error instanceof Error ? error.message : "An unknown error occurred.";
        console.error('[SERVER] Chat with document failed:', message);
        res.status(500).json({ error: `Chat failed. ${message}` });
    }
});

// SPA fallback for production
if (process.env.NODE_ENV === 'production') {
    app.get('*', (req: Request, res: Response) => {
        // Don't serve index.html for API routes
        if (req.path.startsWith('/api/') || req.path.startsWith('/health') || req.path.startsWith('/debug-')) {
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

// Error handling middleware
app.use((err: Error, req: Request, res: Response, next: Function) => {
    console.error('[SERVER] Unhandled error:', err);
    console.error('[SERVER] Error stack:', err.stack);
    res.status(500).json({
        error: 'Internal server error',
        message: err.message,
        stack: process.env.NODE_ENV === 'development' ? err.stack : undefined
    });
});

// Graceful shutdown
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
    console.log(`[SERVER] Health check available at: /health`);
    console.log(`[SERVER] Debug routes available at: /debug-routes`);
    console.log(`[SERVER] Static files served from: ${path.join(__dirname, '..', 'public')}`);
});
