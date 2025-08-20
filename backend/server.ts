import express, { type Request, type Response } from 'express';
import puppeteer, { type Cookie, type Page, type Frame, type Browser } from 'puppeteer';
import cors from 'cors';
import dotenv from 'dotenv';
import { GoogleGenAI, Type } from '@google/genai';
import { CookieCategory, type CookieInfo, type ScanResultData, type TrackerInfo, ComplianceStatus, type LegalAnalysisResult, type LegalPerspective, type VulnerabilityScanResult, type VulnerabilityCategory, type GeneratedContract, ContractTemplate } from './types.js';
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

// Serve static files in production - MOVE THIS AFTER BASIC ROUTES BUT BEFORE API ROUTES
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
    'google-analytics.com', 'googletagmanager.com', 'analytics.google.com', 'doubleclick.net', 'googleadservices.com', 'googlesyndication.com', 'connect.facebook.net', 'facebook.com/tr', 'c.clarity.ms', 'clarity.ms', 'hotjar.com', 'hotjar.io', 'hjid.hotjar.com', 'hubspot.com', 'hs-analytics.net', 'track.hubspot.com', 'linkedin.com/px', 'ads.linkedin.com', 'twitter.com/i/ads', 'ads-twitter.com', 'bing.com/ads', 'semrush.com', 'optimizely.com', 'vwo.com', 'crazyegg.com', 'taboola.com', 'outbrain.com', 'criteo.com', 'addthis.com', 'sharethis.com', 'tiqcdn.com', // Tealium
];

const getHumanReadableExpiry = (puppeteerCookie: Cookie): string => {
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

const collectPageData = async (page: Page, scanTimeout: number): Promise<{ cookies: Cookie[], trackers: Set<string> }> => {
    const trackers = new Set<string>();
    const requestListener = (request: any) => {
        const reqUrl = request.url();
        const trackerDomain = knownTrackerDomains.find(domain => reqUrl.includes(domain));
        if (trackerDomain) trackers.add(`${trackerDomain}|${reqUrl}`);
    };
    page.on('request', requestListener);
    
    try {
        // FASTER: Use 'domcontentloaded' instead of 'networkidle2'
        await page.reload({ 
            waitUntil: 'domcontentloaded',
            timeout: scanTimeout 
        });
        
        // FIXED: Use setTimeout wrapped in Promise instead of waitForTimeout
        await new Promise(resolve => setTimeout(resolve, 1000));
        
        const cookies = await page.cookies();
        
        page.off('request', requestListener);
        return { cookies, trackers };
    } catch (error) {
        page.off('request', requestListener);
        console.warn(`[SCAN] Error collecting page data:`, error instanceof Error ? error.message : error);
        // Return partial data instead of failing completely
        const cookies = await page.cookies().catch(() => []);
        return { cookies, trackers };
    }
}

interface ApiScanRequestBody { 
    url: string; 
    scanDepth?: number;
}

// Add this route to see what files exist:
app.get('/debug-files', (req: Request, res: Response) => {
  try {
    // Check multiple possible locations
    const locations = [
      path.join(__dirname, 'public'),
      path.join(__dirname, '..'),
      path.join(__dirname, '../dist'),
      '/app',
      '/app/dist',
      '/app/backend/public'
    ];
    
    const results: any = {
      __dirname,
      locations: {}
    };
    
    locations.forEach(loc => {
      try {
        const exists = fs.existsSync(loc);
        results.locations[loc] = {
          exists,
          files: exists ? fs.readdirSync(loc) : []
        };
      } catch (e) {
        results.locations[loc] = { error: e instanceof Error ? e.message : 'Unknown error' };
      }
    });
    
    res.json(results);
  } catch (error) {
    res.status(500).json({ 
      error: error instanceof Error ? error.message : 'Unknown error' 
    });
  }
});

// 🔍 Debug middleware for API routes:
app.use('/api/*', (req: Request, res: Response, next: Function) => {
  console.log('[API DEBUG] Request:', req.method, req.path, req.url);
  console.log('[API DEBUG] Body:', req.body);
  next();
});

// ADD A SIMPLE TEST ROUTE
app.get('/api/test', (req: Request, res: Response) => {
  res.json({ 
    message: 'API is working!', 
    timestamp: new Date().toISOString(),
    path: req.path,
    url: req.url
  });
});

app.post('/api/scan', async (req: Request<{}, {}, ApiScanRequestBody>, res: Response) => {
  const { url, scanDepth } = req.body;
  if (!url) return res.status(400).json({ error: 'URL is required' });
  
  const MAX_PAGES_TO_SCAN = Math.max(1, Math.min(10, scanDepth || 1));
  const SCAN_TIMEOUT = 15000;
  
  console.log(`[SERVER] Received scan request for: ${url} with depth ${MAX_PAGES_TO_SCAN}`);
  let browser: Browser | null = null;
  try {
    // GCP Cloud Run optimized Puppeteer configuration
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
        '--disable-images',
        '--disable-web-security',
        '--disable-features=TranslateUI'
      ],
      defaultViewport: { width: 1280, height: 720 },
      timeout: 10000
    });
    const page = await browser.newPage();
    await page.setUserAgent('Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/108.0.0.0 Safari/537.36');
    await page.setViewport({ width: 1920, height: 1080 });

    const urlsToVisit: string[] = [url];
    const visitedUrls = new Set<string>();
    const allCookieMap = new Map<string, any>();
    const allTrackerMap = new Map<string, any>();
    const rootUrl = new URL(url);

    let screenshotBase64 = '';
    let consentBannerFound = false;

    const processItems = (map: Map<string, any>, items: any[], state: string, isCookie: boolean) => {
        items.forEach((item: any) => {
            const key = isCookie ? `${item.name}|${item.domain}|${item.path}` : `${item.split('|')[0]}|${item.split('|')[1]}`;
            if (!map.has(key)) {
                map.set(key, { states: new Set(), data: item });
            }
            map.get(key).states.add(state);
        });
    };
    
    while(visitedUrls.size < MAX_PAGES_TO_SCAN && urlsToVisit.length > 0) {
        const currentUrl = urlsToVisit.shift();
        if (!currentUrl || visitedUrls.has(currentUrl)) {
            continue;
        }

        try {
            const pageUrl = new URL(currentUrl);
            if (pageUrl.hostname !== rootUrl.hostname) {
                continue;
            }
        } catch (e) {
            console.warn(`[CRAWL] Invalid URL skipped: ${currentUrl}`);
            continue;
        }

        console.log(`[CRAWL] Scanning page ${visitedUrls.size + 1}/${MAX_PAGES_TO_SCAN}: ${currentUrl}`);

        try {
            await page.goto(currentUrl, { waitUntil: 'networkidle2', timeout: 30000 });
            visitedUrls.add(currentUrl);

            // Full 3-stage scan for the first page only
            if (visitedUrls.size === 1) {
                console.log('[SCAN] Capturing pre-consent state...');
                screenshotBase64 = await page.screenshot({ encoding: 'base64', type: 'jpeg', quality: 70 });
                const { cookies: preConsentCookies, trackers: preConsentTrackers } = await collectPageData(page, SCAN_TIMEOUT);
                processItems(allCookieMap, preConsentCookies, 'pre-consent', true);
                processItems(allTrackerMap, Array.from(preConsentTrackers), 'pre-consent', false);
                console.log(`[SCAN] Pre-consent: ${preConsentCookies.length} cookies, ${preConsentTrackers.size} trackers.`);
                
                console.log('[SCAN] Capturing post-rejection state...');
                consentBannerFound = await handleConsent(page, 'reject');
                const { cookies: postRejectCookies, trackers: postRejectTrackers } = await collectPageData(page, SCAN_TIMEOUT);
                processItems(allCookieMap, postRejectCookies, 'post-rejection', true);
                processItems(allTrackerMap, Array.from(postRejectTrackers), 'post-rejection', false);
                console.log(`[SCAN] Post-rejection: ${postRejectCookies.length} cookies, ${postRejectTrackers.size} trackers.`);

                console.log('[SCAN] Capturing post-acceptance state...');
                await page.reload({ waitUntil: 'networkidle2' });
                await handleConsent(page, 'accept');
                const { cookies: postAcceptCookies, trackers: postAcceptTrackers } = await collectPageData(page, SCAN_TIMEOUT);
                processItems(allCookieMap, postAcceptCookies, 'post-acceptance', true);
                processItems(allTrackerMap, Array.from(postAcceptTrackers), 'post-acceptance', false);
                console.log(`[SCAN] Post-acceptance: ${postAcceptCookies.length} cookies, ${postAcceptTrackers.size} trackers.`);
            } else { // Simplified scan for subsequent pages
                const { cookies, trackers } = await collectPageData(page, SCAN_TIMEOUT);
                processItems(allCookieMap, cookies, 'post-acceptance', true);
                processItems(allTrackerMap, Array.from(trackers), 'post-acceptance', false);
                console.log(`[SCAN] Subsequent page: ${cookies.length} cookies, ${trackers.size} trackers.`);
            }

            // Discover new links on every scanned page
            const internalLinks = await page.evaluate((hostname) => {
                const links = new Set<string>();
                document.querySelectorAll('a[href]').forEach(el => {
                    const anchor = el as HTMLAnchorElement;
                    try {
                        const linkUrl = new URL(anchor.href, document.baseURI);
                        if (linkUrl.hostname === hostname) {
                            links.add(linkUrl.href.split('#')[0]); // Add link without fragment
                        }
                    } catch (e) { /* ignore invalid URLs */ }
                });
                return Array.from(links);
            }, rootUrl.hostname);

            internalLinks.forEach(link => {
                if (!visitedUrls.has(link) && !urlsToVisit.includes(link)) {
                    urlsToVisit.push(link);
                }
            });

        } catch (pageError) {
             console.warn(`[CRAWL] Failed to load page ${currentUrl}:`, pageError instanceof Error ? pageError.message : pageError);
        }
    }

    const allItemsToAnalyze = [
        ...Array.from(allCookieMap.values()).map(value => ({ type: 'cookie', data: value })),
        ...Array.from(allTrackerMap.values()).map(value => ({ type: 'tracker', data: value }))
    ];

    if (allItemsToAnalyze.length === 0) {
        return res.json({
            cookies: [], trackers: [], screenshotBase64,
            consentBannerDetected: consentBannerFound,
            pagesScannedCount: visitedUrls.size,
            compliance: {
                gdpr: { riskLevel: 'Low', assessment: 'No cookies or trackers were detected.'},
                ccpa: { riskLevel: 'Low', assessment: 'No cookies or trackers were detected.'},
            }
        });
    }

    const BATCH_SIZE = 40;
    const batches = [];
    for (let i = 0; i < allItemsToAnalyze.length; i += BATCH_SIZE) {
        batches.push(allItemsToAnalyze.slice(i, i + BATCH_SIZE));
    }
    console.log(`[AI] Splitting analysis into ${batches.length} batch(es) of size ~${BATCH_SIZE}.`);

    const analyzeBatch = async (batch: any[], batchNum: number, maxRetries = 2): Promise<any[]> => {
      const itemsForBatchAnalysis = batch.map(item => {
        if (item.type === 'cookie') {
            const { name, domain, path } = item.data.data;
            return { type: 'cookie', key: `${name}|${domain}|${path}`, name, provider: domain, states: Array.from(item.data.states) };
        }
        const [provider] = item.data.data.split('|');
        return { type: 'tracker', key: item.data.data, provider, states: Array.from(item.data.states) };
      });
  
      const batchPrompt = `You are a privacy expert categorizing web technologies. Given this batch of cookies and trackers and the states they were observed in ('pre-consent', 'post-rejection', 'post-acceptance'), provide a JSON array. For each item:
- key: The original key.
- category: Categorize into 'Necessary', 'Functional', 'Analytics', 'Marketing', 'Unknown'. Be strict: only essential-for-operation items are 'Necessary'.
- purpose: (For cookies only) A very brief, one-sentence description of the cookie's likely function. Limit to 15 words. If not a cookie, return an empty string.
- complianceStatus: Determine based on its 'states' and 'category':
    - If category is 'Necessary': 'Compliant'.
    - If state includes 'pre-consent' AND category is NOT 'Necessary': 'Pre-Consent Violation'.
    - If state includes 'post-rejection' AND category is NOT 'Necessary': 'Post-Rejection Violation'.
    - Otherwise: 'Compliant'.

CRITICAL: Your response must be ONLY a valid JSON array, nothing else. Do not add any explanatory text.

Input Data:
${JSON.stringify(itemsForBatchAnalysis, null, 2)}`;
      
      const batchResponseSchema = {
        type: Type.ARRAY,
        items: {
            type: Type.OBJECT,
            properties: {
                key: { type: Type.STRING },
                category: { type: Type.STRING },
                purpose: { type: Type.STRING },
                complianceStatus: { type: Type.STRING }
            },
            required: ["key", "category", "purpose", "complianceStatus"]
        }
      };
      
      for (let attempt = 0; attempt <= maxRetries; attempt++) {
        try {
            console.log(`[AI] Analyzing batch ${batchNum + 1}/${batches.length} (Attempt ${attempt + 1})...`);
            const result = await ai.models.generateContent({
                model, contents: [{ parts: [{ text: batchPrompt }] }],
                config: {
                    responseMimeType: "application/json",
                    responseSchema: batchResponseSchema,
                },
            });
            
            let resultText = result.text;
            if (!resultText) {
                throw new Error(`Gemini API returned an empty response for analysis batch #${batchNum + 1}.`);
            }

            // FIX: Clean the response text to extract only JSON
            resultText = resultText.trim();
            
            // Find the first '[' and last ']' to extract JSON array
            const firstBracket = resultText.indexOf('[');
            const lastBracket = resultText.lastIndexOf(']');
            
            if (firstBracket === -1 || lastBracket === -1 || firstBracket >= lastBracket) {
                throw new Error(`No valid JSON array found in AI response`);
            }
            
            // Extract only the JSON part
            const jsonPart = resultText.substring(firstBracket, lastBracket + 1);
            
            try {
                const parsedResult = JSON.parse(jsonPart);
                if (!Array.isArray(parsedResult)) {
                    throw new Error(`Response is not an array`);
                }
                return parsedResult;
            } catch (parseError) {
                console.error(`[AI] JSON Parse Error for batch ${batchNum + 1}:`, parseError);
                console.error(`[AI] Cleaned text:`, jsonPart.substring(0, 200));
                throw parseError;
            }
            
        } catch(error) {
            console.warn(`[AI] Attempt ${attempt + 1}/${maxRetries + 1} failed for batch ${batchNum + 1}.`, error instanceof Error ? error.message : error);
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
        try {
            console.log(`[AI] Processing batch ${index + 1}/${batches.length}...`);
            const batchAnalysis = await analyzeBatch(batch, index);
            aggregatedAnalysis.push(...batchAnalysis);
            
            // Short delay between batches to prevent rate limiting
            if (index < batches.length - 1) {
                await new Promise(res => setTimeout(res, 500));
            }
        } catch (error) {
            console.error(`[AI] Batch ${index + 1} failed, continuing with next batch:`, error);
            // Continue processing other batches instead of failing entirely
            continue;
        }
    }

    // If no successful analysis, provide fallback
    if (aggregatedAnalysis.length === 0) {
        console.warn('[AI] All AI batches failed, providing basic analysis');
        return res.json({
            cookies: Array.from(allCookieMap.values()).map(c => ({
                key: `${c.data.name}|${c.data.domain}|${c.data.path}`,
                name: c.data.name,
                provider: c.data.domain,
                expiry: getHumanReadableExpiry(c.data),
                party: c.data.domain.startsWith('.') ? 'Third' : 'First',
                isHttpOnly: c.data.httpOnly,
                isSecure: c.data.secure,
                complianceStatus: 'Unknown',
                category: 'Unknown',
                purpose: 'Analysis failed - manual review required',
            })),
            trackers: Array.from(allTrackerMap.values()).map(t => {
                const [provider, trackerUrl] = t.data.split('|');
                return {
                    key: t.data,
                    url: trackerUrl,
                    provider,
                    category: 'Unknown',
                    complianceStatus: 'Unknown',
                };
            }),
            screenshotBase64,
            consentBannerDetected: consentBannerFound,
            pagesScannedCount: visitedUrls.size,
            compliance: {
                gdpr: { riskLevel: 'Medium', assessment: 'AI analysis failed - manual privacy review recommended.'},
                ccpa: { riskLevel: 'Medium', assessment: 'AI analysis failed - manual privacy review recommended.'},
            }
        });
    }

    console.log('[AI] All batches analyzed successfully.');

    const violationSummary = {
        preConsentViolations: aggregatedAnalysis.filter(a => a.complianceStatus === 'Pre-Consent Violation').length,
        postRejectionViolations: aggregatedAnalysis.filter(a => a.complianceStatus === 'Post-Rejection Violation').length,
        totalMarketing: aggregatedAnalysis.filter(a => a.category === CookieCategory.MARKETING).length,
        totalAnalytics: aggregatedAnalysis.filter(a => a.category === CookieCategory.ANALYTICS).length,
        totalItems: allItemsToAnalyze.length,
    };
    
    const compliancePrompt = `You are a privacy expert providing a risk assessment. Based on this summary from a website scan, provide a JSON object with "gdpr" and "ccpa" keys.
Summary:
${JSON.stringify(violationSummary, null, 2)}
For both GDPR and CCPA, provide:
- riskLevel: 'Low', 'Medium', 'High'. Any violation ('preConsentViolations' or 'postRejectionViolations' > 0) immediately makes the risk 'High'. A large number of marketing/analytics trackers suggests at least 'Medium' risk.
- assessment: A brief, professional summary explaining the risk level. Specifically mention the number of violations as the primary reason for a 'High' risk assessment.
Return ONLY the valid JSON object.`;
    
    const complianceSchema = {
      type: Type.OBJECT, properties: {
          gdpr: { type: Type.OBJECT, properties: { riskLevel: { type: Type.STRING }, assessment: { type: Type.STRING } }, required: ['riskLevel', 'assessment']},
          ccpa: { type: Type.OBJECT, properties: { riskLevel: { type: Type.STRING }, assessment: { type: Type.STRING } }, required: ['riskLevel', 'assessment']},
      }, required: ['gdpr', 'ccpa']
    };
    
    console.log('[AI] Requesting final compliance assessment...');
    const complianceResult = await ai.models.generateContent({
        model, contents: [{ parts: [{ text: compliancePrompt }] }],
        config: { responseMimeType: "application/json", responseSchema: complianceSchema },
    });
    
    const complianceText = complianceResult.text;
    if (!complianceText) {
      throw new Error('Gemini API returned an empty response for the final compliance assessment.');
    }
    const complianceAnalysis = JSON.parse(complianceText);
    
    const analysisMap = new Map(aggregatedAnalysis.map((item: any) => [item.key, item]));
    const scannedUrlHostname = new URL(url).hostname;
    
    const finalEnrichedCookies: CookieInfo[] = Array.from(allCookieMap.values()).map(c => {
        const key = `${c.data.name}|${c.data.domain}|${c.data.path}`;
        const analyzed = analysisMap.get(key);
        const domain = c.data.domain.startsWith('.') ? c.data.domain : `.${c.data.domain}`;
        const rootDomain = `.${scannedUrlHostname.replace(/^www\./, '')}`;
        return {
            key, name: c.data.name, provider: c.data.domain, expiry: getHumanReadableExpiry(c.data),
            party: domain.endsWith(rootDomain) ? 'First' : 'Third',
            isHttpOnly: c.data.httpOnly, isSecure: c.data.secure,
            complianceStatus: analyzed?.complianceStatus || ComplianceStatus.UNKNOWN,
            category: analyzed?.category || CookieCategory.UNKNOWN,
            purpose: analyzed?.purpose || 'No purpose determined.',
        };
    });

    const finalEnrichedTrackers: TrackerInfo[] = Array.from(allTrackerMap.values()).map(t => {
        const [provider, trackerUrl] = t.data.split('|');
        const key = t.data;
        const analyzed = analysisMap.get(key);
        return {
            key, url: trackerUrl, provider,
            category: analyzed?.category || CookieCategory.UNKNOWN,
            complianceStatus: analyzed?.complianceStatus || ComplianceStatus.UNKNOWN,
        };
    });

    res.json({ cookies: finalEnrichedCookies, trackers: finalEnrichedTrackers, compliance: complianceAnalysis, screenshotBase64, consentBannerDetected: consentBannerFound, pagesScannedCount: visitedUrls.size });

  } catch (error) {
    const message = error instanceof Error ? error.message : "An unknown error occurred.";
    console.error('[SERVER] Scan failed:', message);
    if (error instanceof Error && error.message.includes("JSON")) {
       res.status(500).json({ error: `An AI analysis step failed due to invalid data format. This can happen with complex sites. Please try again. Details: ${message}` });
    } else {
       res.status(500).json({ error: `Failed to scan ${url}. ${message}` });
    }
  } finally {
    if (browser) await browser.close();
  }
});

// OPTIMIZED vulnerability scan route for GCP Cloud Run
app.post('/api/scan-vulnerabilities', async (req: Request<{}, {}, { url: string }>, res: Response) => {
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
            // ADD THESE FOR SPEED:
            '--disable-extensions',
            '--disable-plugins',
            '--disable-images', // Skip loading images for faster scan
            '--disable-web-security',
            '--disable-features=TranslateUI'
          ],
          defaultViewport: { width: 1280, height: 720 }, // Smaller viewport
          timeout: 10000 // Faster startup
        });
        const page = await browser.newPage();
        
        // FASTER: Use domcontentloaded instead of networkidle0
        const response = await page.goto(url, { 
            waitUntil: 'domcontentloaded', // Changed from 'networkidle0'
            timeout: 20000 // Reduced from 60000 to 20000
        });
        if (!response) throw new Error('Could not get a response from the URL.');

        const headers = response.headers();
        const cookies = await page.cookies();
        
        const pageData = await page.evaluate(() => {
            // FASTER: Limit data collection to essential items only
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
    *   'level': A single risk level ('Critical', 'High', 'Medium', 'Low') for the entire document from the chosen perspective.
    *   'summary': A concise, two-sentence executive summary explaining the primary risks or lack thereof.
2.  **Clause-by-Clause Analysis:** Provide an 'analysis' array of objects, one for each significant clause or section you identify (e.g., "Liability," "Data Processing," "Confidentiality," "Termination"). For each clause:
    *   'clause': The name of the clause (e.g., "Limitation of Liability").
    *   'summary': A brief, plain-language summary of what the clause means.
    *   'risk': A detailed explanation of the specific risks this clause poses to the **${perspective}**. Be specific.
    *   'riskLevel': The risk level for this specific clause.
    *   'recommendation': A concrete, actionable recommendation for how the **${perspective}** could negotiate or amend this clause to mitigate risk.

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
    details: string;
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
You are an expert legal AI assistant. Your task is to complete the provided contract template using the key details supplied by the user. 
Fill in the placeholders (like "[Your Company Name]", "[Effective Date]", "[Counterparty Name]", etc.) in the template with the corresponding information from the user's details. 
If a detail is provided by the user but has no clear placeholder in the template, try to incorporate it logically where it makes sense. 
Adhere strictly to the structure and wording of the original template. The final title should be taken from the template's likely title or a generic one if none is obvious.

**Contract Template to Complete:**
---
${templateContent}
---

**User's Key Details to Incorporate:**
---
${details}
---

The output must be a JSON object with two keys: "title" and "content". The "content" must be the fully completed contract text based on the template.
Return ONLY the valid JSON object.`;
        } else {
            console.log(`[SERVER] Received request to generate a ${contractType} from scratch.`);
            generationPrompt = `
You are an expert legal AI specializing in contract drafting. Generate a standard, professional **${contractType}**.
Incorporate the following key details provided by the user:
---
${details}
---
The generated contract should be robust, clear, and follow best practices. The output must be a JSON object with two keys: "title" (e.g., "Mutual Non-Disclosure Agreement") and "content" (the full, formatted text of the contract).
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
            *   Formulate an answer based ONLY on the document's content.
            *   Set the value of \`revisedText\` to be the **exact, verbatim, original document text**. Do NOT alter it in any way, including whitespace or formatting.
        3.  **If the intent is to edit the document:**
            *   Perform the requested edit on the document text.
            *   Formulate a short confirmation message for your answer (e.g., "I have updated the liability section as requested.").
            *   Set the value of \`revisedText\` to be the newly modified document content.
        4.  **Your output MUST be a valid JSON object** with two keys:
            *   \`answer\`: Your conversational response to the user.
            *   \`revisedText\`: The full document text. This MUST be the original text if no edit was made, or the modified text if an edit was performed.

        Return ONLY the JSON object.`;

        const chatSchema = {
            type: Type.OBJECT,
            properties: {
                answer: { type: Type.STRING },
                revisedText: { type: Type.STRING },
            },
            required: ['answer', 'revisedText'],
        };

        const result = await ai.models.generateContent({
            model,
            contents: [{ parts: [{ text: prompt }] }],
            config: {
                responseMimeType: "application/json",
                responseSchema: chatSchema,
            },
        });
        
        const resultText = result.text;
        if (!resultText) {
          throw new Error('Gemini API returned an empty response for the chat request.');
        }

        res.json(JSON.parse(resultText));

    } catch (error) {
        const message = error instanceof Error ? error.message : "An unknown error occurred.";
        console.error('[SERVER] Chat failed:', message);
        res.status(500).json({ error: `Failed to get an answer. ${message}` });
    }
});

// SPA fallback for production - MOVE THIS BEFORE ERROR HANDLERS
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
