# Cookie Care: Product Document

## 1. The What: Holistic Compliance Analysis Engine

**Cookie Care** is an enterprise-grade web application designed to provide a 360-degree view of a website's digital compliance and security posture. It is not just a scanner; it is an intelligent analysis engine that empowers businesses to proactively identify and mitigate privacy risks.

The application is built on three core pillars:

1.  **Cookie Scanner:** Delivers real-time, in-depth reports on website cookies, network trackers, and consent banner effectiveness. It goes beyond simple detection to analyze compliance against regulations like GDPR and CCPA using a unique, multi-stage scanning methodology.
2.  **DPA Reviewer:** An AI-powered legal assistant that analyzes complex Data Processing Agreements (DPAs). Users can paste DPA text, and the tool provides a clause-by-clause breakdown of risks, plain-language summaries, and actionable recommendations from either a Data Controller or Data Processor perspective.
3.  **Vulnerability Scanner:** A non-intrusive security tool that performs a passive scan of a website's front end. It analyzes HTTP headers and page source to identify common security misconfigurations and vulnerabilities, providing a risk score and clear remediation plans.

## 2. The Why: The Need for Intelligent Compliance

In today's digital landscape, businesses face a complex and ever-evolving web of regulations. Non-compliance with laws like GDPR and CCPA can lead to severe financial penalties, operational disruption, and significant reputational damage.

**Current Market Pain Points:**
*   **Surface-Level Scanning:** Existing tools often perform a simple, one-time scan, failing to capture the dynamic nature of modern websites. They miss critical violations that occur before a user gives consent or after they reject it.
*   **Information Overload:** Reports from traditional scanners are often just long, uncontextualized lists of cookies, leaving it up to the user to figure out the actual risk.
*   **Siloed Solutions:** Businesses are forced to use separate tools for cookie compliance, legal document review, and security scanning. This is inefficient, costly, and provides a fragmented view of their overall risk profile.
*   **Lack of Actionable Insight:** Standard tools can tell you *what* is on your site, but they struggle to explain *why* it's a problem and *how* to fix it in a practical way.

**Cookie Care's Solution:**
Cookie Care was built to address these gaps by providing a single, integrated platform that offers:
*   **Depth:** Our unique three-stage scanning process simulates real user interaction to find violations that other tools miss.
*   **Intelligence:** We leverage the advanced reasoning capabilities of the Google Gemini API to transform raw data into a clear, contextual, and actionable compliance report.
*   **Holistic View:** By combining privacy, legal, and security analysis, we give organizations a complete and unified understanding of their digital compliance posture.

## 3. The How: Architecture & Technology

Cookie Care is architected as a modern, decoupled web application, consisting of a lightweight frontend, a powerful backend, and the Google Gemini API for intelligence.

### Tech Stack

| Component           | Technology                                                                | Purpose                                                                          |
| ------------------- | ------------------------------------------------------------------------- | -------------------------------------------------------------------------------- |
| **Frontend**        | React, TypeScript, Tailwind CSS, Recharts, jspdf, html2canvas             | Renders the user interface, manages state, displays data, and generates PDF reports. |
| **Backend**         | Node.js, Express, TypeScript                                              | Serves the API, orchestrates scans, and communicates with the Gemini API.         |
| **Scanning Engine** | Puppeteer                                                                 | A headless browser library used to automate website interaction and data collection. |
| **AI Engine**       | Google Gemini API (`gemini-2.5-flash` model)                              | Provides the core intelligence for analyzing data and generating insights.       |

### How It Works: A Detailed Flow

#### 1. Cookie Scanner

1.  **User Input:** The user enters a URL into the frontend and initiates a scan.
2.  **API Request:** The frontend sends a POST request to the `/api/scan` endpoint on the backend.
3.  **Puppeteer Initialization:** The backend launches a new, isolated Puppeteer headless browser instance.
4.  **Three-Stage Scan:**
    *   **Stage 1: Pre-Consent:** Puppeteer navigates to the URL, waits for the page to become idle, and then captures all existing cookies and network requests (trackers). It also takes a screenshot of the page, capturing the consent banner.
    *   **Stage 2: Post-Rejection:** The page is reloaded. Puppeteer programmatically finds and clicks a "Reject All" button on the consent banner. After a brief wait, it captures the new set of cookies and trackers that were loaded *after* rejection.
    *   **Stage 3: Post-Acceptance (Final State):** The page is reloaded again. This time, Puppeteer clicks an "Accept All" button and captures the complete set of cookies and trackers loaded under full consent.
5.  **Gemini Analysis:** The raw data from all three stages (lists of cookies and trackers) is compiled and sent to the Gemini API with a highly specific system instruction. This prompt guides Gemini to act as a privacy expert and follow a strict set of rules for categorizing technologies and determining their compliance status based on when they appeared during the scan.
6.  **Structured JSON Response:** Gemini returns a detailed JSON object containing its analysis, including cookie categories, purposes, compliance statuses, and an overall risk assessment for GDPR and CCPA.
7.  **Data Aggregation & Response:** The backend merges Gemini's analysis with the other data collected by Puppeteer (e.g., cookie party, expiry) and sends the final, comprehensive `ScanResultData` object back to the frontend.
8.  **Visualization:** The frontend renders this data into interactive charts, tables, and summary cards for the user.

#### 2. DPA & Vulnerability Scanners

The flow for the other two modules is similar but tailored to their specific tasks:

*   **DPA Reviewer:** The user's DPA text and chosen perspective are sent to the `/api/review-dpa` endpoint. The backend forwards this to Gemini with a system prompt instructing it to act as a legal expert. Gemini analyzes the text and returns a structured JSON object with its clause-by-clause analysis.
*   **Vulnerability Scanner:** The user's URL is sent to the `/api/scan-vulnerability` endpoint. Puppeteer visits the site and extracts the final rendered HTML and the HTTP response headers. This information is sent to Gemini with a system prompt to act as a cybersecurity analyst, looking for passive vulnerabilities. Gemini returns a structured report.

## 4. Competitive Landscape

Cookie Care operates in a crowded market but distinguishes itself through its unique, AI-driven, and holistic approach.

**Key Competitors:**
*   **Termly (`termly.io`)**
*   **Nixon Digital (`nixondigital.io`)**
*   **Cookiebot by Usercentrics**
*   **OneTrust**

### Where Competitors Stand

These tools are generally very good at **Consent Management** and **Cookie Detection**. Their strengths include:
*   Providing customizable cookie banners (Consent Management Platforms - CMPs).
*   Maintaining large, pre-categorized databases of common cookies.
*   Performing scheduled scans to keep cookie lists updated.

However, they have significant limitations:
*   **Static, Database-Driven Analysis:** Their scans often just check cookies against a known database. They lack the contextual understanding to assess *how* and *when* a cookie was deployed, which is crucial for compliance.
*   **Limited Dynamic Testing:** Most do not perform the multi-stage analysis required to detect pre-consent or post-rejection violations accurately. Their reports can provide a false sense of security.
*   **Siloed Focus:** They are hyper-focused on cookie consent and do not offer integrated tools for analyzing legal documents like DPAs or assessing security vulnerabilities.

### Where Cookie Care Excels: Our Competitive Edge

Cookie Care is not trying to be another Consent Management Platform. Instead, it's an **Intelligence and Analysis Platform** that provides insights other tools cannot.

1.  **Superior Detection via Multi-Stage Scanning:** Our core differentiator is the **three-stage scan**. By simulating a real user's journey (initial visit, rejection, acceptance), we uncover critical compliance violations that static scanners completely miss. This provides a far more accurate and realistic assessment of a website's privacy practices.

2.  **Deep, Contextual AI Analysis:** We replace static databases with the reasoning power of the Gemini API. This allows us to move beyond simple identification to provide a true **compliance analysis**. We don't just tell you a cookie exists; we tell you if it's a "Pre-Consent Violation" and explain the associated risk.

3.  **Holistic, 3-in-1 Solution:** Cookie Care is the only tool that seamlessly integrates **Privacy Scanning + Legal Review + Security Analysis**. This saves businesses time and money, and more importantly, it connects the dots between different facets of digital risk, providing a single, coherent picture of their compliance posture.

4.  **Actionable, Not Just Informational:** Every piece of data in a Cookie Care report is designed to be actionable. From remediation plans for vulnerabilities to negotiation tips for DPAs, we empower users to *solve* problems, not just identify them.

**In summary, while competitors offer a tool to manage consent, Cookie Care offers an engine to analyze compliance.** We provide the deep intelligence that businesses need to make informed decisions in a complex regulatory environment.
