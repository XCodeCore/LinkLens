# LinkLens

### A beginner-friendly way to understand website safety.

LinkLens is an educational, beginner-focused web app that turns a website's publicly visible connection, redirect, URL, and security-header information into a simple **Website Security Signal**.

## Overview

Enter a public website address and LinkLens makes a safe, non-invasive request to inspect information the website already sends to visitors. The result is a plain-language report covering HTTPS, redirect behavior, URL characteristics, and selected security headers.

The signal is a configuration-oriented aid for learning. It is not a trust score or a security certification.

## Why LinkLens exists

Website security concepts can be difficult to interpret, especially for people who are just learning how browsers and websites communicate. LinkLens provides approachable context around a few visible signals while making the boundaries of those signals clear.

## Main features

- Analyze a public HTTP or HTTPS website from a single URL input.
- Follow and assess safe redirects, up to four redirects.
- Check whether the final connection uses HTTPS.
- Highlight URL characteristics such as raw IP addresses, long hostnames, many subdomains, and suspicious hostname characters.
- Check five commonly discussed HTTP security headers.
- Present a 0–100 Website Security Signal with plain-language explanations and suggested next steps.
- Classify results as Stronger Signals, Mixed Signals, or Fewer Signals.
- Show the final URL, response status code, redirect count, and header details.
- Provide friendly error messages for invalid, unavailable, unsafe, or slow-to-respond targets.

## Security headers checked

LinkLens checks whether the public response includes:

| Header | What it helps with |
| --- | --- |
| `Content-Security-Policy` | Restricting which scripts, styles, and other resources a page can load. |
| `Strict-Transport-Security` | Telling browsers to keep using HTTPS for a website. |
| `X-Content-Type-Options` | Preventing unsafe browser MIME-type guessing. |
| `X-Frame-Options` | Controlling whether another site can embed the page in a frame. `CSP frame-ancestors` can provide an alternative framing protection when this header is absent. |
| `Referrer-Policy` | Controlling how much URL information is shared with other sites. |

A missing header is treated as a hardening signal, not an automatic vulnerability. Header presence alone also does not prove that a site is secure.

## How LinkLens works

1. The input is normalized to HTTPS when no scheme is supplied.
2. The server validates that the target is a public HTTP or HTTPS website.
3. LinkLens makes a normal public web request with a nine-second timeout.
4. Redirects are followed manually and checked at each hop, with a maximum of four redirects.
5. The final response is inspected for HTTPS, redirect behavior, URL characteristics, and the five security headers above.
6. A signal is calculated from those observable configuration indicators and shown with explanations.

## Safety protections

The server-side analyzer refuses targets that are not safe public web destinations. It protects against:

- `localhost`, loopback, and private/internal network addresses.
- Link-local, reserved, multicast, unspecified, and other restricted IP ranges.
- IPv4-mapped IPv6 addresses that resolve to restricted IPv4 networks.
- Hostnames resolving to private or internal addresses are rejected before requests, and redirect destinations are validated again before each request.
- Credential-bearing URLs containing a username or password.
- Unsafe or unsupported protocols.
- Unsafe redirects, including redirects into restricted networks.
- Excessive URL length (over 2,048 characters).
- Redirect loops or chains longer than four redirects.
- Requests that exceed the nine-second timeout.

## Important limitations

The Website Security Signal does **not** prove that a website is trustworthy, legitimate, malicious, safe, or vulnerability-free. It is based only on a limited set of public response and URL signals.

LinkLens does not scan for malware and does not perform exploitation, port scanning, brute force, SQL injection testing, or XSS testing. It does not crawl a site, authenticate, submit forms, or attempt to change the target website. A normal HTTPS connection and present security headers are useful signals, but they cannot establish who operates a site or what content it may serve later.

LinkLens resolves and validates destinations before requests to reduce SSRF risk. High-assurance protection against DNS rebinding/TOCTOU scenarios would require pinning the network connection to the validated resolved IP.

## Built with

- Next.js 15.5.26 with the App Router
- React 19.1.0
- Node.js server runtime for the analysis route
- Tailwind CSS 4 with `@tailwindcss/postcss`
- Plain JavaScript and CSS

## Local setup

Requirements: Node.js and npm.

```bash
git clone https://github.com/XCodeCore/LinkLens.git
cd LinkLens
npm install
npm run dev
```

Open [http://localhost:3000](http://localhost:3000) in a browser.

## Production build

Create and run the production build with:

```bash
npm run build
npm start
```

The production server is available at [http://localhost:3000](http://localhost:3000) by default.

## Project structure

```text
LinkLens/
├── app/
│   ├── api/analyze/route.js  # Server-side safe URL analysis endpoint
│   ├── globals.css           # Application layout and visual styles
│   ├── layout.js             # Root layout and metadata
│   └── page.js               # Analyzer UI and report components
├── eslint.config.mjs         # ESLint configuration
├── next.config.mjs           # Next.js configuration
├── package.json              # Scripts and dependencies
├── package-lock.json         # Locked dependency versions
├── postcss.config.mjs        # Tailwind/PostCSS configuration
└── .gitignore
```

## Hackathon context

LinkLens was created for **Beginner's Paradise - FirstCommit**. The project focuses on making a real web-security concept understandable to beginners while keeping the analyzer's behavior intentionally limited, transparent, and non-invasive.

## What I learned

- Public security headers are useful context, but their absence should be explained carefully rather than treated as proof of a vulnerability.
- URL validation must include DNS resolution and network-range checks, not just string validation.
- Redirects need to be inspected hop by hop because a final destination can differ from the original address.
- A beginner-friendly security tool should communicate uncertainty and limitations as prominently as its score.
- Server-side timeouts and bounded redirect handling are important for making public web requests safer and more predictable.

## Future improvements

Potential next steps, while preserving the project's educational and non-invasive scope, include:

- Add automated tests for URL validation, DNS/network protections, redirects, scoring, and header parsing.
- Improve handling and explanation of more complex public security configurations.
- Add a clearer history or export option for reports without collecting unnecessary browsing data.
- Provide more accessible explanations and keyboard/screen-reader refinements.
- Add configurable, well-documented request policies for deployment environments.
