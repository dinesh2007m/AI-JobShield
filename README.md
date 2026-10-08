# AI JobShield

**AI-powered recruitment fraud risk assessment** · Cybersecurity Track

Paste a job offer, recruiter message or email. AI JobShield returns a 0 to 100 risk score, a risk level (LOW / MEDIUM / HIGH / CRITICAL), the red flags it found with the exact phrases, a short explanation for each, and safety recommendations.

> This tool provides a risk assessment and should not replace independent verification.

---

## Problem statement

Students and job seekers are a constant target of fake job and internship offers. The messages ask for "registration fees", one-time passwords or bank details, promise guaranteed jobs with unrealistic pay, and push candidates onto WhatsApp or Telegram. Victims often notice the pattern only after paying or sharing personal data, and most have no quick way to get a second opinion.

## Solution

AI JobShield is a small web app that reads the text of an offer and explains, in plain language, which parts match known recruitment-fraud patterns and what to do about them. It works with no setup and no account, and every result shows its reasoning.

## Features

- Risk score (0 to 100), risk level badge and an animated score ring
- 17 fraud indicators, each with a fixed weight, a plain-language explanation and a quoted piece of evidence from the message
- Negation handling: "We never ask for a registration fee" is not flagged as a fee request
- Reassuring signs (no-fee statement, company email domain, concrete interview schedule, and so on) that reduce the score when no serious indicator is present, so genuine offers are not marked as scams
- Your message re-displayed with every flagged phrase highlighted
- Three built-in examples: suspicious, borderline and legitimate
- Optional AI review through a Netlify Function; the app works fully without it
- Responsive, keyboard accessible, respects reduced-motion settings
- Strict Content-Security-Policy and security headers configured in `netlify.toml`

## How it works

1. **Preprocess**: normalise unicode, remove zero-width characters, tidy whitespace.
2. **Detect**: rule-specific regular expressions look for suspicious wording. A few rules use small custom logic, such as parsing "earn Rs. 5000 per day" against pay thresholds, or checking whether a recruiter's email is on a free provider.
3. **Filter**: matches that are clearly negated ("never", "no", "do not") or that refer to normal onboarding ("bank details after joining") are ignored.
4. **Score**: each indicator that fires adds its weight once. The total is capped at 100.
5. **Explain**: every flag carries the matched phrase, why it matters and what to do.

| Indicator | Points |
|---|---|
| Asks for OTP or password | +30 |
| Asks for bank or card details | +30 |
| Asks you to send money | +25 |
| Registration, training or processing fee | +25 |
| Payment demanded before joining | +25 |
| Unusual payment method (gift cards, crypto, cheque schemes) | +20 |
| Unrealistic pay | +15 |
| Guaranteed job or selection | +15 |
| Typical work-from-home task scam | +15 |
| No real interview or selection process | +15 |
| Suspicious email address or website | +15 |
| Early request for identity documents | +12 |
| Pressure to act quickly | +10 |
| Recruitment through WhatsApp or Telegram | +10 |
| Shortened or disguised link | +10 |
| Too good to be true | +10 |
| Poor or generic wording | +8 |

Levels: **LOW** 0 to 24, **MEDIUM** 25 to 49, **HIGH** 50 to 74, **CRITICAL** 75 to 100.

Reassuring signs subtract up to 16 points, but only when no indicator worth 25 points or more fired, so a scammer cannot talk the score down by adding "no fees" to an offer that also asks for payment.

## AI approach

This is a hybrid design:

- **Local engine (always on)**: deterministic, explainable, works offline, never sends your text anywhere.
- **Optional AI review (Netlify Function)**: if `OPENAI_API_KEY` is set, the front end also calls `/.netlify/functions/analyze`. The function sends the text to the OpenAI Chat Completions API with instructions to treat the text strictly as data (a defence against prompt injection from the scam message itself), requests JSON output, and sanitises the reply before returning it.
- **Merging**: the final score is 60% local engine and 40% AI score. AI findings that the local engine did not already catch appear as extra cards labelled "Found by AI review". If the function is missing, unconfigured, slow or returns an error, the app silently uses the local result.

The API key lives only in the Netlify environment. It never appears in `index.html` or `script.js`.

## Tech stack

HTML, CSS and vanilla JavaScript on the front end. One Netlify Function (Node.js, no dependencies). IBM Plex fonts from Google Fonts, with system-font fallbacks. No framework, no build step, no database.

## Folder structure

```
AI-JobShield/
├── index.html                    Page structure: home, analyzer, results, footer
├── style.css                     All styling
├── script.js                     Analysis engine + user interface
├── README.md
├── netlify.toml                  Publish directory, functions directory, security headers
└── netlify/
    └── functions/
        └── analyze.js            Optional AI review (reads OPENAI_API_KEY)
```

## Local testing

**Static only (local engine):** any static server works.

```bash
cd AI-JobShield
python3 -m http.server 8000
# open http://localhost:8000
```

**With the AI function:** use the Netlify CLI, which serves the site and the function together.

```bash
cd AI-JobShield
export OPENAI_API_KEY="your-key"        # optional
export OPENAI_MODEL="gpt-4o-mini"       # optional
npx netlify-cli dev
# open the URL it prints (usually http://localhost:8888)
```

Without the key, the function answers `501` and the app uses the local engine.

## Netlify deployment

1. Put the `AI-JobShield` folder in a Git repository (GitHub, GitLab or Bitbucket) and push it. Do not commit any API key.
2. In Netlify choose **Add new site → Import an existing project** and select the repository.
3. Leave the build command empty. Publish directory is `.` and functions directory is `netlify/functions`; both are already set in `netlify.toml`.
4. Click **Deploy**. The static site works immediately.
5. Optional: add the environment variables below, then **trigger a redeploy** so the function picks them up.

Alternative: `npx netlify-cli deploy --prod` from inside the folder deploys the site and the function. A plain drag-and-drop of the folder publishes the static site; if the function is not deployed that way, the app simply runs on the local engine.

### Environment variables

Site configuration → Environment variables:

| Variable | Required | Purpose |
|---|---|---|
| `OPENAI_API_KEY` | No | Enables the AI review. Without it the app uses the local engine only. |
| `OPENAI_MODEL` | No | Chat model to use. Defaults to `gpt-4o-mini`. If your account does not have that model, set this to any chat model you can use. |

## Demo instructions (2 to 4 minutes)

1. **Home (30 s):** read the headline. Point at the example message: it is scanned live by the real engine, with the flagged phrases highlighted.
2. **Suspicious offer (60 s):** open the analyzer, click *Suspicious offer*, click *Analyze*. Show the CRITICAL score, then two or three flag cards with their quoted phrases and points. Open the highlighted message.
3. **Legitimate offer (45 s):** click *Analyze Another Offer*, load *Legitimate offer*, analyze. It scores LOW with no flags and shows the reassuring signs. Make the point that the tool does not call everything a scam, and that the sentence "we never ask for any payment, OTP or bank details" is not penalised.
4. **Borderline offer (30 s):** load *Borderline offer*. It scores MEDIUM because of the free email address, urgency and WhatsApp contact, with no payment request.
5. **Close (30 s):** mention the optional AI review, that the key stays on the server, that the app falls back to the local engine, and read the disclaimer.

## Limitations

- Detection is pattern-based. New wording, other languages and heavily obfuscated text can slip past it, and unusual but honest wording can be over-flagged. It is a risk assessment, not a verdict.
- English text is the focus. Indian-context signals (rupee amounts, UPI, Aadhaar, PAN) are included; other regions' conventions are only partly covered.
- The tool cannot check whether a company, domain or phone number really exists.
- Pay thresholds are rough heuristics, not market data.
- The optional AI review depends on a third-party provider, inherits that model's mistakes, and sends the text to the provider when enabled. The function has no rate limiting, so protect a public deployment's API quota (for example with spending limits in your OpenAI account).
- The score weights are hand-tuned and have not been validated on a labelled dataset, so no accuracy figure is claimed.

## Future improvements

- Tune and evaluate the weights on a labelled dataset of real and fake offers
- Hindi, Tamil and other regional-language support
- Domain-age and WHOIS lookups, and checks against a company's official careers page
- Browser extension to scan messages in Gmail and LinkedIn
- A reporting flow that pre-fills cybercrime complaint details
- Rate limiting and caching for the function
- Automated tests for the rule set

## License

Released for hackathon and educational use.
