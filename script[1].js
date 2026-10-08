/*
  AI JobShield
  Part 1: the local risk-analysis engine (no network needed).
  Part 2: the user interface, including the optional call to the Netlify Function.

  The engine runs in five stages:
    1. Preprocess the text (normalise unicode, strip hidden characters, tidy whitespace)
    2. Detect suspicious patterns with rule-specific regular expressions
    3. Ignore matches that are clearly negated ("we never ask for a fee")
    4. Add up weighted points for each indicator that fired (capped at 100)
    5. Explain every result: what matched, why it matters, what to do
*/
'use strict';

const JobShield = (function () {
  const MAX_CHARS = 8000;
  const MIN_CHARS = 30;

  /* ---------- Shared regex building blocks ---------- */

  // Currency marker: the rupee sign, a dollar sign, or the words Rs / INR / rupees / USD.
  const CUR = '(?:[\\u20B9$]|\\b(?:rs|inr|rupees?|usd)\\b\\.?)';
  // A money amount: "Rs. 500", "$20", "\u20B91,999", "500 rupees".
  const MONEY = '(?:' + CUR + '\\s?\\d|\\d[\\d,]*\\s?(?:rupees?|inr|usd|dollars?)\\b)';
  // Messaging apps that scammers move candidates onto (allows "whats app", "tele gram").
  const PLAT = '(?:whats\\s?app|tele\\s?gram|we\\s?chat|signal)';
  // Verbs that mean "hand something over to us".
  const SHARE = '(?:share|send|provide|give|submit|enter|upload|fill|mention|need|require[sd]?)';

  const FREE_MAIL = [
    'gmail.com', 'googlemail.com', 'yahoo.com', 'yahoo.in', 'yahoo.co.in', 'ymail.com',
    'outlook.com', 'hotmail.com', 'live.com', 'msn.com', 'rediffmail.com', 'aol.com',
    'proton.me', 'protonmail.com', 'icloud.com', 'mail.com', 'gmx.com', 'yandex.com'
  ];
  const RISKY_TLDS = ['xyz', 'top', 'click', 'work', 'icu', 'cfd', 'monster', 'buzz', 'cyou', 'sbs', 'rest', 'vip', 'link', 'biz', 'info'];

  const AFTER_JOINING = /\b(?:after|post|upon|once|during|at\s+the\s+time\s+of)\b[^.\n]{0,30}\b(?:join(?:ing|ed)?|onboarding|offer|document\s+verification)\b/i;
  const RECRUITER_WORDS = /\b(?:hr|human\s+resources?|recruit\w*|career\w*|jobs?|hiring|talent|placement|resume|cv|apply|interview|offer|vacanc\w*|contact|send|email|mail|write)\b/i;

  /* ---------- Stage 1: preprocessing ---------- */

  function preprocess(raw) {
    let t = String(raw == null ? '' : raw);
    t = t.normalize('NFKC');
    t = t.replace(/[\u2018\u2019]/g, "'").replace(/[\u201C\u201D]/g, '"');
    t = t.replace(/[\u200B-\u200D\u2060\uFEFF]/g, '');
    t = t.replace(/\r\n?/g, '\n');
    t = t.replace(/[ \t\u00A0]+/g, ' ').replace(/ ?\n ?/g, '\n').replace(/\n{3,}/g, '\n\n');
    return t.trim();
  }

  /* ---------- Stage 3: negation handling ---------- */

  const NEG_BEFORE = /\b(?:no|not|never|without|zero|neither|nor|don't|dont|doesn't|won't|cannot|can't|isn't|aren't|avoid|beware|nobody)\b/i;
  const NEG_AFTER = /^[^.!?\n]{0,40}\b(?:not\s+(?:required|needed|charged|applicable|asked|collected|accepted)|free(?:\s+of\s+(?:cost|charge))?|waived|nil|never)\b/i;

  function isNegated(text, start, end) {
    let before = text.slice(Math.max(0, start - 60), start);
    const cut = Math.max(before.lastIndexOf('. '), before.lastIndexOf('!'), before.lastIndexOf('?'), before.lastIndexOf('\n'), before.lastIndexOf(';'), before.lastIndexOf(':'));
    if (cut >= 0) before = before.slice(cut + 1);
    before = before.replace(/\b(?:do\s+not|don't|dont)\s+(?:worry|hesitate|miss|delay|wait|ignore)\b/gi, '');
    return NEG_BEFORE.test(before) || NEG_AFTER.test(text.slice(end, end + 50));
  }

  /* ---------- Stage 2: detection helpers ---------- */

  function dedupe(list) {
    list.sort(function (a, b) { return a.start - b.start || b.end - a.end; });
    const out = [];
    let lastEnd = -1;
    for (const item of list) {
      if (item.start >= lastEnd) { out.push(item); lastEnd = item.end; }
    }
    return out;
  }

  function scan(patterns, source) {
    // "Rs." and "INR." would end a sentence-bounded pattern early; blank the dot (same length, same offsets).
    const text = source.replace(/\b(rs|inr)\./gi, '$1 ');
    const out = [];
    for (const p of patterns) {
      const rx = p instanceof RegExp ? p : p.re;
      const always = !(p instanceof RegExp) && !!p.always;
      const g = new RegExp(rx.source, rx.flags.indexOf('g') >= 0 ? rx.flags : rx.flags + 'g');
      let m;
      while ((m = g.exec(text)) !== null) {
        if (m[0].length === 0) { g.lastIndex++; continue; }
        out.push({ start: m.index, end: m.index + m[0].length, always: always });
      }
    }
    return out;
  }

  // Parses "earn Rs. 5000 per day", "$20-30 per hour", "18,000-25,000 per month" ...
  function findUnrealisticSalary(text) {
    const out = [];
    const AMT = '(\\d[\\d,]*(?:\\.\\d+)?)\\s?(k|lakhs?|lacs?|thousand)?';
    const rx = new RegExp('(' + CUR + ')?\\s?' + AMT + '(?:\\s?(?:-|\\u2013|\\u2014|to)\\s?(?:' + CUR + ')?\\s?' + AMT + ')?\\s?(' + CUR + ')?\\s?(?:\\/|per\\s+|a\\s+|every\\s+|each\\s+)\\s?(hour|hr|day|daily|week|weekly|month|monthly)\\b', 'gi');
    const lowEffort = /\b(?:no\s+experience|freshers?|any\s+qualification|no\s+skills?|students?|housewives|work\s+from\s+home|wfh|part[- ]time|simple|easy|mobile)\b|\b\d\s?(?:-\s?\d\s?)?hours?\b/i;
    const hasLowEffort = lowEffort.test(text);
    const mult = function (u) {
      if (!u) return 1;
      u = u.toLowerCase();
      if (u === 'k' || u === 'thousand') return 1e3;
      return 1e5;
    };
    let m;
    while ((m = rx.exec(text)) !== null) {
      const cur = (m[1] || m[6] || '').toLowerCase().replace(/[\s.]/g, '');
      const unit1 = m[3] || m[5] || '';
      const n1 = parseFloat(m[2].replace(/,/g, '')) * mult(unit1);
      const n2 = m[4] ? parseFloat(m[4].replace(/,/g, '')) * mult(m[5] || unit1) : 0;
      const value = Math.max(n1, n2);
      const isUsd = cur === '$' || cur === 'usd';
      const isInr = cur === '\u20B9' || cur === 'rs' || cur === 'inr' || cur === 'rupee' || cur === 'rupees';
      if (!isUsd && !isInr) {
        const ctx = text.slice(Math.max(0, m.index - 30), m.index);
        if (!/\b(?:earn|salary|income|stipend|pay|get|make|package)\b/i.test(ctx)) continue;
      }
      const period = m[7].toLowerCase();
      let limit;
      let needsContext = false;
      if (isUsd) {
        limit = { hour: 100, hr: 100, day: 800, daily: 800, week: 3000, weekly: 3000, month: 8000, monthly: 8000 }[period];
        needsContext = period === 'month' || period === 'monthly';
      } else {
        limit = { hour: 1500, hr: 1500, day: 3000, daily: 3000, week: 20000, weekly: 20000, month: 200000, monthly: 200000 }[period];
        needsContext = period === 'month' || period === 'monthly';
      }
      if (value >= limit && (!needsContext || hasLowEffort)) {
        out.push({ start: m.index, end: m.index + m[0].length });
      }
    }
    return out;
  }

  function findContactRisks(text) {
    const out = [];
    const emailRx = /[a-z0-9._%+-]+@([a-z0-9-]+(?:\.[a-z0-9-]+)+)/gi;
    let m;
    while ((m = emailRx.exec(text)) !== null) {
      const domain = m[1].toLowerCase();
      const start = m.index;
      const end = start + m[0].length;
      const tld = domain.split('.').pop();
      const label = domain.split('.')[0];
      const ctx = text.slice(Math.max(0, start - 80), end + 40);
      if (FREE_MAIL.indexOf(domain) >= 0) {
        if (RECRUITER_WORDS.test(ctx)) {
          out.push({ start: start, end: end, detail: 'The recruiter uses a free email provider (' + domain + ') instead of a company domain.' });
        }
      } else if (RISKY_TLDS.indexOf(tld) >= 0) {
        out.push({ start: start, end: end, detail: 'The domain ends in .' + tld + ', an extension often used for throwaway sites.' });
      } else if (label.indexOf('-') >= 0 && /(career|job|hire|hiring|recruit|hr|talent|vacanc)/.test(domain)) {
        out.push({ start: start, end: end, detail: 'The hyphenated domain looks like an imitation of a real company site.' });
      }
    }
    const urlRx = /\b(?:https?:\/\/|www\.)[^\s<>"')]+/gi;
    while ((m = urlRx.exec(text)) !== null) {
      const url = m[0].replace(/[.,;:!?]+$/, '');
      const host = url.replace(/^https?:\/\//i, '').replace(/^www\./i, '').split(/[\/?#:]/)[0].toLowerCase();
      const tld = host.split('.').pop();
      const label = host.split('.')[0];
      if (RISKY_TLDS.indexOf(tld) >= 0) {
        out.push({ start: m.index, end: m.index + url.length, detail: 'The website ends in .' + tld + ', an extension often used for throwaway sites.' });
      } else if (label.indexOf('-') >= 0 && /(career|job|hire|hiring|recruit|hr|talent|vacanc)/.test(host)) {
        out.push({ start: m.index, end: m.index + url.length, detail: 'The hyphenated website name looks like an imitation of a real company site.' });
      }
    }
    return out;
  }

  function findRemoteTaskScam(text) {
    const out = [];
    const strong = /\b(?:ad(?:s|vertisements?)?\s+posting|link\s+posting|captcha(?:\s+filling)?|product\s+(?:reviews?|ratings?)|rate\s+products?|like\s+(?:and|&)\s+(?:subscribe|share)|(?:youtube|instagram|facebook)\s+(?:likes?|tasks?|videos?)|simple\s+tasks?|online\s+tasks?|task[- ]based|earn\s+(?:money\s+)?(?:from|using|via|on)\s+(?:your\s+)?(?:mobile|phone|home|smartphone)|refer\s+(?:and|&)\s+earn|daily\s+(?:payout|payment|income)|(?:no|zero)\s+investment|part[- ]time\s+(?:job|work)\s+(?:from|at)\s+home)\b/gi;
    const weak = /\b(?:data\s+entry|typing\s+jobs?|copy[- ]?paste|form\s+filling)\b/gi;
    const homeContext = /\b(?:work\s+from\s+home|wfh|from\s+home|online|earn|mobile|part[- ]time)\b/i.test(text);
    let m;
    while ((m = strong.exec(text)) !== null) out.push({ start: m.index, end: m.index + m[0].length });
    if (homeContext) {
      while ((m = weak.exec(text)) !== null) out.push({ start: m.index, end: m.index + m[0].length });
    }
    return dedupe(out);
  }

  function findSelectedWithoutProcess(text) {
    if (/\binterview/i.test(text)) return [];
    if (!/\b(?:whats\s?app|tele\s?gram|fees?|otp|urgent|immediately|hurry|earn)\b/i.test(text)) return [];
    const rx = /\b(?:you\s+(?:have\s+been|are|were)\s+(?:selected|chosen|hired|approved)|congratulations?\b[^.\n]{0,30}\bselected)\b/i;
    const m = rx.exec(text);
    return m ? [{ start: m.index, end: m.index + m[0].length }] : [];
  }

  function findTooGood(text) {
    const out = [];
    const noReq = /\b(?:no|zero|without)\s+(?:prior\s+)?(?:experience|skills?|qualifications?|degree|investment|targets?)\b(?:\s+(?:needed|required|necessary))?/i;
    const bait = /\b(?:earn|daily|per\s+day|weekly\s+payout|lakhs?|bonus|free\s+(?:laptop|mobile|phone|accommodation|food|trip)|work\s+from\s+home|wfh|just\s+\d|only\s+\d+\s+hours?)\b/i;
    const m = noReq.exec(text);
    if (m && bait.test(text)) out.push({ start: m.index, end: m.index + m[0].length });
    return out;
  }

  function findPoorWording(text) {
    const found = [];
    const names = [];
    let m = /\bdear\s+(?:candidate|applicant|job\s*seeker|sir\/madam|sir|madam|student|user|friend|customer)\b/i.exec(text);
    if (m) { found.push({ start: m.index, end: m.index + m[0].length }); names.push('a generic greeting'); }
    const bangs = (text.match(/!/g) || []).length;
    if (bangs >= 3) {
      const run = /!{2,}/.exec(text);
      const at = run ? run.index : text.indexOf('!');
      found.push({ start: at, end: at + (run ? run[0].length : 1) });
      names.push('repeated exclamation marks');
    }
    const letters = text.replace(/[^A-Za-z]/g, '');
    const upper = text.replace(/[^A-Z]/g, '');
    if (letters.length >= 60 && upper.length / letters.length > 0.4) {
      const caps = /\b[A-Z]{3,}(?:\s+[A-Z]{2,}){1,}/.exec(text);
      if (caps) found.push({ start: caps.index, end: caps.index + caps[0].length });
      names.push('text written mostly in capitals');
    }
    const typo = /\b(?:recuirtment|recrutment|vacencies|vaccancy|opertunity|oppurtunity|oppertunity|selction|salery|salry|appoinment|requirment|interveiw|intervew|regestration|registeration|offical|compnay|comapny|experiance|immediatly|payement|paymant)\b/gi;
    const typos = [];
    while ((m = typo.exec(text)) !== null) typos.push({ start: m.index, end: m.index + m[0].length });
    if (typos.length >= 1) { found.push(typos[0]); names.push('spelling mistakes in key recruitment words'); }
    if (names.length < 2) return [];
    found.sort(function (a, b) { return a.start - b.start; });
    const first = found[0];
    return [{ start: first.start, end: first.end, detail: 'Signs found: ' + names.join(', ') + '.' }];
  }

  /* ---------- Rule catalogue ---------- */

  const RULES = [
    {
      id: 'otp_password', title: 'Asks for an OTP or password', weight: 30, negatable: true,
      explanation: 'An OTP, password or PIN gives someone direct access to your accounts or your bank. No genuine hiring process needs either.',
      advice: 'Never share OTPs, passwords or PINs. If you already did, change your passwords and call your bank straight away.',
      patterns: [
        new RegExp('\\b(?:share|send|provide|give|tell|enter|forward|submit|reveal|read\\s+out|reply\\s+with|type)\\b[^.\\n]{0,50}?\\b(?:otp|one[-\\s]?time\\s+(?:password|passcode|code|pin)|verification\\s+code|password|passcode|login\\s+(?:details|credentials|id)|credentials|security\\s+code|upi\\s?pin|atm\\s?pin|pin\\b(?!\\s?code))', 'i'),
        /\botp\b[^.\n]{0,30}\b(?:you\s+(?:receive|get|will\s+get|will\s+receive)|received|sent\s+to|on\s+your)\b/i
      ]
    },
    {
      id: 'bank_card', title: 'Asks for bank or card details', weight: 30, negatable: true,
      explanation: 'Card numbers, CVV, UPI PIN and net-banking details let criminals empty accounts. Employers only need account details for salary, and only after you have joined.',
      advice: 'Do not share card or banking details during hiring. Give salary account details only after you have verified the company and completed joining formalities.',
      excludeNear: AFTER_JOINING,
      patterns: [
        new RegExp('\\b' + SHARE + '\\b[^.\\n]{0,60}?\\b(?:bank\\s+(?:account|details|statement|login)|account\\s+(?:number|details|no\\.?)|a\\/c|ifsc|passbook|net\\s?banking)\\b', 'i'),
        { re: new RegExp('\\b' + SHARE + '\\b[^.\\n]{0,60}?\\b(?:atm|debit|credit)\\s+card\\b', 'i'), always: true },
        { re: /\b(?:cvv|card\s+number|card\s+details|upi\s?pin|atm\s?pin|expiry\s+date|net\s?banking\s+(?:password|id))\b/i, always: true }
      ]
    },
    {
      id: 'payment_request', title: 'Asks you to send money', weight: 25, negatable: true,
      explanation: 'Genuine employers pay you; they do not collect money from candidates. A recruiter asking you to transfer money for any reason is the most common sign of job fraud.',
      advice: 'Do not pay any amount to get, keep or confirm a job. Real employers never charge candidates.',
      patterns: [
        new RegExp('\\b(?:pay|paying|transfer|deposit|remit)\\b[^.\\n]{0,40}?(?:' + MONEY + '|\\b(?:amount|money|fees?|charges?|upi|gpay|google\\s?pay|phonepe|paytm|qr\\s?code)\\b)', 'i'),
        /\b(?:upi|gpay|google\s?pay|phonepe|paytm|qr\s?code|bank\s+transfer)\b[^.\n]{0,40}?\b(?:pay|payment|fees?|transfer|send|amount)\b/i,
        new RegExp('\\bsend\\b[^.\\n]{0,25}?(?:' + MONEY + '|\\b(?:money|amount|fees?|payment)\\b)', 'i'),
        /\b(?:payment|fee|amount)\b[^.\n]{0,25}\b(?:must|need(?:s)?\s+to|has\s+to|should|required\s+to)\b[^.\n]{0,15}\b(?:be\s+)?(?:paid|made|deposited|transferred)\b/i
      ]
    },
    {
      id: 'registration_fee', title: 'Registration, training or processing fee', weight: 25, negatable: true,
      explanation: 'Fees for registration, training, kits, ID cards or "refundable" deposits are a standard scam hook. Legitimate hiring does not depend on the candidate paying.',
      advice: 'Ask for the fee policy in writing and compare it with the company\'s official careers page. Paid courses are a different thing from hiring: make sure the job itself does not depend on payment.',
      patterns: [
        /\b(?:registration|enrol+ment|training|kit|onboarding|verification|processing|security|joining|admission|application|interview|uniform|laptop|software|medical|insurance|refundable|activation|id\s?card|documentation|background\s?check|membership|certification)\s+(?:fees?|charges?|deposit|amount|cost|payment)\b/i,
        /\brefundable\b[^.\n]{0,25}\b(?:fees?|deposit|amount|money)\b/i,
        /\b(?:fees?|deposit|amount)\b[^.\n]{0,25}\brefundable\b/i,
        /\bpay\s+for\s+(?:your\s+)?(?:training|kit|laptop|id\s?card|uniform|software|registration)\b/i
      ]
    },
    {
      id: 'advance_payment', title: 'Payment demanded before joining', weight: 25, negatable: true,
      explanation: 'Asking for payment before you join, interview or receive an offer letter reverses how employment works: the employer pays you after you start.',
      advice: 'Never pay before joining. Ask for a formal offer letter from a verifiable company email address first.',
      patterns: [
        /\badvance\s+(?:payment|amount|fees?|money|deposit)\b/i,
        /\b(?:pay|payment|fees?|deposit|amount)\b[^.\n]{0,40}?\bbefore\b[^.\n]{0,25}?\b(?:join(?:ing)?|offer|interview|training|start(?:ing)?|confirm(?:ation)?|activation|selection|appointment)\b/i,
        /\bupfront\b[^.\n]{0,20}\b(?:payment|fees?|cost|amount|deposit)\b/i,
        /\b(?:payment|fees?|deposit)\b[^.\n]{0,15}\bupfront\b/i,
        /\b(?:pay|deposit|transfer|send)\b[^.\n]{0,60}?\bto\s+(?:confirm|secure|reserve|book|activate|unlock)\b[^.\n]{0,25}?\b(?:seat|slot|position|job|offer|registration|employee|id|appointment|letter|account|training)\b/i,
        /\b(?:pay|payment|fees?)\s+(?:first|in\s+advance)\b/i
      ]
    },
    {
      id: 'unusual_payment', title: 'Unusual payment method', weight: 20, negatable: true,
      explanation: 'Gift cards, cryptocurrency, wire services and cheque-based "reimbursements" are favoured by fraudsters because the transfers are hard to reverse.',
      advice: 'Never buy gift cards, crypto or equipment on an employer\'s behalf, and never deposit a cheque from an unverified employer.',
      patterns: [
        /\b(?:pay|send|transfer|deposit|buy|purchase)\b[^.\n]{0,40}\b(?:gift\s+cards?|itunes\s+card|google\s+play\s+card|bitcoin|btc|usdt|crypto(?:currency)?|ethereum|western\s+union|money\s?gram|wire\s+transfer)\b/i,
        /\b(?:cheque|check)\b[^.\n]{0,60}\b(?:deposit|cash|send\s+back|forward|vendor|purchase|equipment|supplies)\b/i
      ]
    },
    {
      id: 'unrealistic_salary', title: 'Unrealistic pay', weight: 15, negatable: false,
      explanation: 'The pay promised is far above what this kind of work normally earns. Scammers inflate earnings so that you stop being careful.',
      advice: 'Compare the pay with listings for the same role on trusted job sites. If it is far higher for little work, treat it as bait.',
      patterns: [
        /\b(?:earn|make|get|income)\b[^.\n]{0,25}\b(?:lakhs?|lacs?|crores?|millions?)\b/i,
        /\b(?:get\s+rich|financial\s+freedom|earn\s+(?:unlimited|huge|big)|unlimited\s+(?:income|earning))\b/i
      ],
      custom: findUnrealisticSalary
    },
    {
      id: 'guaranteed_job', title: 'Guaranteed job or selection', weight: 15, negatable: true,
      explanation: 'No honest recruiter can guarantee a job before assessing you. "Guaranteed placement" language is used to rush decisions and lower your guard.',
      advice: 'Be sceptical of guarantees. Ask exactly what the selection process is and who conducts it.',
      patterns: [
        /\b(?:100\s?%|guaranteed|guarantee|assured|sure[- ]?shot)\s+(?:job|placement|selection|offer|employment|internship|joining|income|salary|returns?)\b/i,
        /\b(?:job|placement|selection|offer)\s+(?:is\s+)?(?:guaranteed|assured)\b/i,
        /\bguarantee(?:d|s)?\b[^.\n]{0,25}\b(?:job|placement|selected|selection|hired)\b/i
      ]
    },
    {
      id: 'wfh_scam', title: 'Typical work-from-home task scam', weight: 15, negatable: false,
      explanation: 'Easy online tasks such as data entry, liking videos, rating products or posting ads for daily pay are widely used in task scams that begin with small payouts and later ask for deposits.',
      advice: 'Avoid "task" jobs that promise daily payouts for simple work. Check reviews and the company\'s registration before engaging.',
      custom: findRemoteTaskScam
    },
    {
      id: 'fake_interview', title: 'No real interview or selection process', weight: 15, negatable: false,
      explanation: 'Being "selected" without an interview, or being interviewed only through a chat app, suggests there is no genuine hiring process behind the offer.',
      advice: 'Expect a real interview with named interviewers on a known platform, and check that the role exists on the company\'s own careers page.',
      patterns: [
        /\bno\s+interviews?\b/i,
        /\bwithout\s+(?:any\s+)?(?:interviews?|tests?|screening|exams?)\b/i,
        /\bdirect\s+(?:joining|selection|offer|appointment|confirmation)\b/i,
        /\bselected\b[^.\n]{0,40}\b(?:based\s+on|from|through|after\s+(?:reviewing|seeing))\s+(?:your\s+)?(?:resume|cv|profile|naukri|linkedin|indeed)\b/i,
        new RegExp('\\binterviews?\\b[^.\\n]{0,40}\\b(?:on|via|through|over|by|in)\\s+(?:' + PLAT + '|chat|text|messenger|google\\s+chat|skype\\s+chat)\\b', 'i')
      ],
      custom: findSelectedWithoutProcess
    },
    {
      id: 'suspicious_contact', title: 'Suspicious email address or website', weight: 15, negatable: false,
      explanation: 'Recruiters from established companies write from company domains. Free email addresses, unusual domain endings and look-alike names are common in impersonation.',
      advice: 'Compare the sender\'s domain with the company\'s real website. Type the website address yourself instead of using a link from the message.',
      custom: findContactRisks
    },
    {
      id: 'sensitive_docs', title: 'Early request for identity documents', weight: 12, negatable: true,
      explanation: 'Aadhaar, PAN, passport copies and selfies can be used for identity theft or loan fraud. Genuine employers collect them during onboarding, after a verified offer.',
      advice: 'Hold back ID documents until you have verified the employer and hold a written offer. Share masked copies where possible.',
      excludeNear: AFTER_JOINING,
      patterns: [
        /\b(?:share|send|upload|submit|provide|email|forward|whatsapp)\b[^.\n]{0,50}?\b(?:aadhaa?r|pan\s+card|pan\s+number|passport|driving\s+licen[sc]e|voter\s+id|id\s+proof|ssn|social\s+security|selfie|signature|photo\s+id|identity\s+(?:card|proof))\b/i
      ]
    },
    {
      id: 'urgency', title: 'Pressure to act quickly', weight: 10, negatable: false,
      explanation: 'Artificial deadlines and "limited seats" leave you no time to verify the offer, which is exactly what scammers need.',
      advice: 'Take your time. A real offer will still be there after a day of checking.',
      patterns: [
        /\b(?:urgent(?:ly)?|immediate(?:ly)?\s+(?:joining|join|start|openings?|hiring)|join\s+(?:immediately|today|tomorrow|now|asap)|asap|last\s+(?:date|chance|few\s+seats)|limited\s+(?:seats|slots|vacancies|positions|period)|hurry|today\s+only|only\s+\d+\s+(?:seats|slots|vacancies|positions)\s+(?:left|remaining)|offer\s+(?:expires?|valid)\s+(?:in|within|till|until)|within\s+\d+\s+hours?|don't\s+miss|act\s+(?:fast|now)|expires?\s+(?:today|soon))\b/i
      ]
    },
    {
      id: 'suspicious_platform', title: 'Recruitment through WhatsApp or Telegram', weight: 10, negatable: true,
      explanation: 'Companies hire through official email, careers portals and known video platforms. Moving candidates to WhatsApp or Telegram chats avoids traceable channels.',
      advice: 'Ask the recruiter to continue on official company email. Do not join unknown groups or channels.',
      patterns: [
        new RegExp('\\b(?:contact|message|msg|text|chat|dm|reach|call|ping|connect|join|add|write|reply|send)\\b[^.\\n]{0,40}?\\b' + PLAT + '\\b', 'i'),
        new RegExp('\\b' + PLAT + '\\b[^.\\n]{0,40}?\\b(?:group|channel|number|no\\b|id|link|only|hr|recruiter|manager|interview|chat)\\b', 'i'),
        /\b(?:t\.me|wa\.me|telegram\.me|chat\.whatsapp\.com)\/\S*/i,
        new RegExp('\\bonly\\b[^.\\n]{0,15}\\b(?:on|via|through|by)\\b[^.\\n]{0,10}\\b' + PLAT + '\\b', 'i')
      ]
    },
    {
      id: 'shortened_link', title: 'Shortened or disguised link', weight: 10, negatable: false,
      explanation: 'Shortened links hide where they lead, which can be a phishing page that copies a real company site.',
      advice: 'Do not open shortened links. Ask for the full address, or search for the company\'s careers page yourself.',
      patterns: [
        /\b(?:bit\.ly|tinyurl\.com|t\.co|goo\.gl|cutt\.ly|rb\.gy|is\.gd|shorturl\.at|ow\.ly|tiny\.cc|buff\.ly)\/\S+/i
      ]
    },
    {
      id: 'too_good', title: 'Too good to be true', weight: 10, negatable: false,
      explanation: 'Easy money, no skills needed and big perks together are a classic bait combination.',
      advice: 'Ask what the work actually is, who your manager would be and where the company is registered.',
      patterns: [
        /\b(?:easy|quick|fast|instant)\s+(?:money|income|earning|cash)\b/i,
        /\brisk[- ]?free\b/i,
        /\bfree\s+(?:laptop|mobile|smartphone|iphone|bike|car|gift)\b/i,
        /\b(?:anyone|any\s+one)\s+can\s+(?:apply|join|earn)\b/i,
        /\bhigh\s+(?:income|salary|pay|earning|payout)\b[^.\n]{0,30}\b(?:low|less|little|minimal|easy|simple)\b/i
      ],
      custom: findTooGood
    },
    {
      id: 'poor_wording', title: 'Poor or generic wording', weight: 8, negatable: false,
      explanation: 'Generic greetings, spelling mistakes, text in capitals or repeated exclamation marks are common in mass-sent scam messages.',
      advice: 'Look for a named recruiter, a company address and role details you can verify.',
      custom: findPoorWording
    }
  ];

  /* ---------- Stage 2b: apply a rule to the text ---------- */

  function collect(rule, text) {
    let raw = [];
    if (rule.patterns) raw = raw.concat(scan(rule.patterns, text));
    if (rule.custom) raw = raw.concat(rule.custom(text));
    raw = dedupe(raw);
    const hits = [];
    const negated = [];
    for (const m of raw) {
      if (rule.excludeNear && !m.always) {
        const win = text.slice(Math.max(0, m.start - 90), m.end + 90);
        if (rule.excludeNear.test(win)) continue;
      }
      if (rule.negatable && isNegated(text, m.start, m.end)) negated.push(m);
      else hits.push(m);
    }
    return { hits: hits, negated: negated };
  }

  function makeEvidence(text, start, end) {
    const SPAN = 70;
    const from = Math.max(0, start - SPAN);
    const to = Math.min(text.length, end + SPAN);
    let before = text.slice(from, start);
    let after = text.slice(end, to);
    if (from > 0) {
      const sp = before.indexOf(' ');
      before = '\u2026' + (sp >= 0 ? before.slice(sp + 1) : before);
    }
    if (to < text.length) {
      const sp = after.lastIndexOf(' ');
      after = (sp >= 0 ? after.slice(0, sp) : after) + '\u2026';
    }
    const flat = function (s) { return s.replace(/\s*\n\s*/g, ' '); };
    return { start: start, end: end, before: flat(before), match: flat(text.slice(start, end)), after: flat(after) };
  }

  /* ---------- Reassuring signals ---------- */

  function findPositives(text) {
    const out = [];
    if (/\b(?:never|do\s+not|don't|will\s+not|won't|no)\b[^.\n]{0,60}\b(?:ask|charge|require|collect|request|accept)[^.\n]{0,50}\b(?:payment|fees?|money|otp|bank|password|deposit)\b/i.test(text) ||
        /\b(?:free\s+of\s+(?:cost|charge)|no\s+(?:registration\s+)?fees?|zero\s+fees?|without\s+any\s+(?:fee|payment|charges?))\b/i.test(text)) {
      out.push({ id: 'no_fee', title: 'States that no payment is needed', detail: 'The message says candidates are not charged and are not asked for codes or bank details.' });
    }
    const emailRx = /[a-z0-9._%+-]+@([a-z0-9-]+(?:\.[a-z0-9-]+)+)/gi;
    let m;
    let companyMail = null;
    while ((m = emailRx.exec(text)) !== null) {
      const d = m[1].toLowerCase();
      const tld = d.split('.').pop();
      if (FREE_MAIL.indexOf(d) < 0 && RISKY_TLDS.indexOf(tld) < 0 && !(d.split('.')[0].indexOf('-') >= 0 && /(career|job|hire|hiring|recruit|hr|talent)/.test(d))) {
        companyMail = m[0];
        break;
      }
    }
    if (companyMail) {
      out.push({ id: 'company_mail', title: 'Contact uses a company email domain', detail: companyMail + ' is not a free mailbox. Still check that the domain matches the company\'s official website.' });
    }
    const groups = [/\bresponsibilit/i, /\bqualification|eligibility/i, /\bexperience\b/i, /\blocation|office|remote|hybrid\b/i, /\bskills?\s+required|tech(?:nical)?\s+stack|role\s+overview|job\s+description|department|reporting\s+to\b/i];
    if (groups.filter(function (g) { return g.test(text); }).length >= 3) {
      out.push({ id: 'role_detail', title: 'Gives specific role details', detail: 'Responsibilities, requirements or location are described, which is typical of a real opening.' });
    }
    if (/\b(?:careers?\s+(?:page|portal|site|website)|official\s+(?:website|portal|careers)|applied\s+(?:through|via|on))\b/i.test(text)) {
      out.push({ id: 'official_channel', title: 'Refers to an official application channel', detail: 'The message points to a careers portal or an application you made yourself.' });
    }
    if (/\binterview\b/i.test(text) && /(?:\b\d{1,2}[:.]\d{2}\s?(?:am|pm)?\b|\b\d{1,2}(?:st|nd|rd|th)?\s+(?:jan|feb|mar|apr|may|jun|jul|aug|sep|oct|nov|dec)[a-z]*\b|\b(?:mon|tues|wednes|thurs|fri|satur|sun)day\b)/i.test(text)) {
      out.push({ id: 'schedule', title: 'Describes a concrete interview schedule', detail: 'A date or time and a format for the interview are given.' });
    }
    return out;
  }

  /* ---------- Scoring, levels, summary ---------- */

  function levelFor(score) {
    return score >= 75 ? 'CRITICAL' : score >= 50 ? 'HIGH' : score >= 25 ? 'MEDIUM' : 'LOW';
  }

  const SUMMARIES = {
    LOW: 'No strong scam indicators were found. Still confirm the employer through official channels before sharing personal details.',
    MEDIUM: 'Some warning signs were found. Verify this recruiter and company independently before replying or sharing anything.',
    HIGH: 'Several common recruitment-fraud patterns were found. Do not pay money or share personal or banking details.',
    CRITICAL: 'This message matches multiple serious recruitment-fraud patterns and is very likely fraudulent. Do not pay, reply with codes or share any details.'
  };

  function severityFor(weight) {
    return weight >= 25 ? 'high' : weight >= 15 ? 'medium' : 'low';
  }

  function pushUnique(list, item) {
    if (item && list.indexOf(item) < 0) list.push(item);
  }

  function analyze(raw) {
    const text = preprocess(raw);
    const flags = [];
    let rawScore = 0;

    for (const rule of RULES) {
      const r = collect(rule, text);
      if (!r.hits.length) continue;
      const first = r.hits[0];
      rawScore += rule.weight;
      flags.push({
        id: rule.id,
        title: rule.title,
        severity: severityFor(rule.weight),
        weight: rule.weight,
        explanation: rule.explanation + (first.detail ? ' ' + first.detail : ''),
        advice: rule.advice,
        evidence: makeEvidence(text, first.start, first.end),
        ranges: r.hits.map(function (h) { return { start: h.start, end: h.end }; }),
        occurrences: r.hits.length,
        origin: 'local'
      });
    }
    flags.sort(function (a, b) { return b.weight - a.weight || a.evidence.start - b.evidence.start; });

    const positives = findPositives(text);
    const hasStrong = flags.some(function (f) { return f.weight >= 25; });
    const trustCredit = hasStrong ? 0 : Math.min(16, positives.length * 4);
    const score = Math.max(0, Math.min(100, rawScore - trustCredit));
    const level = levelFor(score);

    const recommendations = [];
    flags.slice(0, 5).forEach(function (f) { pushUnique(recommendations, f.advice); });
    if (score >= 50) pushUnique(recommendations, 'Do not reply with money, codes or documents. Stop contact with the sender and block them if the messages continue.');
    if (score >= 25) pushUnique(recommendations, 'Search the company name together with "scam" or "fraud", and look for the same role on the company\'s own careers page.');
    pushUnique(recommendations, 'Verify the employer independently: use the phone number or email shown on the official company website, not the details in this message.');
    if (score >= 50) pushUnique(recommendations, 'If you already paid or shared details, contact your bank immediately and report it (in India: cybercrime.gov.in or helpline 1930).');
    if (score < 25) pushUnique(recommendations, 'Stay safe either way: never pay for a job, and share ID or bank details only after you have verified the company and hold a written offer.');

    return {
      text: text,
      score: score,
      level: level,
      summary: SUMMARIES[level],
      flags: flags,
      positives: positives,
      recommendations: recommendations.slice(0, 8),
      stats: { characters: text.length, words: text ? text.split(/\s+/).length : 0, rawScore: rawScore, trustCredit: trustCredit },
      source: 'local'
    };
  }

  /* ---------- Merge optional AI output with the local result ---------- */

  function mergeWithAI(local, ai) {
    const clamp = function (n) { return Math.max(0, Math.min(100, Math.round(n))); };
    const score = clamp(local.score * 0.6 + ai.score * 0.4);
    const known = local.flags.map(function (f) { return (f.evidence.match || '').toLowerCase(); });
    const knownTitles = local.flags.map(function (f) { return f.title.toLowerCase(); });
    const extra = [];
    (ai.flags || []).forEach(function (f) {
      const ev = String(f.evidence || '').toLowerCase().trim();
      const title = String(f.title || '').toLowerCase().trim();
      if (!title || knownTitles.indexOf(title) >= 0) return;
      if (ev.length >= 8 && known.some(function (k) { return k && (k.indexOf(ev) >= 0 || ev.indexOf(k) >= 0); })) return;
      extra.push({
        id: 'ai_' + extra.length,
        title: String(f.title),
        severity: ['low', 'medium', 'high'].indexOf(f.severity) >= 0 ? f.severity : 'medium',
        weight: 0,
        explanation: String(f.explanation || ''),
        advice: '',
        evidence: f.evidence ? { before: '', match: String(f.evidence), after: '' } : null,
        ranges: [],
        occurrences: 1,
        origin: 'ai'
      });
    });
    const recs = local.recommendations.slice();
    (ai.recommendations || []).forEach(function (r) { pushUnique(recs, String(r)); });
    return Object.assign({}, local, {
      score: score,
      level: levelFor(score),
      summary: ai.summary ? String(ai.summary) : SUMMARIES[levelFor(score)],
      flags: local.flags.concat(extra.slice(0, 4)),
      recommendations: recs.slice(0, 9),
      aiScore: clamp(ai.score),
      localScore: local.score,
      source: 'ai+local'
    });
  }

  return {
    MAX_CHARS: MAX_CHARS,
    MIN_CHARS: MIN_CHARS,
    preprocess: preprocess,
    analyze: analyze,
    mergeWithAI: mergeWithAI,
    levelFor: levelFor
  };
})();

/* ===================================================================
   Sample inputs
   =================================================================== */

const SAMPLES = {
  suspicious: [
    'Dear Candidate!!!',
    '',
    'CONGRATULATIONS! You have been selected for the Work From Home Data Entry job at a leading MNC (no interview required). Earn Rs. 5000 per day working just 2 hours from your mobile. 100% guaranteed job, no experience needed.',
    '',
    'To confirm your seat, pay a refundable registration fee of Rs. 1,999 via UPI today only. Seats are limited and this offer expires within 24 hours. Also share your bank account number, ATM card details and the OTP you receive to activate your employee ID.',
    '',
    'Contact the HR Manager only on WhatsApp: +91 90000 12345 or email hr.globaljobs2026@gmail.com'
  ].join('\n'),
  legit: [
    'Subject: Interview invitation \u2013 Junior Software Engineer (Campus Hiring)',
    '',
    'Hello Priya,',
    '',
    'Thank you for applying for the Junior Software Engineer role through our careers portal. Your profile has been shortlisted for a technical interview, which will be held on 14 October 2026 at 10:30 AM at our Coimbatore office (the address is on our careers page). If you prefer, the interview can be conducted online on Microsoft Teams.',
    '',
    'Role overview: you will work with the platform team on backend services. Qualification: B.E./B.Tech in CS, IT or AI&DS, 2025 or 2026 pass-outs. Responsibilities include writing and reviewing code, fixing defects and documenting your work. Compensation will be discussed as per our standard campus pay band after the final round.',
    '',
    'Please bring a copy of your resume and your college ID. Our hiring process is completely free of cost, and we never ask candidates for any payment, OTP or bank details at any stage. For queries, write to campus.hiring@brightwavetech.com.',
    '',
    'Regards,',
    'Talent Acquisition Team',
    'Brightwave Technologies Pvt. Ltd.'
  ].join('\n'),
  borderline: [
    'Hiring urgently: Customer Support Executive (work from home).',
    '',
    'Salary 18,000 to 25,000 per month plus incentives. Freshers can apply. The interview will be conducted online. Send your resume to hr.brightstaff@gmail.com or message us on WhatsApp at +91 90000 12345. Immediate joining preferred.'
  ].join('\n')
};

const HERO_TEXT = 'Congratulations, you are selected! Pay a refundable registration fee of \u20B91,999 today to confirm your seat. Share the OTP you receive to activate your employee ID. Contact HR on Telegram only.';

/* ===================================================================
   User interface
   =================================================================== */

function initUI() {
  const $ = function (id) { return document.getElementById(id); };
  const form = $('analyzer-form');
  const input = $('offer-text');
  const counter = $('char-count');
  const errorBox = $('form-error');
  const analyzeBtn = $('analyze-btn');
  const analyzeLabel = $('analyze-label');
  const clearBtn = $('clear-btn');
  const analyzerSection = $('analyzer');
  const results = $('results');
  const againBtn = $('again-btn');
  const engineStatus = $('engine-status');
  const engineLabel = $('engine-status-text');
  const srStatus = $('sr-status');
  const CIRC = 377;
  const reduceMotion = window.matchMedia && window.matchMedia('(prefers-reduced-motion: reduce)').matches;
  let busy = false;

  function h(tag, cls, text) {
    const n = document.createElement(tag);
    if (cls) n.className = cls;
    if (text != null) n.textContent = text;
    return n;
  }

  function sleep(ms) {
    return new Promise(function (resolve) { setTimeout(resolve, ms); });
  }

  /* ----- highlighting ----- */

  function highlightInto(container, text, flags) {
    container.textContent = '';
    const ranges = [];
    flags.forEach(function (f) {
      (f.ranges || []).forEach(function (r) { ranges.push({ start: r.start, end: r.end, sev: f.severity, title: f.title }); });
    });
    ranges.sort(function (a, b) { return a.start - b.start || b.end - a.end; });
    const merged = [];
    ranges.forEach(function (r) {
      const last = merged[merged.length - 1];
      if (last && r.start < last.end) {
        if (r.end > last.end) last.end = r.end;
        return;
      }
      merged.push(Object.assign({}, r));
    });
    let pos = 0;
    merged.forEach(function (r) {
      if (r.start > pos) container.appendChild(document.createTextNode(text.slice(pos, r.start)));
      const mark = h('mark', 'hit', text.slice(r.start, r.end));
      mark.dataset.sev = r.sev;
      mark.title = r.title;
      container.appendChild(mark);
      pos = r.end;
    });
    if (pos < text.length) container.appendChild(document.createTextNode(text.slice(pos)));
  }

  /* ----- hero demo (runs the real engine on a short example) ----- */

  function renderHeroDemo() {
    const box = $('demo-message');
    if (!box) return;
    const res = JobShield.analyze(HERO_TEXT);
    highlightInto(box, res.text, res.flags);
    $('demo-score').textContent = res.score + ' / 100';
    const lvl = $('demo-level');
    lvl.textContent = res.level;
    lvl.dataset.level = res.level;
    const list = $('demo-flags');
    list.textContent = '';
    res.flags.slice(0, 4).forEach(function (f) {
      const li = h('li', null, f.title);
      li.dataset.sev = f.severity;
      list.appendChild(li);
    });
  }

  /* ----- counter / errors / busy ----- */

  function updateCounter() {
    const n = input.value.length;
    counter.textContent = n.toLocaleString('en-US') + ' / ' + JobShield.MAX_CHARS.toLocaleString('en-US');
    counter.classList.toggle('near-limit', n >= JobShield.MAX_CHARS - 500);
  }

  function showError(msg) {
    errorBox.textContent = msg;
    errorBox.hidden = false;
    input.setAttribute('aria-invalid', 'true');
  }

  function hideError() {
    errorBox.hidden = true;
    errorBox.textContent = '';
    input.removeAttribute('aria-invalid');
  }

  function setBusy(on) {
    busy = on;
    analyzeBtn.disabled = on;
    clearBtn.disabled = on;
    analyzeBtn.setAttribute('aria-busy', on ? 'true' : 'false');
    analyzeLabel.textContent = on ? 'Analyzing\u2026' : 'Analyze';
  }

  function setEngine(aiActive) {
    engineStatus.dataset.mode = aiActive ? 'ai' : 'local';
    engineLabel.textContent = aiActive ? 'Local engine + AI review active' : 'Local engine ready';
  }

  /* ----- optional AI enhancement ----- */

  async function fetchAI(text) {
    const ctrl = new AbortController();
    const timer = setTimeout(function () { ctrl.abort(); }, 12000);
    try {
      const res = await fetch('/.netlify/functions/analyze', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ text: text }),
        signal: ctrl.signal
      });
      if (!res.ok) return null;
      const data = await res.json();
      if (!data || typeof data.score !== 'number' || !isFinite(data.score)) return null;
      return data;
    } catch (err) {
      return null;
    } finally {
      clearTimeout(timer);
    }
  }

  /* ----- rendering the results ----- */

  function animateScore(target) {
    const num = $('score-number');
    const ring = $('ring-value');
    ring.style.setProperty('stroke-dashoffset', String(CIRC));
    if (reduceMotion) {
      num.textContent = String(target);
      ring.style.setProperty('stroke-dashoffset', String(CIRC * (1 - target / 100)));
      return;
    }
    num.textContent = '0';
    requestAnimationFrame(function () {
      ring.style.setProperty('stroke-dashoffset', String(CIRC * (1 - target / 100)));
    });
    const duration = 900;
    const t0 = performance.now();
    function tick(now) {
      const p = Math.min(1, (now - t0) / duration);
      const eased = 1 - Math.pow(1 - p, 3);
      num.textContent = String(Math.round(target * eased));
      if (p < 1) requestAnimationFrame(tick);
    }
    requestAnimationFrame(tick);
  }

  function renderFlag(f) {
    const card = h('article', 'flag-card');
    card.dataset.sev = f.severity;
    const head = h('div', 'flag-head');
    const sevLabel = { high: 'High severity', medium: 'Medium severity', low: 'Low severity' }[f.severity] || 'Severity';
    head.appendChild(h('span', 'flag-sev', sevLabel));
    if (f.origin === 'ai') head.appendChild(h('span', 'flag-tag', 'Found by AI review'));
    else head.appendChild(h('span', 'flag-points', '+' + f.weight + ' pts'));
    card.appendChild(head);
    card.appendChild(h('h4', 'flag-title', f.title));
    card.appendChild(h('p', 'flag-text', f.explanation));
    if (f.evidence && f.evidence.match) {
      const q = h('blockquote', 'evidence');
      q.appendChild(document.createTextNode(f.evidence.before || ''));
      const hit = h('mark', 'hit', f.evidence.match);
      hit.dataset.sev = f.severity;
      q.appendChild(hit);
      q.appendChild(document.createTextNode(f.evidence.after || ''));
      card.appendChild(q);
    }
    if (f.occurrences > 1) card.appendChild(h('p', 'flag-more', 'Appears ' + f.occurrences + ' times in the message.'));
    return card;
  }

  function renderResults(res) {
    results.dataset.level = res.level;
    $('level-badge').textContent = res.level;
    $('level-badge').setAttribute('aria-label', 'Risk level: ' + res.level);
    $('verdict-summary').textContent = res.summary;

    const n = res.flags.length;
    let meta = n === 0 ? 'No red flags were detected.' : n + (n === 1 ? ' red flag was detected.' : ' red flags were detected.');
    meta += res.source === 'ai+local'
      ? ' Scored by the local engine (' + res.localScore + ') and an AI review (' + res.aiScore + ').'
      : ' Scored by the local analysis engine.';
    $('verdict-meta').textContent = meta;

    animateScore(res.score);

    const flagList = $('flag-list');
    flagList.textContent = '';
    res.flags.forEach(function (f) { flagList.appendChild(renderFlag(f)); });
    $('no-flags').hidden = n !== 0;
    flagList.hidden = n === 0;

    const posWrap = $('positives');
    const posList = $('positive-list');
    posList.textContent = '';
    res.positives.forEach(function (p) {
      const li = h('li');
      li.appendChild(h('strong', null, p.title));
      li.appendChild(h('span', null, p.detail));
      posList.appendChild(li);
    });
    posWrap.hidden = res.positives.length === 0;

    const recoList = $('reco-list');
    recoList.textContent = '';
    res.recommendations.forEach(function (r) { recoList.appendChild(h('li', null, r)); });

    highlightInto($('annotated'), res.text, res.flags);
    $('annotated-wrap').hidden = res.flags.every(function (f) { return !f.ranges || !f.ranges.length; });
    $('annotated-wrap').open = false;

    srStatus.textContent = 'Analysis complete. Risk score ' + res.score + ' out of 100. Risk level ' + res.level + '. ' + n + (n === 1 ? ' red flag.' : ' red flags.');
  }

  function showResults() {
    analyzerSection.hidden = true;
    results.hidden = false;
    results.focus({ preventScroll: true });
    results.scrollIntoView({ behavior: reduceMotion ? 'auto' : 'smooth', block: 'start' });
  }

  function showAnalyzer(clearText) {
    results.hidden = true;
    analyzerSection.hidden = false;
    if (clearText) {
      input.value = '';
      updateCounter();
    }
    hideError();
    analyzerSection.scrollIntoView({ behavior: reduceMotion ? 'auto' : 'smooth', block: 'start' });
    input.focus({ preventScroll: true });
  }

  /* ----- events ----- */

  input.addEventListener('input', function () {
    updateCounter();
    if (!errorBox.hidden) hideError();
  });

  document.querySelectorAll('[data-sample]').forEach(function (btn) {
    btn.addEventListener('click', function () {
      const key = btn.getAttribute('data-sample');
      if (!SAMPLES[key]) return;
      input.value = SAMPLES[key];
      updateCounter();
      hideError();
      input.focus({ preventScroll: true });
      input.setSelectionRange(0, 0);
      input.scrollTop = 0;
    });
  });

  clearBtn.addEventListener('click', function () {
    input.value = '';
    updateCounter();
    hideError();
    input.focus();
  });

  againBtn.addEventListener('click', function () { showAnalyzer(true); });

  form.addEventListener('submit', async function (e) {
    e.preventDefault();
    if (busy) return;
    const cleaned = JobShield.preprocess(input.value);
    if (cleaned.length < JobShield.MIN_CHARS) {
      showError('Paste a few sentences first (at least ' + JobShield.MIN_CHARS + ' characters) so there is something to analyze.');
      input.focus();
      return;
    }
    hideError();
    setBusy(true);
    try {
      const local = JobShield.analyze(input.value);
      const pair = await Promise.all([fetchAI(cleaned), sleep(500)]);
      const ai = pair[0];
      const finalResult = ai ? JobShield.mergeWithAI(local, ai) : local;
      if (ai) setEngine(true);
      renderResults(finalResult);
      showResults();
    } catch (err) {
      console.error(err);
      showError('Something went wrong while analyzing this text. Please try again.');
    } finally {
      setBusy(false);
    }
  });

  updateCounter();
  setEngine(false);
  renderHeroDemo();
}

if (typeof document !== 'undefined') {
  if (document.readyState === 'loading') document.addEventListener('DOMContentLoaded', initUI);
  else initUI();
}

if (typeof module !== 'undefined' && module.exports) {
  module.exports = { JobShield: JobShield, SAMPLES: SAMPLES, HERO_TEXT: HERO_TEXT };
}
