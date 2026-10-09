/* =========================================================
   Phishing Email Analyzer - analysis engine + UI
   Runs 100% in the browser. No data ever leaves this page.
   All example emails and domains below are FICTIONAL.
   ========================================================= */
(function () {
  "use strict";

  /* ---------- Helpers ---------- */
  function unique(arr) {
    return Array.from(new Set(arr));
  }

  // Run a regex over text and return up to N unique matched strings.
  function regexFind(text, regex, max) {
    const out = [];
    const re = new RegExp(regex.source, regex.flags.replace(/g/g, "") + "g");
    let m;
    while ((m = re.exec(text)) !== null && out.length < (max || 4)) {
      const val = m[0].trim();
      if (val && out.indexOf(val) === -1) out.push(val);
    }
    return out;
  }

  // Short human-friendly snippet around a match.
  function snippet(text, match, radius) {
    radius = radius || 60;
    const idx = text.indexOf(match);
    if (idx === -1) return match;
    const start = Math.max(0, idx - 28);
    const end = Math.min(text.length, idx + match.length + radius);
    const pre = start > 0 ? "..." : "";
    const post = end < text.length ? "..." : "";
    return pre + text.slice(start, end).replace(/\s+/g, " ").trim() + post;
  }

  function extractUrls(text) {
    const re = /\bhttps?:\/\/[^\s<>"')\]]+/gi;
    const urls = [];
    let m;
    while ((m = re.exec(text)) !== null) {
      urls.push(m[0].replace(/[.,;:!?]+$/, ""));
    }
    return unique(urls);
  }

  function getHostname(url) {
    try { return new URL(url).hostname.toLowerCase(); }
    catch (e) { return ""; }
  }

  function isIpAddress(host) {
    return /^\d{1,3}(\.\d{1,3}){3}$/.test(host);
  }

  // Well-known brands and their genuine domains, to spot lookalike links.
  const BRANDS = {
    microsoft: ["microsoft.com", "live.com", "outlook.com", "office.com", "office365.com", "onedrive.com", "aka.ms", "azure.com"],
    apple: ["apple.com", "icloud.com"],
    google: ["google.com", "gmail.com", "googlemail.com", "youtube.com"],
    paypal: ["paypal.com"],
    amazon: ["amazon.com", "amazon.co.uk", "amazon.de", "amazon.ca"],
    netflix: ["netflix.com"],
    facebook: ["facebook.com", "fb.com"],
    instagram: ["instagram.com"],
    dhl: ["dhl.com"],
    fedex: ["fedex.com"],
    ups: ["ups.com"],
    usps: ["usps.com"],
    chase: ["chase.com"],
    wellsfargo: ["wellsfargo.com"],
    bankofamerica: ["bankofamerica.com"],
    hsbc: ["hsbc.com", "hsbc.co.uk"],
    barclays: ["barclays.co.uk", "barclays.com"],
    lloyds: ["lloydsbank.com", "lloyds.com"],
    santander: ["santander.co.uk", "santander.com"]
  };

  function brandLookalike(host) {
    if (!host || isIpAddress(host)) return null;
    for (const brand in BRANDS) {
      if (host.indexOf(brand) !== -1) {
        const genuine = BRANDS[brand].some(function (d) {
          return host === d || host.endsWith("." + d);
        });
        if (!genuine) return brand;
      }
    }
    return null;
  }
  /* ---------- Fictional demo emails (no real links/domains) ---------- */
  const DEMO_EMAILS = [
    {
      id: "obvious",
      name: "Obvious phishing",
      tag: "phishing",
      description: "Loud threats, a password request, and a scary deadline.",
      body: `Subject: URGENT: Your email account will be CLOSED in 24 hours!
From: "Mail Security Team" <security@webmail-support.example>

Dear Customer,

This is a final warning. Your email account will be permanently suspended within 24 hours due to unusual sign-in activity.

To avoid losing access to your mailbox, you must verify your password immediately by clicking the link below:

Verify your password now: http://secure-webmail-verify.example/login

If you do not act now, your account and all emails will be permanently deleted.

Regards,
The Mail Security Team`
    },
    {
      id: "sophisticated",
      name: "Sophisticated phishing",
      tag: "sophisticated",
      description: "Subtle social engineering that asks for a verification code.",
      body: `Subject: We need to verify a recent payment
From: "PayPal Security" <service@paypal-account-alert.example>

Hi,

We noticed a new sign-in to your account from a device we don't recognize.

If this was you, no action is needed. If it was NOT you, please secure your account immediately by confirming the one-time verification code we sent to you.

Confirm your identity here: https://paypal-account-alert.example/verify

For your protection, we may limit your account until you verify.

PayPal Security Team`
    },
    {
      id: "microsoft365",
      name: "Fake Microsoft 365 warning",
      tag: "phishing",
      description: "A fake 'mailbox is full' warning demanding your password.",
      body: `Subject: Your Microsoft 365 mailbox is almost full
From: "Microsoft 365 Team" <admin@microsoft365-alerts.example>

Dear Valued Customer,

Your Microsoft 365 mailbox has exceeded its storage quota. To avoid disruption and possible suspension of your account, please update your account information and re-enter your password within 12 hours.

Update account: https://portal-microsoft365-verify.example/login

Failure to comply will result in your account being deactivated.

Microsoft 365 Support`
    },
    {
      id: "parcel",
      name: "Fake parcel delivery",
      tag: "phishing",
      description: "A 'parcel on hold' trick that asks for a gift-card payment.",
      body: `Subject: Your parcel could not be delivered - action required
From: "Delivery Service" <noreply@parcel-tracking.example>

Dear Customer,

We attempted to deliver your parcel but nobody was home. Your parcel is on hold and will be returned within 48 hours unless you confirm your address and pay a small redelivery fee.

Confirm delivery: https://parcel-redelivery.example/confirm

Please pay the $1.99 redelivery fee using a gift card or online payment to release your parcel.

Thank you,
Delivery Team`
    },
    {
      id: "invoice",
      name: "Fake invoice / BEC-style",
      tag: "phishing",
      description: "A fake 'we changed our bank details' email with a macro attachment.",
      body: `Subject: Urgent invoice - payment details updated
From: "Accounts Department" <accounts@vendor-invoices.example>

Dear Accounts Team,

Please note our bank details have changed. Going forward, please send all outstanding invoice payments to the new account below. We have attached the updated invoice for your records.

New bank account:
Account Name: Acme Trading Ltd
Sort Code: 12-34-56
Account Number: 12345678

Please update your records immediately and confirm payment of the attached invoice (Invoice-2024-8842.docm). You may need to enable macros to view the invoice.

Best regards,
The Accounts Team`
    },
    {
      id: "boss-giftcard",
      name: "Gift-card scam from the 'boss'",
      tag: "sophisticated",
      description: "A fake CEO asks you to buy gift cards and send the codes.",
      body: `Subject: Quick request - need your help today
From: "John Smith (CEO)" <ceo@company-mail.example>

Hi,

I'm tied up in meetings all day and can't talk right now, but I need your help urgently.

I need to buy gift cards for a client as a surprise. Please purchase 5 gift cards immediately and send me the codes as soon as possible. I'll reimburse you right away.

Don't call me - I'm in meetings. Just reply to this email when it's done.

Thanks,
John
Sent from my phone`
    },
    {
      id: "tech-support",
      name: "Fake tech support",
      tag: "phishing",
      description: "A fake 'your PC is infected' email with a dangerous .exe attachment.",
      body: `Subject: WARNING: Your computer is infected
From: "Technical Support Team" <support@pc-fix-now.example>

Dear Customer,

Our system has detected that your computer is infected with a serious virus. If you do not remove it immediately, your files will be permanently deleted.

Please download the attached removal tool (Security-Fix.exe) and run it right away. This is a final warning.

The Technical Support Team`
    },
    {
      id: "spoofed-headers",
      name: "Spoofed email (with headers)",
      tag: "sophisticated",
      description: "A bank email whose raw headers show SPF, DKIM and DMARC failures.",
      body: `Return-Path: <bounce@spoofed-sender.example>
Received: from mail.spoofed-sender.example (mail.spoofed-sender.example [203.0.113.5])
From: "Your Bank" <alerts@yourbank.example>
Reply-To: <fraudster@attacker-mail.example>
Subject: Action required: confirm your account
Authentication-Results: mx.example.com; spf=fail smtp.mailfrom=yourbank.example; dkim=fail header.d=yourbank.example; dmarc=fail (p=none sp=none) header.from=yourbank.example

Dear Customer,

We detected unusual activity on your account. To keep it safe, please confirm your account within 24 hours by clicking the link below.

https://yourbank-security.example/confirm

Your Bank Security Team`
    },
    {
      id: "ip-link",
      name: "Raw IP-address link",
      tag: "phishing",
      description: "A link that points straight to an IP address instead of a website name.",
      body: `Subject: Your account needs attention
From: "Account Team" <noreply@secure-login.example>

Dear User,

We need you to log in and verify your account within 24 hours to keep it active.

Log in here: http://192.0.2.10/login

Thank you,
Account Team`
    },
    {
      id: "shortened-link",
      name: "Shortened link",
      tag: "phishing",
      description: "A link hidden behind a URL shortener.",
      body: `Subject: Confirm your identity
From: "Support" <help@webmail.example>

Dear Customer,

Your account has been flagged for a security review. Please confirm your identity within 24 hours to avoid interruption.

Open this link: https://bit.ly/confirm-now-8374

Support Team`
    },
    {
      id: "misleading-link",
      name: "Misleading link text",
      tag: "sophisticated",
      description: "The clickable text shows one address, but the link goes somewhere else.",
      body: `Subject: Important - verify your account
From: "Security" <security@yourbank.example>

Dear Customer,

To keep your account secure, please sign in using the official link below:

[www.yourbank.example](http://203.0.113.9/signin)

Sign in immediately to avoid your account being suspended.

Your Bank Security Team`
    },
    {
      id: "legitimate",

      name: "Legitimate email",
      tag: "legit",
      description: "A normal, harmless message. See how the tool stays calm.",
      body: `Subject: Your monthly account statement is ready
From: "Northbank" <statements@northbank.example>

Hi Alex,

Your monthly statement for your savings account is now available to view in the app. You can sign in to your account through the Northbank app or at northbank.example to view it.

No action is required. If you have any questions, please call us using the number on the back of your card.

Thanks,
The Northbank Team`
    }
  ];
  /* ---------- Detector helpers ---------- */
  function regexDetector(id, title, points, description, regex) {
    return {
      id: id, title: title, points: points, description: description,
      check: function (text) {
        const matches = regexFind(text, regex, 4);
        if (!matches.length) return null;
        return { evidence: matches.join("   |   ") };
      }
    };
  }

  /* ---------- Text-based warning signs (each with a set point value) ---------- */
  const DET_URGENCY = regexDetector(
    "urgency", "Urgency & pressure language", 10,
    "The email tries to rush you into acting quickly without thinking.",
    /\b(urgent(ly)?|immediately|asap|right away|act now|without delay|within \d{1,2} hours?|within \d{1,2} minutes?|limited time|time (is )?running out|final (notice|warning|reminder)|last chance|expires? (today|soon|immediately)|don'?t delay|hurry|before it'?s too late)\b/gi
  );

  const DET_ACCOUNT_THREAT = regexDetector(
    "account-threat", "Threat to suspend or close your account", 20,
    "It threatens to suspend, close, lock, or delete your account to scare you.",
    /\b(suspend(ed|s)?|terminat(e|ed|ion)|deactivat(e|ed|ion)|clos(e|ed)? your account|lock(ed)? your account|disable[d]? your account|your account (will be|has been) (suspended|closed|deactivated|locked|disabled|terminated)|permanently (suspended|closed|deleted|removed)|lose access to your (account|mailbox|messages)|account will be (closed|suspended|deleted|disabled))\b/gi
  );

  const DET_PASSWORD = regexDetector(
    "password", "Asks for your password or login details", 30,
    "It asks you to provide, verify, or enter your password. Real companies never ask for this by email.",
    /\b((verify|confirm|enter|provide|update|re-?enter|validate|submit|type) (your )?(password|passcode|login (details|credentials)|pin|login)|enter your (username and )?password|confirm your password|update your password|re-enter your password)\b/gi
  );

  const DET_MFA = regexDetector(
    "mfa-code", "Asks for a verification / MFA code", 25,
    "It asks for a verification code, one-time code, or 2FA/MFA code. Scammers use these to break into accounts.",
    /\b(verification code|security code|authentication code|one-?time (code|password|passcode|verification code)|otp|2fa( code)?|mfa( code)?|6-?digit code|multi-?factor( authentication)? code|access code|login code)\b/gi
  );

  const DET_PAYMENT = regexDetector(
    "payment-giftcard", "Payment or gift-card request", 25,
    "It asks for money via gift cards, wire transfer, cryptocurrency, or a payment app - a classic scam pattern.",
    /\b(gift cards?|itunes cards?|amazon (gift )?cards?|google play cards?|steam cards?|prepaid cards?|wire transfer|western union|moneygram|crypto(currency)?|bitcoin|\bbtc\b|zelle|venmo|cash ?app|redelivery fee|processing fee|send (a |the )?payment)\b/gi
  );

  const DET_BANK = regexDetector(
    "bank-details", "Asks you to change bank / payment details", 25,
    "It claims bank or payment details have changed and asks you to update where you send money.",
    /\b((update|change|verify|confirm) (your |our )?(bank(ing)?|payment|billing|direct deposit|account) (details|information|info|number)|(new|updated|changed) bank (account|details)|bank details have changed|sort code|account number|routing number|\biban\b|send (the )?(payment|funds|invoice|outstanding) to (the )?(new|updated))\b/gi
  );

  const DET_INVOICE = regexDetector(
    "unexpected-invoice", "Unexpected invoice or payment message", 10,
    "It mentions an invoice, overdue payment, or outstanding balance you weren't expecting.",
    /\b(invoice|overdue|past due|outstanding (balance|payment|invoice|amount)|payment (reminder|request|due|notice)|amount due|late fee|unpaid (invoice|balance|amount)|balance due|attached invoice|invoice payments)\b/gi
  );

  const DET_CREDENTIAL = regexDetector(
    "credential-harvesting", "Tries to get you to sign in or verify", 15,
    "It pushes you to sign in, confirm, or update your account - often through a fake sign-in page.",
    /\b(verify (your )?(account|identity|information|details|address)|confirm (your )?(identity|account|details|address)|update (your )?(account|information|details|profile|security)|re-?activate (your )?(account|mailbox)|secure your account|your mailbox is (full|over|exceeded)|(click|tap) (here|below|the link) to (login|log ?in|sign ?in|verify|confirm|update|unlock|restore|secure)|(sign ?in|log ?in) to (verify|confirm|update|unlock|restore|secure|re-?activate))\b/gi
  );

  const DET_IMPERSONATION = regexDetector(
    "impersonation", "Impersonation language", 10,
    "It uses a generic greeting or pretends to be a 'security team' or official department.",
    /\b(dear (customer|user|member|account holder|valued customer|client|sir\/madam|sir|madam|accounts team|accounts)|valued (customer|member|client)|esteemed (customer|member)|we (have )?noticed (unusual|suspicious) (activity|sign-?in|login)|we noticed a new sign-?in|new sign-?in (to your account)?|unfamiliar device|device we don'?t recogni[sz]e|don'?t recogni[sz]e|sign-?in attempt|from (a |an )?(new|different|unfamiliar) (device|location|browser|country)|your account has been (compromised|accessed|breached)|(from )?the (security|support|help ?desk|billing|accounts|technical) (team|department)|we have detected)\b/gi
  );

  const DET_SHORTENED = regexDetector(
    "shortened-url", "Shortened link", 15,
    "The link is shortened, which hides its real destination.",
    /\b(bit\.ly|tinyurl\.com|goo\.gl|t\.co|ow\.ly|is\.gd|buff\.ly|rebrand\.ly|cutt\.ly|shorturl\.at|tiny\.cc|s\.id|lnkd\.in|rb\.gy|trib\.al|bitly\.com|short\.link)\/\S+/gi
  );
  /* ---------- Custom (logic-based) warning signs ---------- */

  const DET_MACROS = {
    id: "enable-macros",
    title: "Asks you to enable macros or content",
    points: 25,
    description: "It asks you to 'enable macros' or open a macro-enabled document, which can run harmful code.",
    check: function (text) {
      const phrase = /\b(enable (macros|content|editing|activex)|click ?(the )?(enable|edit|content)|turn on macros|run the macro)\b/i;
      const ext = /\.(docm|xlsm|pptm|dotm)\b/gi;
      const evidence = [];
      const p = regexFind(text, phrase, 2);
      const e = regexFind(text, ext, 3);
      if (p.length) evidence.push(p.join(", "));
      if (e.length) evidence.push(e.join(", "));
      if (!evidence.length) return null;
      return { evidence: evidence.join("   |   ") };
    }
  };

  const DET_EXECUTABLE = regexDetector(
    "executable-attachment", "Executable / dangerous attachment", 25,
    "The attachment is a program or script that can run code on your computer.",
    /\.(exe|scr|bat|cmd|com|msi|msp|jar|ps1|psm1|vbs|vbe|js|jse|hta|wsf|lnk|apk|dll|pif)\b/gi
  );

  const DET_UNUSUAL_ATTACHMENT = {
    id: "unusual-attachment",
    title: "Unusual attachment filename",
    points: 10,
    description: "The attachment has a risky or generic name (like an archive or a file named 'invoice.pdf').",
    check: function (text) {
      const archives = regexFind(text, /\.(zip|rar|7z|iso|img|gz|tar|tgz)\b/gi, 3);
      const bases = regexFind(text, /\b(invoice|payment|receipt|scan(ned)?|voicemail|voice_mail|document|attachment|order|refund|statement|contract|unpaid|overdue|settlement|dispatch|parcel|package|delivery|confirmation|important|urgent)[-_ ]?\d*\.(pdf|docx?|xlsx?|html?|htm|txt)\b/gi, 3);
      const doubles = regexFind(text, /\b[\w\-]+\.[a-z0-9]{2,4}\.[a-z0-9]{2,4}\b/gi, 3);
      const found = unique(archives.concat(bases, doubles));
      if (!found.length) return null;
      return { evidence: found.join("   |   ") };
    }
  };

  const DET_SUSPICIOUS_URL = {
    id: "suspicious-url",
    title: "Suspicious or risky web link",
    points: 15,
    description: "A link uses an unusual address, such as 'http' (not secure) or a lookalike brand name.",
    check: function (text) {
      const urls = extractUrls(text);
      const flagged = [];
      urls.forEach(function (u) {
        const host = getHostname(u);
        if (!host || isIpAddress(host)) return; // IP addresses are flagged separately
        const reasons = [];
        if (/^http:\/\//i.test(u)) reasons.push("uses http:// instead of https://");
        if (u.indexOf("@") !== -1) reasons.push("contains an @ sign");
        if (/\.(zip|exe|scr|bat|apk|docm|xlsm|pptm)(\?|$|\/)/i.test(u)) reasons.push("points to a downloadable file");
        const brand = brandLookalike(host);
        if (brand) reasons.push("looks like it's pretending to be " + brand);
        if (reasons.length) flagged.push(u + " (" + reasons.join(", ") + ")");
      });
      if (!flagged.length) return null;
      return { evidence: flagged.slice(0, 3).join("  |  ") };
    }
  };

  const DET_IP_URL = {
    id: "ip-url",
    title: "Link uses a raw IP address",
    points: 25,
    description: "A link points directly to an IP address instead of a normal website name - common in attacks.",
    check: function (text) {
      const found = regexFind(text, /\bhttps?:\/\/\d{1,3}(\.\d{1,3}){3}(:\d{1,5})?(\/|$)/gi, 3);
      if (!found.length) return null;
      return { evidence: found.join("   |   ") };
    }
  };

  const DET_MISLEADING_LINK = {
    id: "misleading-link",
    title: "Link text hides the real destination",
    points: 15,
    description: "The text you would click shows a different address than where the link actually goes.",
    check: function (text) {
      const found = [];
      const labelDomain = /\b[a-z0-9.-]+\.(com|net|org|co|io|gov|edu|uk|example)\b/gi;

      const md = /\[([^\]]+)\]\((https?:\/\/[^)]+)\)/g;
      let m;
      while ((m = md.exec(text)) !== null) {
        const label = m[1].trim();
        const host = getHostname(m[2].trim());
        const domains = label.match(labelDomain);
        if (domains && host) {
          const lb = domains[0].toLowerCase().replace(/^www\./, "");
          if (lb && host !== lb && host.indexOf(lb) === -1) {
            found.push('Shows "' + lb + '" but links to "' + host + '"');
          }
        }
      }

      const html = /<a\s+[^>]*href\s*=\s*["']([^"']+)["'][^>]*>([\s\S]*?)<\/a>/gi;
      while ((m = html.exec(text)) !== null) {
        const label = m[2].replace(/<[^>]+>/g, "").trim();
        const host = getHostname(m[1]);
        const domains = label.match(labelDomain);
        if (domains && host) {
          const lb = domains[0].toLowerCase().replace(/^www\./, "");
          if (lb && host !== lb && host.indexOf(lb) === -1) {
            found.push('Shows "' + lb + '" but links to "' + host + '"');
          }
        }
      }

      if (!found.length) return null;
      return { evidence: unique(found).slice(0, 3).join("  |  ") };
    }
  };
  /* ---------- Email-header helpers ---------- */
  function hasEmailHeaders(text) {
    return /^(from|to|subject|date|return-path|reply-to|received|message-id|mime-version|content-type|dkim-signature|authentication-results|received-spf|delivered-to):\s/im.test(text);
  }

  function headerValue(text, name) {
    const re = new RegExp("^" + name + ":\\s*([^\\r\\n]+)", "im");
    const m = text.match(re);
    return m ? m[1].trim() : null;
  }

  function emailsIn(str) {
    const out = [];
    const re = /[\w.+-]+@[\w-]+\.[\w.-]+/g;
    let m;
    while ((m = re.exec(str)) !== null) out.push(m[0].toLowerCase());
    return unique(out);
  }

  /* ---------- Header-based warning signs (only run if headers are present) ---------- */
  const DET_SENDER_REPLYTO = {
    id: "sender-replyto-mismatch",
    title: "Sender and Reply-To do not match",
    points: 20,
    description: "The 'From' address and 'Reply-To' address are different - a common trick to hide who really gets your reply.",
    headerOnly: true,
    check: function (text) {
      const from = headerValue(text, "From");
      const replyTo = headerValue(text, "Reply-To");
      if (!from || !replyTo) return null;
      const f = emailsIn(from);
      const r = emailsIn(replyTo);
      if (!f.length || !r.length) return null;
      if (f[0] !== r[0]) {
        return { evidence: "From: " + f[0] + "    vs    Reply-To: " + r[0] };
      }
      return null;
    }
  };

  const DET_SPF = {
    id: "spf-fail",
    title: "SPF authentication failed",
    points: 15,
    description: "SPF verifies the sending server. A failed SPF check means the email may be spoofed.",
    headerOnly: true,
    check: function (text) {
      const found = regexFind(text, /\b(spf\s*=\s*(fail|softfail|permerror|temperror)|received-spf\s*:\s*(fail|softfail|permerror|temperror))\b/i, 2);
      if (!found.length) return null;
      return { evidence: found.join("   |   ") };
    }
  };

  const DET_DKIM = {
    id: "dkim-fail",
    title: "DKIM authentication failed",
    points: 15,
    description: "DKIM is a digital signature check. A failed DKIM check means the email's signature could not be verified.",
    headerOnly: true,
    check: function (text) {
      const found = regexFind(text, /\bdkim\s*=\s*(fail|permerror|temperror)\b/i, 2);
      if (!found.length) return null;
      return { evidence: found.join("   |   ") };
    }
  };

  const DET_DMARC_FAIL = {
    id: "dmarc-fail",
    title: "DMARC authentication failed",
    points: 20,
    description: "DMARC ties SPF and DKIM together. A failed DMARC check is a strong sign of spoofing.",
    headerOnly: true,
    check: function (text) {
      const found = regexFind(text, /\bdmarc\s*=\s*(fail|permerror|temperror)\b/i, 2);
      if (!found.length) return null;
      return { evidence: found.join("   |   ") };
    }
  };

  const DET_DMARC_NONE = {
    id: "dmarc-none",
    title: "No DMARC policy enforced",
    points: 10,
    description: "The sender's domain has no DMARC policy (or it's set to 'none'), so spoofed emails are harder to catch.",
    headerOnly: true,
    check: function (text) {
      const found = regexFind(text, /\b(dmarc\s*=\s*none|p\s*=\s*none)\b/i, 2);
      if (!found.length) return null;
      return { evidence: found.join("   |   ") };
    }
  };
  /* ---------- Master list, run in order ---------- */
  const DETECTORS = [
    DET_URGENCY, DET_ACCOUNT_THREAT, DET_PASSWORD, DET_MFA, DET_PAYMENT, DET_BANK,
    DET_INVOICE, DET_CREDENTIAL, DET_IMPERSONATION, DET_SHORTENED, DET_MACROS,
    DET_EXECUTABLE, DET_UNUSUAL_ATTACHMENT, DET_SUSPICIOUS_URL, DET_IP_URL,
    DET_MISLEADING_LINK, DET_SENDER_REPLYTO, DET_SPF, DET_DKIM, DET_DMARC_FAIL, DET_DMARC_NONE
  ];

  function classify(score) {
    if (score <= 34) return { level: "low", label: "Low Risk", color: "#1e6b3a" };
    if (score <= 69) return { level: "suspicious", label: "Suspicious", color: "#1e6b3a" };
    return { level: "high", label: "High Risk", color: "#1e6b3a" };
  }

  function buildRecommendations(hits) {
    const ids = hits.map(function (h) { return h.id; });
    const recs = [
      "Do not click any links or open any attachments in this email.",
      "Do not reply with personal information, passwords, or codes.",
      "Verify the message using the company's official website or app - not the link in the email.",
      "Contact the sender using a phone number you already know and trust."
    ];
    if (ids.indexOf("password") !== -1 || ids.indexOf("mfa-code") !== -1) {
      recs.push("Never share your password or verification code. Legitimate services will never ask for them by email.");
    }
    if (ids.indexOf("payment-giftcard") !== -1) {
      recs.push("Legitimate organizations never ask for payment via gift cards, wire transfer, or cryptocurrency.");
    }
    if (ids.indexOf("bank-details") !== -1) {
      recs.push("If you receive a change-of-bank-details message, phone the company on a known number before changing anything.");
    }
    if (["suspicious-url", "shortened-url", "ip-url", "misleading-link"].some(function (x) { return ids.indexOf(x) !== -1; })) {
      recs.push("Hover over links (without clicking) to preview where they really go.");
    }
    if (["executable-attachment", "enable-macros", "unusual-attachment"].some(function (x) { return ids.indexOf(x) !== -1; })) {
      recs.push("Never open unexpected attachments or enable macros.");
    }
    if (["spf-fail", "dkim-fail", "dmarc-fail", "dmarc-none", "sender-replyto-mismatch"].some(function (x) { return ids.indexOf(x) !== -1; })) {
      recs.push("This email's authentication checks raised flags - treat it as very suspicious and report or delete it.");
    }
    recs.push("If in doubt, delete the email and report it to your IT team or email provider.");
    return recs;
  }

  function analyseEmail(rawText) {
    const text = (rawText || "").replace(/\r\n?/g, "\n");
    const headersFound = hasEmailHeaders(text);

    const hits = [];
    DETECTORS.forEach(function (det) {
      if (det.headerOnly && !headersFound) return; // skip header checks when no headers are pasted
      const result = det.check(text);
      if (result) {
        hits.push({
          id: det.id, title: det.title, points: det.points,
          description: det.description, evidence: result.evidence
        });
      }
    });

    let score = hits.reduce(function (sum, h) { return sum + h.points; }, 0);
    if (score > 100) score = 100;
    if (score < 0) score = 0;

    return {
      score: score,
      classification: classify(score),
      hits: hits,
      recommendations: buildRecommendations(hits),
      headersFound: headersFound
    };
  }
  /* ---------- Rendering ---------- */
  function escapeHtml(s) {
    return String(s).replace(/[&<>"']/g, function (c) {
      return { "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c];
    });
  }

  function gaugeSvg(score, color) {
    const r = 62;
    const c = 2 * Math.PI * r;
    const offset = c * (1 - score / 100);
    return '<svg width="150" height="150" viewBox="0 0 150 150" aria-hidden="true">'
      + '<circle class="track" cx="75" cy="75" r="' + r + '"></circle>'
      + '<circle class="fill" cx="75" cy="75" r="' + r + '" stroke="' + color + '"'
      + ' stroke-dasharray="' + c.toFixed(2) + '" stroke-dashoffset="' + offset.toFixed(2) + '"></circle>'
      + '</svg>';
  }

  function renderResults(result) {
    const panel = document.getElementById("results-panel");
    const cls = result.classification;

    let summary;
    if (cls.level === "low") summary = "Only a few (or no) warning signs were found. It still pays to double-check unexpected messages.";
    else if (cls.level === "suspicious") summary = "Several warning signs were found. Treat this message with caution and verify it another way.";
    else summary = "Many strong warning signs were found. Do not click links or open attachments - verify through official channels.";

    let indicatorsHtml;
    if (result.hits.length) {
      indicatorsHtml = result.hits.map(function (h) {
        return '<div class="indicator">'
          + '<span class="pts">+' + h.points + '</span>'
          + '<div>'
          + '<p class="ind-title">' + h.title + '</p>'
          + '<p class="ind-desc">' + h.description + '</p>'
          + '<p class="ind-evidence">' + escapeHtml(h.evidence) + '</p>'
          + '</div></div>';
      }).join("");
    } else {
      indicatorsHtml = '<p class="no-indicators">No warning signs were found in this email.</p>';
    }

    const headersNote = result.headersFound ? "" :
      '<p class="headers-note">No email headers were detected, so the sender/Reply-To and SPF/DKIM/DMARC checks were skipped. Paste the full "raw" email (including headers) to include those checks.</p>';

    const recs = '<ul class="recommendations">'
      + result.recommendations.map(function (r) { return "<li>" + r + "</li>"; }).join("")
      + "</ul>";

    panel.innerHTML =
      '<div class="results-card">'
      + '<div class="result-head">'
      +   '<div class="gauge">'
      +     gaugeSvg(result.score, cls.color)
      +     '<span class="gauge-num" style="color:' + cls.color + '">' + result.score + '</span>'
      +     '<span class="gauge-label">risk score</span>'
      +   '</div>'
      +   '<div class="result-meta">'
      +     '<span class="classification ' + cls.level + '">' + cls.label + '</span>'
      +     '<p class="result-summary">' + summary + '</p>'
      +   '</div>'
      + '</div>'
      + '<div class="result-section"><h3>Warning Signs Found (' + result.hits.length + ')</h3>' + indicatorsHtml + '</div>'
      + headersNote
      + '<div class="result-section"><h3>Recommended Actions</h3>' + recs + '</div>'
      + '<div class="disclaimer-box"><strong>Note:</strong> this is an educational tool, not a final verdict. It highlights warning signs but cannot guarantee whether an email is safe or malicious.</div>'
      + '</div>';

    const numEl = panel.querySelector('.gauge-num');
    if (numEl && !window.matchMedia('(prefers-reduced-motion: reduce)').matches) {
      const target = result.score;
      const dur = 700;
      const t0 = performance.now();
      function tick(now) {
        const p = Math.min(1, (now - t0) / dur);
        const eased = 1 - Math.pow(1 - p, 3);
        numEl.textContent = Math.round(target * eased);
        if (p < 1) requestAnimationFrame(tick);
      }
      requestAnimationFrame(tick);
    }

    panel.hidden = false;
    document.getElementById("empty-state").hidden = true;
  }
  function runAnalysis() {
    const input = document.getElementById("email-input");
    const panel = document.getElementById("results-panel");
    const text = input.value;
    if (!text.trim()) {
      panel.innerHTML = '<div class="results-card"><p style="font-weight:600;margin:0">Please paste some email text first, then click "Analyze Email".</p></div>';
      panel.hidden = false;
      document.getElementById("empty-state").hidden = true;
      input.focus();
      return;
    }
    renderResults(analyseEmail(text));
  }

  function loadAndAnalyse(body) {
    document.getElementById("email-input").value = body;
    runAnalysis();
    document.getElementById("analyser").scrollIntoView({ behavior: "smooth", block: "start" });
  }

  function populateSelect() {
    const sel = document.getElementById("example-select");
    DEMO_EMAILS.forEach(function (ex) {
      const opt = document.createElement("option");
      opt.value = ex.id;
      opt.textContent = ex.name;
      sel.appendChild(opt);
    });
  }

  /* ---------- Wire up the page ---------- */
  document.getElementById("analyse-btn").addEventListener("click", runAnalysis);

  document.getElementById("clear-btn").addEventListener("click", function () {
    const input = document.getElementById("email-input");
    input.value = "";
    const panel = document.getElementById("results-panel");
    panel.hidden = true;
    panel.innerHTML = "";
    document.getElementById("empty-state").hidden = false;
    input.focus();
  });

  document.getElementById("email-input").addEventListener("keydown", function (e) {
    if ((e.ctrlKey || e.metaKey) && e.key === "Enter") {
      e.preventDefault();
      runAnalysis();
    }
  });

  document.getElementById("example-select").addEventListener("change", function () {
    const id = this.value;
    if (!id) return;
    const ex = DEMO_EMAILS.find(function (e) { return e.id === id; });
    if (ex) loadAndAnalyse(ex.body);
    this.value = "";
  });

  /* ---------- Motion: reveal on scroll, header state, progress bar ---------- */
  function initScrollEffects() {
    const header = document.querySelector('.site-header');
    const progress = document.getElementById('scroll-progress');
    function update() {
      const y = window.scrollY || window.pageYOffset;
      if (header) header.classList.toggle('scrolled', y > 24);
      if (progress) {
        const doc = document.documentElement;
        const max = doc.scrollHeight - window.innerHeight;
        progress.style.width = (max > 0 ? (y / max) * 100 : 0) + '%';
      }
    }
    window.addEventListener('scroll', update, { passive: true });
    update();
  }

  function renderScoringTable() {
    const tbody = document.getElementById('scoring-tbody');
    if (!tbody) return;
    tbody.innerHTML = DETECTORS.map(function (d) {
      const note = d.headerOnly ? ' <span class="table-note">(needs headers)</span>' : '';
      return '<tr><td>' + d.title + note + '</td><td class="pts-col">+' + d.points + '</td></tr>';
    }).join('');
  }

  function initScrollSpy() {
    const links = Array.prototype.slice.call(document.querySelectorAll('.site-nav a'));
    const sections = Array.prototype.slice.call(document.querySelectorAll('section[id]'));
    if (!links.length || !sections.length) return;
    function update() {
      const pos = window.scrollY + 90;
      let currentId = '';
      sections.forEach(function (sec) {
        const top = sec.getBoundingClientRect().top + window.scrollY;
        if (top <= pos) currentId = sec.id;
      });
      links.forEach(function (link) {
        const href = link.getAttribute('href');
        link.classList.toggle('active', href === '#' + currentId);
      });
    }
    window.addEventListener('scroll', update, { passive: true });
    update();
  }

  function initMotion() {
    initScrollEffects();
    initScrollSpy();
    renderScoringTable();
  }

  populateSelect();
  initMotion();
})();







