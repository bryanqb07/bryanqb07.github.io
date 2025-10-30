---
layout: post
title: "Elabftw CVE-2025-62793"
category: cve
tags: [elabftw, cve-2025-62793, security]
cvss_score: 6.8
cvss_vector: "CVSS:3.1/AV:N/AC:L/PR:L/UI:R/S:C/C:H/I:N/A:N"
---

## HTML Injection / Stored XSS via Malicious SVG Upload
{% if page.cvss_score %}
  {% include cvss.html score=page.cvss_score vector=page.cvss_vector %}
{% endif %}

[Elabftw](https://github.com/elabftw/elabftw) is an open source software that I keep track of, having published a [SQL Injection CVE](https://bryanlynch.dev/posts/elabftw_sqli.html) about six months ago.

About a month ago, I decided to go back and give the code another audit. One thing that immediately jumped out at me was an allowed MIME type for image downloads that had the word `xml` in it.

```php
// force the download of everything (regardless of the forceDownload parameter)
// to avoid having html injected and interpreted as an elabftw page
$safeMimeTypes = array(
    'application/pdf',
    'image/gif',
    'image/jpeg',
    'image/png',
    'video/mp4',
    'image/svg+xml',
    'text/plain',
);
```

I tested it out and sure enough, it was vulnerable to multiple injection attacks. The lesson here: never trust anything with the word `xml` in it, especially not images.

Since this is a newly published CVE, I won't post the PoC for now, but I will include a link to the security advisory [here](https://github.com/elabftw/elabftw/security/advisories/GHSA-rq98-8jh9-684f).
