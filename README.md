    # Cookie Security Inspector — Offline Web Application Security Tool

    [![License: MIT](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)
    [![Python 3.12+](https://img.shields.io/badge/python-3.12+-blue.svg)](https://www.python.org/downloads/)
    [![Offline](https://img.shields.io/badge/mode-offline%20first-important.svg)](#)
    [![secintel](https://img.shields.io/badge/schema-secintel%20v1-purple.svg)](https://github.com/reshot2005/secintel-core)
    [![GitHub](https://img.shields.io/badge/github-reshot2005%2Fcookie-security-inspector-black.svg)](https://github.com/reshot2005/cookie-security-inspector)

    > **Parse Set-Cookie flags — detect missing Secure, HttpOnly, SameSite and cookie security misconfigurations for AppSec reviews.**

    **Category:** Web Application Security  
    **Collection phase tool:** 4/15  
    **Schema:** [secintel-core](https://github.com/reshot2005/secintel-core) v1  
    **Repository:** https://github.com/reshot2005/cookie-security-inspector  
    **Author account:** [reshot2005](https://github.com/reshot2005)

    ## Why Cookie Security Inspector ranks for security search

    Cookie Security Inspector is an **offline-first**, research-grade **web application security** utility designed for practitioners who need reproducible analysis without uploading sensitive artifacts to SaaS scanners. It emits structured findings through the shared **secintel** evidence taxonomy (OBSERVED / DERIVED / INFERRED / CORRELATED / VERIFIED) so results are auditable, exportable, and CI-friendly.

    ### Primary SEO keywords
    `cookie security, HttpOnly, SameSite, Secure cookie, session cookie audit`

    ### Topics
    `web-security` `appsec` `owasp` `cybersecurity` `pentesting` `bug-bounty` `http-security` `security-tools` `python` `offline-security` `cookies` `session-security`

    ## What problem does this solve?

    Inspect Set-Cookie attributes and flag insecure cookie configurations that enable session theft or CSRF risk.

    Dedicated cookie inspector with structured findings.

    ## Key features

    - Set-Cookie parsing
- Secure/HttpOnly/SameSite checks
- Session cookie risk flags
- Clear remediation guidance
- Offline HAR/header inputs

    ## Ideal use cases

    - Audit auth cookies
- Fix session fixation risks
- AppSec cookie reviews

    ## Who should use this

    - Security engineers & AppSec / NetSec specialists
    - SOC / DFIR / malware analysts (as applicable)
    - Bug bounty hunters and penetration testers
    - DevSecOps teams needing offline/air-gapped tooling
    - Students and researchers learning web application security

    ## Quick start

    ```bash
    git clone https://github.com/reshot2005/cookie-security-inspector.git
    cd cookie-security-inspector
    python3.12 -m venv .venv
    source .venv/bin/activate  # Windows: .venv\Scripts\Activate.ps1
    pip install -e ../secintel-core  # or: pip install -e git+https://github.com/reshot2005/secintel-core.git#egg=secintel-core
    pip install -e ".[dev]"

    cookie-security-inspector analyze sample_data --json
    cookie-security-inspector analyze sample_data --html report.html
    cookie-security-inspector version
    ```

    ### Exports for interoperability

    ```bash
    cookie-security-inspector analyze sample_data \
      --json --html report.html --csv findings.csv --sarif results.sarif
    ```

    ## Evidence quality & reproducibility

    - Findings follow **secintel** classification rules (confidence only where schema allows).
    - Provenance includes tool version, config hash, and input integrity metadata.
    - Set `SECINTEL_SOURCE_DATE_EPOCH` for deterministic timestamps in CI.

    ```bash
    export SECINTEL_SOURCE_DATE_EPOCH=1704067200
    cookie-security-inspector analyze sample_data --json
    ```

    ## Development

    ```bash
    ruff check src tests
    mypy src
    pytest
    ```

    ## Related tools in this collection

    Browse more offline security research tools by [reshot2005](https://github.com/reshot2005?tab=repositories): network security, web AppSec, DevSecOps, digital forensics, and static malware analysis — each in its own public repository with the same secintel reporting contract.

    ## License

    MIT — free for research, education, and commercial use with attribution preserved.

    ---

    ### Discoverability blurb (search engines & GitHub)

    **Cookie Security Inspector (cookie-security-inspector)** — Parse Set-Cookie flags — detect missing Secure, HttpOnly, SameSite and cookie security misconfigurations for AppSec reviews. Search terms: cookie security, HttpOnly, SameSite, Secure cookie, session cookie audit. Open-source, MIT-licensed, Python 3.12, offline cybersecurity tool by reshot2005.
