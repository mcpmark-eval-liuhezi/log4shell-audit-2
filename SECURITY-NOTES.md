# Log4Shell Security Notes (CVE-2021-44228)

## The vulnerability

**Log4Shell** is a remote code execution (RCE) flaw in **Apache Log4j 2**, one of the most widely used Java logging libraries. An attacker who can get application-generated log messages (or log message parameters) to contain attacker-controlled input — for example a crafted username, an exception trace, or an untrusted HTTP request header — can trigger Log4j's JNDI lookups, which by default are enabled on vulnerable versions. The attacker can then load malicious Java classes from attacker-controlled LDAP/remote JNDI endpoints, achieving remote code execution on the affected application.

The flaw is specific to **`org.apache.logging.log4j:log4j-core`**; the `log4j-api` and other Log4j-related libraries are not directly affected, but `log4j-core` must be upgraded to match `log4j-api` for compatibility.

## CVE

- **CVE ID:** CVE-2021-44228
- **Bugtraq / CVE database:** https://nvd.nist.gov/vuln/detail/CVE-2021-44228
- **Published:** December 10, 2021

## Severity

- **CVSS 3.1 base score: 10.0 — CRITICAL**
  - Vector: `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H`
  - Attack vector: network; attack complexity: low; privileges required: none; user interaction: none; scope changed; high impact on confidentiality, integrity, and availability.
- **Affected product (per CISA):** `org.apache.logging.log4j:log4j-core`, from **2.0-beta9** through **2.15.0**, excluding the known-to-be-safe backport releases **2.12.2**, **2.12.3**, and **2.3.1**.
  - Per the GitHub Advisory Database: `>= 2.0-beta9 < 2.3.1`, `>= 2.4 < 2.12.2`, `>= 2.13.0 < 2.15.0`.
- **Related follow-on:** CVE-2021-45046 (log4j 2.15.0 did not fully close JNDI lookups); the full remediation was in **2.16.0**.

## Affected vs. fixed versions

| Category | Log4j version |
|---|---|
| **Affected range (2.x release line)** | **2.0-beta9 — 2.15.0**, excluding the patched backports |
| **Patched backports** | **2.3.1, 2.12.2, 2.12.3** (each fixes this specific issue) |
| **Permanently fixed version** | **2.16.0** (disables JNDI by default and completely removes message-lookup support) |
| **Recommended for Java 8+ environments (per CISA)** | **2.17.0** (latest release at time of CISA advisory, December 2021) |
| **Recommended for Java 7 environments** | **2.12.3** (Java 7 is EOL; organizations should upgrade to Java 8) |

Only the `log4j-core` artifact is directly vulnerable; `log4j-api` and `log4j` 1.x are not part of this advisory (Log4j 1.x is end of life and has its own risks).

## Why it matters (from the sources)

- **CISA / FBI / NSA advisory (aa21-356a):** Log4Shell was one of the most widely exploited vulnerabilities; patches or updates were the only acceptable remediation action for assets for which updates exist.
- **CISA Known Exploited Vulnerabilities Catalog:** Log4Shell is listed with a December 2021 entry and a December 2021 remediation due date, reinforcing that exploitation was active at time of write-up.
- **NVD:** Scored 10.0 CRITICAL with a CVSS 3.1 vector of `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H`, corroborating the maximum-severity network-exploitable profile.

## What we do about it (derived from the sources)

- Upgrade `log4j-core` to a patched release (per the repo description, aim for 2.16.0+, ideally 2.17.0 for Java 8+).
- Detect and treat vulnerable assets as potentially compromised; inventory all assets using Log4j, including cloud assets.
- Disable JNDI lookups via configuration (`formatMsgNoLookups` / system property) and, as an interim measure, remove `JndiLookup.class` from the classpath.
- Reduce blast radius: remove unused library files, restrict outbound LDAP/JNDI traffic, consider WAF rules and block lists.
- Add automated dependency scanning (Snyk, OWASP Dependency-Check, Trivy, Dependabot) to CI/CD pipelines so vulnerable transitive dependencies are caught on every build.
- Verify mitigations with multiple scanning methods after patching; keep an inventory of known vulnerable assets throughout.

## Sources

- NVD — CVE-2021-44228: https://nvd.nist.gov/vuln/detail/CVE-2021-44228
- Apache Log4j 2 Security Vulnerabilities page: https://logging.apache.org/log4j/2.x/security.html
- CISA / FBI / NSA advisory aa21-356a: https://www.cisa.gov/news-events/cybersecurity-advisories/aa21-356a
- GitHub Advisory Database — CVE-2021-44228: https://github.com/advisories/ghsa-jfh8-c2jp-5v3q