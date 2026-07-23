---
title: 'Evilginx 3: AiTM Phishing and MFA Bypass for Red Teams'
slug: evilginx3-aitm-mfa-bypass
description: 'Learn how Evilginx 3 enables AiTM phishing, captures post-MFA cookies, and helps red teams understand MFA-bypass risks in Microsoft 365.'
image: /evilginx3-aitm-mfa-bypass.webp
draft: false
date: 2026-06-19T00:00:00.000Z
lastmod: 2026-07-23T00:00:00.000Z
categories:
  - web-hacking
subcategories:
  - expoit
tags:
  - session hijacking
  - Microsoft MFA bypass
  - phishing
---

# Evilginx 3: Complete Guide to AiTM Phishing, MFA Bypass, and Session Cookie Theft

Your organization enforces MFA. Your pentest report still says "account compromised." That's usually not a broken control — it's an adversary-in-the-middle (AiTM) attack, and Evilginx 3 is the framework red teams use to demonstrate it in authorized engagements. It doesn't crack MFA and it doesn't bypass FIDO2. It lets the victim authenticate normally, then steals the session cookie issued right after — which is exactly why so many "MFA is enabled" assumptions turn out to be wrong.

This guide covers how Evilginx works internally, how to map it to a professional engagement (scope, ATT\&CK, detection validation, reporting), the current phishlet format, GoPhish integration, and — in detail — how Microsoft Entra ID actually detects this attack class today.

***

## Prerequisites

* A VPS with a public IP, registered domain, full DNS record access
* Go 1.22 or newer (the project's `go.mod` pins this version — an older Go install won't build it)
* TCP port 443 (reverse proxy HTTPS), TCP port 22 (SSH), and UDP port 53 (DNS) reachable from the Internet
* Administrative SSH access and sudo privileges

## What Is an AiTM Attack?

In a classic AiTM (adversary-in-the-middle) attack, the attacker's server sits between the victim and the legitimate service. The victim interacts with the real login page, completes MFA, and authenticates successfully — the entire session passes through the attacker's reverse proxy in real time. For a broader look at how man-in-the-middle techniques work at the network level, see HackITA's guide to [Man in the Middle](https://hackita.it/articoli/man-in-the-middle/).

```
Victim Browser
      │
      ▼
Attacker-Controlled Domain
      │
      ▼
Evilginx Reverse Proxy
      │
      ├──────────► login.microsoftonline.com
      │
      ▼
Session Cookie Issued
      │
      ▼
Captured by the Proxy
```

The moment the legitimate service (e.g., Microsoft Entra ID) issues the authenticated session cookie, Evilginx intercepts it. That cookie represents a valid, post-MFA authenticated session — replaying it from another machine can open the victim's account without a new authentication challenge, the same underlying idea as classic [session hijacking](https://hackita.it/articoli/session-hijacking/), just applied to a modern, MFA-protected login flow instead of a bare unauthenticated cookie.

This is fundamentally different from traditional credential [phishing](https://hackita.it/articoli/phishing/). Stolen credentials alone are useless if MFA is enforced. A stolen post-MFA session token is immediately actionable — this is the core reason AiTM / reverse proxy phishing has become a favored technique against Microsoft Entra ID and other IdPs where MFA isn't phishing-resistant.

## Internal Architecture

Evilginx isn't just "a proxy" — it's a self-contained stack with several components working together:

* **Embedded DNS server** — Evilginx acts as the authoritative resolver for your phishing domain, provisioning subdomains automatically as each phishlet requires, instead of relying on an external DNS provider.
* **Reverse proxy core** — sits between the victim's browser and the real service, forwarding requests and responses in both directions in real time.
* **TLS termination** — handled via the `certmagic` library, which manages Let's Encrypt certificate issuance and renewal automatically.
* **Response rewriting** — Evilginx rewrites hostnames inside HTML/JS/JSON responses (the `auto_filter` behavior) so the victim's browser keeps talking to the proxy instead of jumping to the real domain mid-flow.
* **Cookie/token extraction** — the `auth_tokens` block in a phishlet tells Evilginx exactly which cookies, headers, or body fields to pull out of the traffic as it passes through.
* **Session storage** — captured sessions (tokens, and any credentials a phishlet extracts) are kept in a local embedded database on the VPS for the duration of the engagement, not sent anywhere externally by default.
* **Lure management** — tracks individual campaign URLs, their target phishlet, and their configured redirect, independently of the phishlet's core config.

## Threat Model

**Goal**: demonstrate, in an authorized red team engagement, that classic MFA (TOTP/SMS/push) doesn't prevent account takeover if the post-authentication session token can be intercepted and replayed.

**Limits**: it doesn't work against phishing-resistant authentication bound to the origin at the protocol level — FIDO2/WebAuthn (passkeys, hardware keys), Windows Hello for Business, and certificate-based authentication all qualify, provided the tenant enforces a phishing-resistant Authentication Strength so a weaker fallback method can't be used instead. Token Protection can also reduce the value of a stolen token in supported scenarios, but it isn't a universal browser-session defense.

**Countermeasures**: phishing-resistant MFA with Authentication Strength enforced, Continuous Access Evaluation, Conditional Access, and monitoring for post-auth IP mismatches. For a broader map of how authentication and authorization weaknesses fit together beyond this one technique, see HackITA's [Auth & Access Control](https://hackita.it/articoli/auth-access-control-guida-completa/) guide.

### Why TLS Doesn't Save the Victim Here

A common point of confusion: the victim's browser shows a valid padlock and a correct-looking HTTPS connection throughout the attack. That's because the certificate is real — issued by Let's Encrypt for the attacker's own domain, not for Microsoft's. TLS guarantees the connection is encrypted and that the domain in the address bar matches the certificate; it says nothing about whether that domain is the one the user actually meant to visit. The transparent proxying is what makes the attack invisible to the browser itself — the browser has no way to know the traffic it's forwarding is being mirrored to a second, attacker-controlled connection to the real service.

***

## Infrastructure Requirements

Set the domain's nameserver glue records to your VPS IP at the registrar level. Most registrars (Namecheap, GoDaddy, Porkbun) support this under "Custom Nameservers" or "Host Records." The glue record maps your nameserver hostname (e.g., `ns1.yourdomain.com`) to your VPS IP — this allows DNS resolution to reach Evilginx before any `A` records exist.

## Installation

```bash
sudo apt update
sudo apt install -y git make ca-certificates

# Install a currently supported Go release from:
# https://go.dev/doc/install
go version  # must report go1.22 or newer

git clone --depth 1 https://github.com/kgretzky/evilginx2.git
cd evilginx2
make

sudo ./build/evilginx -p ./phishlets
```

If UDP port 53 is already occupied, identify and reconfigure the conflicting resolver before starting Evilginx:

```bash
sudo ss -lunp | grep ':53'
```

Don't disable `systemd-resolved` blindly — doing so can break DNS resolution on the VPS itself.

***

## Initial Configuration

```
config domain <your-phishing-domain>
config ipv4 external <your-vps-ip>
blacklist unauth
```

`blacklist unauth` blocks unauthenticated visits — threat intel crawlers will probe any newly issued TLS certificate within hours of it appearing in Certificate Transparency logs, so this reduces exposure to automated scanning.

DNS must be resolving through your VPS before enabling any phishlet — otherwise the ACME HTTP-based challenge fails. Verify propagation with `dig NS yourdomain.com` before proceeding. For a deep dive into how HTTP/HTTPS and TLS work at the protocol level, see HackITA's guide to [HTTP and HTTPS](https://hackita.it/articoli/http-https/).

## Common Operational Issues

At a conceptual level — not exhaustive troubleshooting steps, just what these symptoms usually mean:

| Symptom                | Likely cause                                                                                                                 |
| ---------------------- | ---------------------------------------------------------------------------------------------------------------------------- |
| Certificate not issued | DNS not yet propagated, or the ACME challenge can't reach the VPS                                                            |
| Phishlet won't enable  | Domain/hostname not fully configured, or a version mismatch with the phishlet's `min_ver`                                    |
| Lure unreachable       | DNS or firewall issue between the victim and the VPS                                                                         |
| No sessions recorded   | The target's authentication flow has changed since the phishlet was written, or a required host wasn't captured by the proxy |

This is also why phishlets age: identity providers change login flows, cookie names, and redirect logic over time, so a phishlet that worked in one engagement can silently stop working in the next without any configuration error on your end — it needs to be re-validated against the current flow, not just reused.

## Validating Your Setup Before a Real Campaign

Running a lure against a live target before confirming the infrastructure actually works end-to-end is how engagements get burned on day one. Check these, in order, before you ever send a lure email:

**DNS is actually resolving through Evilginx.** From a machine outside your VPS (not the VPS itself):

```bash
dig NS yourdomain.com
dig yourdomain.com
```

The `A` record should resolve to your VPS IP, and the NS records should point to the nameservers you configured. If this doesn't match, don't move on — the ACME challenge and every phishlet after it will fail for the same reason.

**The certificate actually issued.** Inside Evilginx:

```
phishlets
```

A phishlet showing as enabled with no certificate error means it issued successfully. From outside, confirm what a real browser would see:

```bash
curl -vI https://yourphishingdomain.com 2>&1 | grep -i "subject\|issuer"
```

You want to see Let's Encrypt as the issuer, not a self-signed cert — a self-signed cert here almost always means you're accidentally running in `-developer` mode or the ACME challenge silently failed and Evilginx fell back to a local cert.

**The lure actually redirects correctly.** Open the lure URL yourself (from a browser, not `curl` — some phishlets depend on JS execution) and walk through the full login flow with a disposable test account in your own lab tenant if you have one. Confirm you land on the real service after auth, not an error page, and that the session shows up in `sessions` before you ever point it at a real target.

**Reading what the tool is telling you.** `phishlets` lists enabled phishlets and whether their certificate is valid — an entry present but greyed out or flagged usually means DNS/cert issues, not a phishlet bug. `lures` shows every lure you've created and which phishlet it's bound to — a lure pointing at a disabled phishlet won't work even if the URL itself resolves. `sessions` only lists a session once the phishlet's `auth_tokens` actually matched something in the traffic — an empty list after a real login attempt almost always means the target's current flow doesn't match what the phishlet expects, not that nothing happened.

***

## Phishlet Structure and Anatomy

Phishlets are YAML configuration files that define how Evilginx proxies a specific authentication flow. Each phishlet specifies which hostnames to proxy, which cookies to capture, which POST fields contain credentials, and which URL signals authentication has completed. The current phishlet format specification is documented on [help.evilginx.com](https://help.evilginx.com/community/phishlet-format).

The following excerpt illustrates the Evilginx 3 phishlet schema for Microsoft 365. It is not presented as a ready-to-use or currently verified phishlet: authentication hosts, parameters, and cookie behavior can change and must be validated in an authorized test tenant before use.

```yaml
name: 'Microsoft 365'
min_ver: '3.0.0'

proxy_hosts:
  - {phish_sub: 'login', orig_sub: 'login', domain: 'microsoftonline.com', session: true, is_landing: true, auto_filter: true}
  - {phish_sub: 'account', orig_sub: 'account', domain: 'microsoft.com', session: false, is_landing: false, auto_filter: true}
  - {phish_sub: 'www', orig_sub: 'www', domain: 'office.com', session: false, is_landing: false, auto_filter: true}

auth_tokens:
  - domain: '.login.microsoftonline.com'
    keys: ['ESTSAUTH:always', 'ESTSAUTHPERSISTENT', 'SignInStateCookie:always']
    type: 'cookie'

credentials:
  username:
    key: '(login|UserName)'
    search: '(.*)'
    type: 'post'
  password:
    key: '(passwd|Password|accesspass)'
    search: '(.*)'
    type: 'post'

login:
  domain: 'login.microsoftonline.com'
  path: '/?auth=2'
```

**`proxy_hosts`** lists every Microsoft subdomain Evilginx impersonates. The `session: true` flag marks the primary authentication host. `auto_filter: true` enables the response rewriting described in the architecture section above — without it, the victim's browser starts hitting Microsoft's real servers directly, breaking the proxy chain.

**`auth_tokens`** defines exactly which cookies to extract. Microsoft documents `ESTSAUTH` as a transient SSO session cookie and `ESTSAUTHPERSISTENT` as a persistent SSO cookie; its effective lifetime depends on session and tenant policies and shouldn't be described as a fixed duration. `SignInStateCookie` helps Microsoft coordinate sign-out across accessed services and doesn't contain user information by itself. Cookies such as `x-ms-gateway-slice` are used for routing and load balancing rather than authentication. Cookie names and authentication flows can change, so a phishlet must be validated against the authorized tenant and flow used during the engagement — see [Microsoft's documentation on authentication cookies](https://learn.microsoft.com/en-us/entra/identity/authentication/concept-authentication-web-browser-cookies) for the current reference.

On IdPs built around OAuth/OIDC rather than classic cookies, the equivalent artifact is often a bearer token in an `Authorization` header or a response body field — Evilginx 3's support for body/header capture (not just cookies) exists specifically for this case, storing whatever the phishlet's `auth_tokens` definition tells it to.

**`credentials`** captures the username and password from the proxied POST request; the regex patterns match Microsoft's login form field names, which vary across authentication flows.

**`login`** defines the landing URL Evilginx redirects a target to after hitting your lure.

Place the YAML in the `phishlets/` directory — Evilginx loads it automatically.

***

## Enabling Phishlets and Generating Lure URLs

```
phishlets hostname m365 <your-phishing-domain>
phishlets enable m365
phishlets
```

Create a lure and set its redirect target — `redirect_url` is configured per-lure with `lures edit`, not as a global `config` command:

```
lures create m365
lures edit 0 redirect_url https://office.com
lures get-url 0
```

Run `help lures` inside Evilginx for the full list of lure parameters available in your version.

***

## Session Capture and Cookie Reuse

```
sessions
sessions <session_id>
```

The output includes whichever cookies the phishlet's `auth_tokens` captured, alongside username and password if the phishlet extracts them. Importing the right cookies into a browser can reopen the session without a fresh authentication prompt, if MFA already passed on the legitimate server and the session hasn't since been revoked.

***

## GoPhish Integration (Evilginx 3.3+)

As of version 3.3, Evilginx supports official integration with a forked version of GoPhish for managing phishing campaigns. Architecturally, GoPhish owns the campaign layer — email templates, sending profiles, recipient groups, and open/click tracking — while Evilginx owns the authentication layer. The integration point is the lure URL: instead of pointing a GoPhish campaign at a static landing page, you point it at an Evilginx lure, so a single dashboard shows email opens and clicks feeding into the same event stream as phishlet session captures.

```
config gophish admin_url https://<gophish-ip>:<port>
config gophish api_key <your-api-key>
config gophish test
```

The forked GoPhish repository is maintained at `github.com/kgretzky/gophish`, documented in detail on breakdev.org.

***

## Differences from Evilginx 2

Hackita already has a guide on [Evilginx 2](https://hackita.it/articoli/evilginx2/), focused on 2FA bypass via MITM phishing proxy. The main differences that justify a separate guide for Evilginx 3: TLS management moved to certmagic for native Let's Encrypt auto-renewal; support for session tokens in HTTP response bodies and headers, not just cookies; built-in example phishlets dropped from the main repository (community-maintained now); configuration format switched from custom to JSON (phishlets remain YAML); and official integration with a GoPhish fork for campaign management.

## Why "Microsoft 365" Isn't One Scenario

Treating Microsoft Entra ID as a single authentication flow is the most common conceptual mistake in planning this kind of engagement. The tenant's identity model changes what an AiTM proxy is actually up against:

* **Cloud-only tenants** authenticate entirely within Entra ID — the phishlet only needs to handle Microsoft's own login and MFA flow.
* **Password Hash Synchronization (PHS)** and **Pass-Through Authentication (PTA)** both still terminate at Entra ID's login pages from the browser's perspective, but PTA involves an on-premises agent validating credentials — which matters for how the client's blue team correlates the sign-in, not for the proxy itself.
* **Federated tenants (ADFS)** hand authentication off to an entirely separate on-premises login page before Entra ID issues anything — a phishlet built only for `login.microsoftonline.com` won't capture a federated login at all, since the actual credential prompt happens on the organization's own ADFS server.
* **Conditional Access, device compliance, and sign-in frequency** policies can force re-authentication or block the session outright based on signals a reverse proxy can't replicate — a captured token from a policy-compliant session behaves very differently from one that a stricter policy would have blocked or immediately re-challenged.

None of this changes how you'd configure Evilginx — it changes whether an engagement's objective (say, "test session hijacking resilience") is even answerable against a given tenant without first confirming which of these models it uses.

***

## Running This as a Professional Engagement, Not Just a Tool Demo

Turning this technique into a real engagement — not just running a tool — looks like this:

**Scope and objectives.** Agree with the client on what you're validating: credential exposure, session hijacking feasibility, or detection-stack validation — these need different success criteria and reporting. Get written authorization covering the specific domains, identities, and time window, and agree how captured session data will be stored and destroyed.

**Mapping to ATT\&CK.** [T1566 Phishing](https://attack.mitre.org/techniques/T1566/) for the initial access vector, [T1539 Steal Web Session Cookie](https://attack.mitre.org/techniques/T1539/) for the cookie theft, and [T1550.004 Use Alternate Authentication Material: Web Session Cookie](https://attack.mitre.org/techniques/T1550/004/) for the replay step. Naming these lets the client's blue team map findings onto their own detection coverage.

**Honest limits.** A reverse proxy of this kind leaves artifacts almost by definition — DNS records, a certificate, a differing IP, distinct traffic patterns. That's not a flaw to hide; it's what a detection-validation engagement is testing for. A successful capture proves a gap exists at that moment, not that it stays exploitable afterward — session state, Conditional Access policy, and phishlet compatibility can all change quickly.

**Detection engineering and purple team validation.** Work with the client's SOC beforehand on what to collect — Entra ID sign-in/risk logs, Conditional Access results, Attacker in the Middle / Anomalous Token alerts — and agree what "detected" means. Track how long each step took relative to capture; that MTTD/MTTR gap is often more valuable to the client than the fact that the technique worked.

**Reporting.** The deliverable is the reproducible chain from lure to session reuse, whether detection fired and when, and recommendations tied to what was actually observed — not just "we captured a cookie."

## Detection Surface

It helps to think about where AiTM activity can actually be observed, since no single layer catches everything on its own:

* **Network** — TLS/HTTP fingerprint mismatches (JA3/JA4, HTTP/2 frame ordering) between a proxy and a real browser
* **Identity** — Entra ID Protection's Attacker in the Middle and Anomalous Token detections, IP/location mismatches between MFA completion and later session use
* **Endpoint** — device compliance state and device ID not matching the session's registered device
* **Cloud/SaaS** — Conditional Access and Continuous Access Evaluation acting on risk signals in near real time
* **Certificate Transparency logs** — newly issued certificates on suspicious or newly registered domains targeting your organization's brand, independent of which reverse-proxy tool is behind them

## What Blue Teams Should Be Looking For

AiTM activity is not inherently invisible. Microsoft Entra ID Protection includes detections built for exactly this attack class: **Attacker in the Middle**, an offline detection that flags sessions linked to a malicious reverse proxy, and **Anomalous Token**, a real-time/offline detection for tokens with unusual characteristics such as an unexpected lifetime or replay from an unfamiliar location. Both require Entra ID P2 for full detail, alongside signals like unfamiliar sign-in properties and atypical travel. Detection availability and timing depend on licensing, telemetry, and signal confidence — the absence of an alert doesn't prove a session is legitimate. Pairing these with risk-based Conditional Access (forcing re-authentication at medium+ risk) and Continuous Access Evaluation is what turns detection into mitigation, since the token can be revoked, not just flagged.

Evilginx's own certificate strings (e.g., from its self-signed `-developer` testing mode) don't appear in normal Let's Encrypt deployments, so detection shouldn't rely on spotting a tool-specific certificate — it should rely on the identity and network signals above, which apply regardless of which reverse-proxy framework is behind the attack.

A rough starting point for correlating sign-in and session activity in Entra ID logs, looking for MFA completion and later use from different network origins within a short window:

```kql
SigninLogs
| where TimeGenerated > ago(24h)
| where ResultType == 0
| where AuthenticationRequirement == "multiFactorAuthentication"
| project TimeGenerated, UserPrincipalName, IPAddress, Location, DeviceDetail
| join kind=inner (
    AADNonInteractiveUserSignInLogs
    | where TimeGenerated > ago(24h)
    | project TimeGenerated2 = TimeGenerated, UserPrincipalName, IPAddress2 = IPAddress, Location2 = Location
) on UserPrincipalName
| where IPAddress != IPAddress2 and TimeGenerated2 > TimeGenerated
```

Treat this as a starting shape to adapt to your own workspace schema, not a drop-in detection rule — field names and available tables vary by license tier and how the tenant's logs are exported.

### What "It Worked" Actually Means

"The session showed up in `sessions`" is a weaker claim than it sounds, and conflating it with "the environment is vulnerable" is a common reporting mistake. These are distinct, increasingly strong claims, and a report should specify which one was actually confirmed:

1. A token was **captured** by the phishlet
2. The token is still **valid** (hasn't expired or been revoked)
3. The session is **reusable** (importing it actually reopens an authenticated session)
4. The **target resource** is reachable with that session (not just the IdP login state)
5. No **alert fired** and no **control** (Conditional Access, CAE) blocked the reuse

A finding that stops at step 1 is not the same finding as one validated through step 5, and reporting them identically overstates the result.

### What Actually Stops This Attack Class

| Control                                                   | Effect against AiTM                                                                 |
| --------------------------------------------------------- | ----------------------------------------------------------------------------------- |
| SMS, TOTP, and push MFA                                   | Phishable — don't prevent session interception                                      |
| FIDO2 security keys and passkeys                          | Phishing-resistant when enforced                                                    |
| Windows Hello for Business                                | Phishing-resistant                                                                  |
| Certificate-based MFA                                     | Phishing-resistant                                                                  |
| Token Protection                                          | Reduces replay for supported native apps/resources; not a universal browser defense |
| Conditional Access, device compliance, risk policies, CAE | Reduce exposure but aren't an absolute guarantee                                    |

FIDO2/WebAuthn, Windows Hello for Business, and certificate-based authentication all bind the authentication assertion to the origin domain, which is what defeats AiTM at the protocol level — provided the tenant enforces a phishing-resistant Authentication Strength so a weaker fallback method isn't still permitted. See [2FA Bypass on Hackita](https://hackita.it/articoli/2fa-bypass/) for more on why phishing-resistant methods hold up where TOTP/SMS/push don't.

## End-of-Engagement Checklist

The operational side of a live engagement doesn't stop at "we captured a session." Before closing out:

1. **Confirm nothing is left reachable.** Disable every active phishlet (`phishlets disable <name>`) and stop pointing lures at real domains the moment active testing is done — a lure left live after the test window is scoped is no longer authorized activity.
2. **Handle captured data as sensitive.** Session cookies and any captured credentials are functionally equivalent to plaintext passwords for the duration they're valid. Store them only as long as the client's evidence-handling agreement requires, encrypted at rest, and don't copy them anywhere outside that agreed location.
3. **Revoke what you captured.** Where the engagement scope allows it, work with the client to revoke the specific sessions/tokens captured during testing rather than leaving them to expire naturally — this closes the actual window you opened.
4. **Tear down the infrastructure.** Destroy the VPS, remove the DNS records pointing at it, and let the domain's certificate lapse rather than leaving a phishing-capable domain sitting configured after the report is delivered.
5. **Report against what you validated, not just what worked.** Tie every finding back to the validation steps above — a session you confirmed was reusable is a different finding from one that merely appeared in `sessions` but was never tested for reuse.

***

## Frequently Asked Questions

**Does Evilginx 3 work against Microsoft's MFA?** Against TOTP, push notifications, and SMS, potentially yes if the resulting session token can be captured and reused before revocation. Not against properly enforced FIDO2/passkeys, Windows Hello for Business, or certificate-based auth.

**What changed between Evilginx 2 and Evilginx 3?** Version 3 moved TLS management to certmagic for Let's Encrypt auto-renewal, added support for session tokens in HTTP response bodies and headers (not just cookies), dropped built-in phishlets from the main repository, and changed the configuration format to JSON. Phishlets remain in YAML.

**Where are community phishlets for Evilginx 3?** The main repository doesn't ship example phishlets. Community collections exist on GitHub — search `evilginx3 phishlets`. The official Evilginx Mastery course (academy.breakdev.org) covers custom phishlet development.

**Is Evilginx detectable on the network?** Yes, through a combination of signals — Certificate Transparency monitoring of newly issued certs, session replay from an IP that didn't complete MFA, and Entra ID Protection's Attacker in the Middle and Anomalous Token detections specifically.

**Does capturing a session mean the environment is actually vulnerable?** It means the technique worked at that moment, against that specific authentication flow and policy configuration. It's not a permanent finding — IdP flow changes, Conditional Access updates, or a revoked session can all close the gap, which is why findings should be validated and reported with that context rather than as an absolute statement.

***

*Evilginx is a publicly available red team tool intended for use in authorized penetration tests and red team engagements with signed scope and written client authorization.*
