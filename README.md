# Endpoint Triager

An advanced endpoint classification and risk scoring tool  
built to help you **prioritize what actually matters**.

Because not every endpoint deserves your time.

---

## Why i built this

Recon usually gives you:
- 500 URLs
- 1 brain
- Limited time

Endpoint Triager was built to answer:

> “Where should I focus first?”

Instead of randomly attacking endpoints, this tool:
- Categorizes them
- Scores them
- Flags risky patterns
- Suggests possible vulnerability classes

It turns noise into direction.

---

## What it analyzes

### Scoring endpoints by impact

Endpoints are classified based on:

- Authentication-related paths
- Admin / internal panels
- Debug / staging endpoints
- APIs and data routes
- File exposure & backups
- High-risk operations (exec, command, upload, etc.)

Each category adds weighted points to a total risk score.

---

### Catching dangerous parameters

Parameters are inspected and casually grouped by risk level:

- **Critical** → `cmd`, `exec`, `eval`, `compile`
- **High** → `file`, `path`, `url`, `redirect`
- **Medium** → `id`, `user`, `account`, `role`

These increase scoring automatically.

---

###  Aggressive Mode (Optional)

When enabled with `--aggressive`, the tool looks for:

- Potential IDOR patterns
- Potential SSRF patterns
- Potential RCE patterns

This mode increases scoring and adds vulnerability hints.

Because sometimes you want to be... suspicious.

---

## Scoring System

Based on total weighted score:

| Score | Severity |
|-------|----------|
| 25+   | CRITICAL |
| 15+   | HIGH     |
| 8+    | MEDIUM   |
| <8    | LOW      |

Higher score = higher priority.

ahh...simple...

---

## Usage

Basic triage:

```bash
python3 endpoint_triager.py -w urls.txt
