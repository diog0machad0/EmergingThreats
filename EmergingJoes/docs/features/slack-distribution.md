# Slack advisory distribution

Module: `slack_client.py`. Page: `/emerging-threats` (Vulnerabilities, Threat Intelligence, and Advisories tabs).

## Behavior

1. The analyst opens a vulnerability or TI match and picks target channels in the create-advisory block.
2. The advisory is generated as usual (LLM markdown → Scriba PDF, tracked in `advisories`).
3. `POST /api/advisories/<id>/distribute` uploads the PDF to each selected channel with a crafted mrkdwn message as its `initial_comment`.
4. Every channel attempt is written to `advisory_distributions` with `sent` or `failed` plus the error, so "was this already sent, and where" survives closing the modal.

Already-generated advisories can be re-sent from the **Send to Slack** action on each card in the Advisories tab, which calls the same endpoint.

## Why the PDF is attached rather than linked

Advisory PDFs are served from `http://127.0.0.1:5050/api/advisories/pdf/<filename>`, which is reachable only on the machine running the app. A link in Slack would be dead for every recipient, so the file itself is uploaded via `files_upload_v2`.

## Configuration

Settings → Slack Integration:

- Enable toggle (`slack_enabled`)
- Bot token (`slack_bot_token`, `xoxb-…`), also settable via the `SLACK_BOT_TOKEN` environment variable

Connectivity check: `GET /api/slack/status` tests the saved token. `POST /api/slack/status` with `{"token": "..."}` tests a token that has been typed into Settings but not saved yet — the Test button uses this, so a valid token is not reported as "not set" just because the analyst has not pressed Save. The posted token is never persisted.

## Bot token or user token

Both work; nothing in the code inspects the prefix.

| | Bot token (`xoxb-`) | User token (`xoxp-`) |
|---|---|---|
| Channels visible | Only those the bot was invited to | The ones you are already in |
| Posts appear as | The app | You |
| Scopes granted under | *Bot Token Scopes* | *User Token Scopes* |
| Survives your account being deactivated | Yes | No |

Granting the scopes under the wrong heading is the usual cause of `missing_scope` — a user token ignores Bot Token Scopes entirely. A bot token is the better choice for a shared team tool; a user token is a quick way to trial the feature without an invite step.

### Slack app setup

1. Create an app at <https://api.slack.com/apps> → **From scratch**.
2. Under **OAuth & Permissions**, add the bot token scopes: `chat:write`, `files:write`, `channels:read`, `groups:read`.
3. Install to the workspace and copy the **Bot User OAuth Token**.
4. Run `/invite @your-bot` in every channel that should receive advisories.

Step 4 is not optional. `list_member_channels()` filters to `is_member == True`, so a channel the bot has not joined never appears in the picker — this is deliberate, since offering it would only produce a `not_in_channel` failure at send time.

## Which customers a CVE affects

`GET /api/cve/<cve_id>/customers` (backed by `get_customers_for_cve()`) aggregates every `vulnerability_analyses` hit for a CVE across the whole corpus into one entry per customer, with their matched technologies and the articles the CVE appeared in. The vulnerability modal shows this as an "Affects N customers" line per hit.

This roll-up is **analyst-only and is not put in the Slack message**. Channels are shared, and naming which other customers are exposed to a live vulnerability would leak one client's risk posture to another.

This matters because the queue is article-scoped: the same CVE routinely appears in several articles and matches different customers in each, so a single modal understates real exposure.

## The notification message

`advisory_notification.py` owns the message format. The approved template is stored verbatim as `NOTIFICATION_TEMPLATE` in that module, which is the source of truth:

```
Security Vulnerability Notification

Advisory Date: [DD Month YYYY]
Vulnerability Name: [Vulnerability or advisory name]
Vendor / Product: [Vendor and affected product]
CVE(s): [CVE ID(s)]
Advisory ID: [Vendor advisory ID / N/A]
Severity: [Critical / High / Medium / Low]
Affected Versions: [Affected version(s)]
Fixed Version: [Fixed version / Not available]

Description:
[Briefly describe the vulnerability, exploitation requirements, and potential impact.]

Recommendations:
• [Required patch, upgrade, mitigation, or validation action]
• [Priority and requested completion date]
Attachments:
• [Advisory filename].pdf — Security advisory
```

### Threat intelligence variant

TI advisories have no CVE and no version numbers, so they use `TI_NOTIFICATION_TEMPLATE` — the same layout, retitled, with the CVE and version fields dropped and `Vulnerability Name` reading `Threat Name`:

```
Threat Intelligence Notification

Advisory Date: [DD Month YYYY]
Threat Name: [Threat, campaign, or actor name]
Vendor / Product: [Affected vendor, product, or technology]
Advisory ID: [Vendor or CERT advisory ID / N/A]
Severity: [Critical / High / Medium / Low]

Description:
[Briefly describe the threat, how it is delivered, and potential impact.]

Recommendations:
• [Required detection, mitigation, or validation action]
• [Priority and requested completion date]
Attachments:
• [Advisory filename].pdf — Security advisory
```

Selection is driven by the advisory's `kind` column, and each variant has its own extraction prompt — the TI one asks for detection and hunting actions rather than patch versions. `Advisory ID` is retained because CERT and government bulletins (for example `AA24-109A`) often do carry one.

### Why the LLM only fills fields

`extract_fields()` asks the model for a JSON object of field *values*; `render()` lays them out in code. Handing the model the whole template invites renamed, reordered, or silently dropped lines, and this is a client-facing deliverable with a fixed shape. It also makes `render()` a pure function, testable with no API key.

The extractor reads the generated advisory markdown (`markdown_path`), not the source article — the advisory has already been researched and is the better-grounded input. Fields the advisory does not state come back as `N/A`; the prompt explicitly forbids guessing version numbers, advisory IDs, and severities.

### Fields that are not LLM-generated

- **Advisory Date** — the advisory's `created_date`.
- **Attachments** — the real `pdf_filename`.
- **The priority bullet** — derived from severity via `REMEDIATION_DAYS` (Critical 7 days, High 14, Medium 30, Low 90). Asking the model for a completion date produced inconsistent deadlines between advisories; a table is predictable and tunable in one place.

### Degradation

`build()` never raises. With no API key or a failed call it renders from `fallback_fields()` — advisory title, technology, and CVE from the database, `N/A` elsewhere — and logs a warning. A degraded notification is better than refusing to distribute an advisory that has already been generated and paid for.

## Notes for agents

- `advisory_notification.render()` is pure — no network, no config, no file reads — so message layout is testable without a workspace or an API key. `build_advisory_message()` wraps it and may call the LLM.
- The notification is built once per distribution, before the channel loop, so a five-channel send costs one LLM call rather than five.
- `distribute_advisory()` never raises for a per-channel failure. It returns one result dict per channel, matching how `apt_ioc_processor` records `status` / `error_message` instead of failing the pipeline. One archived or bot-less channel must not block delivery to the rest.
- Distribution is a separate endpoint from advisory creation. A Slack outage then costs you a delivery, not a generated advisory.
- `files_upload_v2` targets a single channel per call, hence the loop rather than a comma-joined channel list.
- Keep `SLACK_BOT_TOKEN` blank in `.env.example`. A placeholder string there previously made the app report an integration that did not exist.
