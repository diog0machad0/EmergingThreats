# Slack advisory distribution

Module: `slack_client.py`. Page: `/emerging-threats` (Vulnerabilities, Threat Intelligence, and Advisories tabs).

## Behavior

1. The analyst opens a vulnerability or TI match and picks **which customers to notify** in the create-advisory block. The customer the match belongs to is pre-ticked.
2. The advisory is generated as usual (LLM markdown → Scriba PDF, tracked in `advisories`).
3. `POST /api/advisories/<id>/distribute` with `{"customers": [id, ...]}` renders that customer's approved message and uploads the PDF to that customer's channels as an `initial_comment`.
4. Every channel attempt is written to `advisory_distributions` with `sent` or `failed`, the error, **and the customer it was sent for**, so "was this already sent, and to whom" survives closing the modal.

Already-generated advisories can be re-sent from the **Send to Slack** action on each card in the Advisories tab, which calls the same endpoint.

### Why customers, not channels

Channels used to be selected directly. That stopped working once formats became
per-customer: a channel id says where to post but nothing about which wording
belongs there, and two customers selected at once need two different messages.
Choosing the customer determines both the destination and the format.

One advisory sent to several customers therefore produces several distinct
messages. The field extraction behind them runs **once** — it reads the advisory,
not the customer — so an extra recipient costs at most one small follow-up call
for free-text placeholders, and nothing for a customer whose format has none.

A bare `{"channels": [...]}` body is still accepted for direct sends, and a
request with neither falls back to the advisory's own customer.

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

## Channel routing

Each customer carries its own destinations in `customers.slack_channels`, set on
the Customers page from a picker backed by `GET /api/slack/channels`. Evoke goes
to `#evoke-threatintel`, Fidelidade to `#fidelidade-threatintel`.

`GET /api/advisories/<id>/channels` returns the configured channels for an
advisory's customer so the send dialog can pre-tick them. The analyst can still
change the selection; if a distribute call arrives with no channels at all, the
customer's configured list is used rather than failing.

A channel is stored as `{"id", "name"}`. The id is what `files_upload_v2`
addresses, but seeded and hand-typed channels start with only a name, so ids are
resolved against the workspace listing at send time. A name that resolves to
nothing is reported as a failed channel rather than silently dropped.

## The notification message

Customers do not share a message format, so `advisory_notification.py` renders
whichever template is stored on the customer row. `GET`-ing a preview before
sending is possible via `POST /api/advisories/<id>/message-preview`.

Evoke's approved field block is the seed default, also used for any customer
with no format of its own:

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

### Per-customer formats

Fidelidade uses a prose covering note instead of the field block:

```
Hello,

We are sharing the attached advisory regarding <CVE-ID> (<VULNERABILITY-NAME>), a <VULNERABILITY-TYPE / SHORT DESCRIPTION> affecting <AFFECTED PRODUCT / COMPONENT> that <BRIEF DESCRIPTION OF HOW THE VULNERABILITY CAN BE TRIGGERED OR EXPLOITED>.

Please review the attached advisory, validating <WHAT SHOULD BE CHECKED / EXPOSURE CONDITION>, and prioritizing <PATCHING / MITIGATION ACTION> for <SYSTEMS OR ASSETS THAT SHOULD RECEIVE PRIORITY>.

[Security Advisory] @SOCIberia_DXC [<SEVERITY>]

Thanks,
```

Templates are Slack mrkdwn written by the analyst and emitted **verbatim**, so
the `@SOCIberia_DXC` mention and the `[Security Advisory]` tag line survive.
Only substituted values are escaped.

Placeholders are `<UPPERCASE>` tokens and fall into three groups:

| Group | Filled by | Examples |
|---|---|---|
| Computed | Code, never the model | `<CVE-ID>`, `<SEVERITY>`, `<ADVISORY-DATE>`, `<PDF-FILENAME>`, `<RECOMMENDATIONS>`, `<PRIORITY-BULLET>`, `<REMEDIATION-DATE>` |
| Known fields | The standard extraction call | `<VULNERABILITY-NAME>`, `<VENDOR-PRODUCT>`, `<ADVISORY-ID>`, `<AFFECTED-VERSIONS>`, `<FIXED-VERSION>`, `<DESCRIPTION>` |
| Analyst-authored | A second extraction call | `<WHAT SHOULD BE CHECKED / EXPOSURE CONDITION>` and anything else invented |

The placeholder name is the only instruction the model gets for the third
group, so descriptive names produce better output than terse ones. The whole
template is passed as context so each value reads correctly in its sentence.
Anything the advisory does not state becomes `N/A`. The second call is skipped
when a template uses no analyst-authored tokens, so Evoke's format still costs
exactly one LLM call.

Evoke's templated output is byte-for-byte identical to the previous hardcoded
rendering; that equivalence is worth re-checking if the renderer changes.

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

- `advisory_notification.render()` and `render_template()` are pure — no network, no config, no file reads — so message layout is testable without a workspace or an API key. `build_advisory_message()` wraps them and may call the LLM.
- `prepare_fields()` is customer-independent and `build_for_customer()` is not. Keep that split: collapsing them would re-extract the advisory once per recipient.
- The notification is built once per **customer**, not once per channel, so a customer with three channels still costs one render.
- `render_template()` corrects `a`/`an` against the value that follows, because a template writes "a &lt;PLACEHOLDER&gt;" without knowing what lands there. Without it, messages read "a unauthenticated remote code execution flaw".
- `distribute_advisory()` never raises for a per-channel failure. It returns one result dict per channel, matching how `apt_ioc_processor` records `status` / `error_message` instead of failing the pipeline. One archived or bot-less channel must not block delivery to the rest.
- Distribution is a separate endpoint from advisory creation. A Slack outage then costs you a delivery, not a generated advisory.
- `files_upload_v2` targets a single channel per call, hence the loop rather than a comma-joined channel list.
- Keep `SLACK_BOT_TOKEN` blank in `.env.example`. A placeholder string there previously made the app report an integration that did not exist.
