"""Slack integration — distribute advisory PDFs to analyst-selected channels."""

import logging
import os

from config import load_config

logger = logging.getLogger(__name__)

# Scopes the bot token needs. Surfaced in Settings so a misconfigured app is
# diagnosable without reading the docs.
REQUIRED_SCOPES = ("chat:write", "files:write", "channels:read", "groups:read")

_CHANNEL_PAGE_LIMIT = 200
_MAX_CHANNEL_PAGES = 20


def slack_config():
    cfg = load_config()
    return {
        "bot_token": (cfg.get("slack_bot_token") or "").strip(),
        "enabled": bool(cfg.get("slack_enabled", False)),
    }


def is_slack_configured():
    cfg = slack_config()
    return cfg["enabled"] and bool(cfg["bot_token"])


def _get_client(token=None):
    """Build a client from an explicit token, else the saved one.

    The override lets Settings verify a token the analyst has typed but not
    yet saved, which is otherwise a dead end: the Test button would report
    "token not set" for a token sitting right there in the field.
    """
    from slack_sdk import WebClient

    resolved = (token or "").strip() or slack_config()["bot_token"]
    if not resolved:
        raise RuntimeError("Slack bot token not configured")
    return WebClient(token=resolved)


def test_connection(token=None):
    """Return (ok, message) for Slack connectivity.

    Args:
        token: Optional unsaved token to verify instead of the stored one.
            When given, the enabled toggle is ignored — the analyst is
            explicitly asking whether this credential works.
    """
    cfg = slack_config()
    candidate = (token or "").strip()
    if not candidate:
        if not cfg["enabled"]:
            return False, "Slack integration disabled"
        if not cfg["bot_token"]:
            return False, "Slack bot token not set (Settings)"
    try:
        resp = _get_client(candidate).auth_test()
        team = resp.get("team") or "workspace"
        who = resp.get("user") or "bot"
        message = f"Connected — {who} on {team}"
        if candidate and candidate != cfg["bot_token"]:
            message += " (not saved yet — click Save Settings)"
        return True, message
    except Exception as e:
        return False, str(e)


def list_member_channels(token=None):
    """Return the channels the bot has been invited to.

    Slack can only post where the bot is a member, so channels it has not been
    invited to are filtered out rather than offered and then failing at send
    time. Raises on API failure so the caller can report why the list is empty.
    """
    client = _get_client(token)
    channels = []
    cursor = None

    for _ in range(_MAX_CHANNEL_PAGES):
        resp = client.conversations_list(
            types="public_channel,private_channel",
            exclude_archived=True,
            limit=_CHANNEL_PAGE_LIMIT,
            cursor=cursor,
        )
        for ch in resp.get("channels") or []:
            if not ch.get("is_member"):
                continue
            channels.append({
                "id": ch.get("id"),
                "name": ch.get("name"),
                "is_private": bool(ch.get("is_private")),
            })
        cursor = (resp.get("response_metadata") or {}).get("next_cursor")
        if not cursor:
            break

    channels.sort(key=lambda c: (c["name"] or "").lower())
    return channels


def build_advisory_message(advisory, article_url=None, use_llm=True):
    """Compose the Slack message that accompanies an advisory PDF.

    Delegates to ``advisory_notification``, which renders the approved
    Security Vulnerability Notification template from LLM-extracted fields.

    Returns:
        A Slack mrkdwn string.
    """
    from advisory_notification import build

    text, _used_llm = build(advisory, article_url=article_url, use_llm=use_llm)
    return text


def _share_timestamp(response, channel_id):
    """Pull the message ts for a channel out of a files_upload_v2 response."""
    try:
        files = response.get("files") or []
        file_obj = files[0] if files else (response.get("file") or {})
        shares = file_obj.get("shares") or {}
        for visibility in ("public", "private"):
            entries = (shares.get(visibility) or {}).get(channel_id) or []
            if entries:
                return entries[0].get("ts")
    except Exception:  # noqa: BLE001 - ts is best-effort metadata only
        pass
    return None


def normalize_targets(targets):
    """Accept either recipient groups or a bare channel-id list.

    A group is ``{customer_id, customer_name, channels: [{id, name}]}``. The
    bare list form is kept so older callers and direct channel sends still
    work; it becomes a single group with no customer, which renders in the
    standard format.
    """
    groups = []
    for entry in targets or []:
        if isinstance(entry, str):
            groups.append({
                "customer_id": None, "customer_name": None,
                "channels": [{"id": entry, "name": None}],
            })
            continue
        if not isinstance(entry, dict):
            continue
        channels = [
            {"id": c.get("id"), "name": c.get("name")}
            if isinstance(c, dict) else {"id": c, "name": None}
            for c in (entry.get("channels") or [])
        ]
        channels = [c for c in channels if c["id"]]
        if not channels:
            continue
        groups.append({
            "customer_id": entry.get("customer_id"),
            "customer_name": entry.get("customer_name"),
            "channels": channels,
        })
    return groups


def _failure(group, channel, error):
    return {
        "channel_id": channel["id"],
        "channel_name": channel.get("name"),
        "customer_id": group.get("customer_id"),
        "customer_name": group.get("customer_name"),
        "status": "failed",
        "error_message": error,
        "slack_ts": None,
    }


def distribute_advisory(advisory, targets, article_url=None):
    """Upload an advisory PDF to each recipient, in that recipient's format.

    Customers do not share a message format, so the notification is rendered
    once per customer rather than once per send. The advisory fields behind it
    are extracted only once, so adding a recipient costs at most one small
    follow-up call, and nothing at all for a customer whose format needs no
    free-text placeholders.

    Each channel is attempted independently and its outcome recorded, so one
    bad channel (bot removed, renamed, archived) cannot stop delivery to the
    others. Never raises for a per-channel failure.

    Returns:
        List of ``{channel_id, channel_name, customer_id, customer_name,
        status, error_message, slack_ts}`` dicts.
    """
    from advisory_notification import build_for_customer, prepare_fields, resolve_customer

    groups = normalize_targets(targets)
    if not groups:
        return []

    pdf_path = advisory.get("pdf_path") or ""
    pdf_filename = advisory.get("pdf_filename") or os.path.basename(pdf_path)

    if not pdf_path or not os.path.isfile(pdf_path):
        error = f"Advisory PDF not found on disk: {pdf_path or '(no path)'}"
        logger.warning(error)
        return [_failure(g, c, error) for g in groups for c in g["channels"]]

    try:
        client = _get_client()
    except Exception as e:
        return [_failure(g, c, str(e)) for g in groups for c in g["channels"]]

    # Customer-independent, so extracted once no matter how many recipients.
    fields, used_llm, markdown_text = prepare_fields(advisory)

    results = []
    for group in groups:
        customer = None
        if group.get("customer_id"):
            try:
                from database import get_customer

                customer = get_customer(group["customer_id"])
            except Exception as e:
                logger.warning("Could not load customer %s: %s", group["customer_id"], e)
        if customer is None and not group.get("customer_name"):
            customer = resolve_customer(advisory)

        try:
            message = build_for_customer(
                advisory, fields, customer=customer, article_url=article_url,
                markdown_text=markdown_text, use_llm=used_llm,
            )
        except Exception as e:
            logger.exception("Notification build failed for %s", group.get("customer_name"))
            results.extend(_failure(group, c, f"Message build failed: {e}")
                           for c in group["channels"])
            continue

        for channel in group["channels"]:
            try:
                resp = client.files_upload_v2(
                    channel=channel["id"],
                    file=pdf_path,
                    filename=pdf_filename,
                    title=advisory.get("title") or pdf_filename,
                    initial_comment=message,
                )
                results.append({
                    "channel_id": channel["id"],
                    "channel_name": channel.get("name"),
                    "customer_id": group.get("customer_id"),
                    "customer_name": group.get("customer_name"),
                    "status": "sent",
                    "error_message": None,
                    "slack_ts": _share_timestamp(resp, channel["id"]),
                })
                logger.info(
                    "Advisory %s sent to %s for %s",
                    pdf_filename, channel["id"], group.get("customer_name") or "(no customer)",
                )
            except Exception as e:
                logger.warning("Slack delivery to %s failed: %s", channel["id"], e)
                results.append(_failure(group, channel, str(e)))

    return results
