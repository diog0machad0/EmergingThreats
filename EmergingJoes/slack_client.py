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


def distribute_advisory(advisory, channel_ids, article_url=None):
    """Upload an advisory PDF with a crafted message to each channel.

    Each channel is attempted independently and its outcome recorded, so one
    bad channel (bot removed, renamed, archived) cannot stop delivery to the
    others. Never raises for a per-channel failure.

    Returns:
        List of ``{channel_id, status, error_message, slack_ts}`` dicts where
        ``status`` is ``"sent"`` or ``"failed"``.
    """
    results = []
    channel_ids = [c for c in (channel_ids or []) if c]
    if not channel_ids:
        return results

    pdf_path = advisory.get("pdf_path") or ""
    pdf_filename = advisory.get("pdf_filename") or os.path.basename(pdf_path)

    if not pdf_path or not os.path.isfile(pdf_path):
        error = f"Advisory PDF not found on disk: {pdf_path or '(no path)'}"
        logger.warning(error)
        return [
            {"channel_id": cid, "status": "failed",
             "error_message": error, "slack_ts": None}
            for cid in channel_ids
        ]

    try:
        client = _get_client()
    except Exception as e:
        return [
            {"channel_id": cid, "status": "failed",
             "error_message": str(e), "slack_ts": None}
            for cid in channel_ids
        ]

    # Built once, before the loop: the notification costs an LLM call and is
    # identical for every channel.
    message = build_advisory_message(advisory, article_url)

    for channel_id in channel_ids:
        try:
            resp = client.files_upload_v2(
                channel=channel_id,
                file=pdf_path,
                filename=pdf_filename,
                title=advisory.get("title") or pdf_filename,
                initial_comment=message,
            )
            results.append({
                "channel_id": channel_id,
                "status": "sent",
                "error_message": None,
                "slack_ts": _share_timestamp(resp, channel_id),
            })
            logger.info(f"Advisory {pdf_filename} sent to Slack channel {channel_id}")
        except Exception as e:
            logger.warning(f"Slack delivery to {channel_id} failed: {e}")
            results.append({
                "channel_id": channel_id,
                "status": "failed",
                "error_message": str(e),
                "slack_ts": None,
            })

    return results
