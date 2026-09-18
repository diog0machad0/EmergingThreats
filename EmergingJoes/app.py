import json
import logging
import os
import socket
import webbrowser
import threading

from flask import Flask, jsonify, render_template, request, send_from_directory

from config import load_config, save_config
from cost_tracker import cost_tracker, _lookup_pricing
from database import (
    _compute_category_hash,
    article_exists,
    clear_articles_before_days,
    clear_database,
    delete_article_summary,
    get_article,
    delete_failed_summaries,
    get_articles,
    get_articles_for_category,
    get_available_tags,
    get_categorized_articles,
    get_category_insight,
    get_connection,
    get_embedding_stats,
    get_failure_articles,
    get_ingested_articles,
    get_sources,
    get_customers,
    get_customer,
    create_customer,
    update_customer,
    delete_customer,
    get_emerging_threats,
    get_emerging_threat_article,
    set_emerging_threat_triage,
    get_vulnerability_threats,
    get_vulnerability_article,
    set_vulnerability_triage,
    save_advisory,
    get_advisories,
    get_advisory,
    save_advisory_distribution,
    get_advisory_distributions,
    get_customers_for_cve,
    backfill_advisories_from_scriba,
    get_apt_groups_from_summaries,
    get_apt_group_detail,
    get_apt_ioc_exports,
    get_summarized_articles_without_threat_analysis,
    get_stats,
    get_subcategories,
    get_trend_analyses,
    init_db,
    insert_article,
    reset_scrape_failed_articles,
    save_category_insight,
    update_article_tags,
    upsert_source,
)
from scheduler import (
    abort_pipeline,
    approve_cost,
    decline_cost,
    dismiss_actual_cost,
    get_actual_cost,
    get_cost_estimate,
    get_pipeline_stage,
    is_aborting,
    is_digesting,
    is_embedding_only,
    is_refreshing,
    reschedule_digest,
    start_scheduler,
    trigger_embed,
    trigger_manual_refresh,
    trigger_process_pending,
    trigger_send_digest,
)

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
)

logger = logging.getLogger(__name__)

app = Flask(__name__)


# === Page Routes ===

@app.route("/")
def index():
    """Render the main dashboard page."""
    return render_template("index.html")


@app.route("/article/<int:article_id>")
def article_detail(article_id):
    """Render the article detail page.

    Parses JSON ``tags`` and ``key_points`` fields for the template.

    Args:
        article_id: The article's integer ID from the URL path.

    Returns:
        Rendered HTML, or a 404 response if the article is not found.
    """
    article = get_article(article_id)
    if not article:
        return "Article not found", 404

    # Parse JSON fields for template
    try:
        article["tags"] = json.loads(article.get("tags") or "[]")
    except (json.JSONDecodeError, TypeError):
        article["tags"] = []
    try:
        article["key_points"] = json.loads(article.get("key_points") or "[]")
    except (json.JSONDecodeError, TypeError):
        article["key_points"] = []

    return render_template("article.html", article=article)


@app.route("/settings")
def settings_page():
    """Render the settings configuration page."""
    config = load_config()
    sources = get_sources()
    source_map = {s["url"]: s for s in sources}
    return render_template("settings.html", config=config, source_map=source_map)


@app.route("/intelligence")
def intelligence_page():
    """Render the intelligence search and chat page."""
    return render_template("intelligence.html")


@app.route("/feeds")
def feeds_page():
    """Render the raw ingested feeds listing page."""
    return render_template("feeds.html")


@app.route("/emerging-threats")
def emerging_threats_page():
    """Render the emerging threats dashboard."""
    return render_template("emerging_threats.html")


@app.route("/customers")
def customers_page():
    """Render the customers management page."""
    return render_template("customers.html")


@app.route("/apt")
def apt_page():
    """Render the APT groups dashboard."""
    return render_template("apt.html")


# === API Routes ===

@app.route("/api/articles")
def api_articles():
    """Return a paginated JSON list of articles.

    Query params:
        source_id: Filter by source ID.
        search: Full-text search substring.
        tag: Filter by exact tag.
        page: Page number (default 1).
        limit: Results per page (default 20, max 100).

    Returns:
        JSON array of article objects.
    """
    source_id = request.args.get("source_id", type=int)
    search = request.args.get("search", "").strip() or None
    tag = request.args.get("tag", "").strip() or None
    page = request.args.get("page", 1, type=int)
    limit = request.args.get("limit", 20, type=int)
    limit = min(limit, 100)

    articles = get_articles(source_id=source_id, search=search, tag=tag, page=page, limit=limit)
    return jsonify(articles)


@app.route("/api/ingested")
def api_ingested():
    """Return paginated raw ingested feed articles.

    Query params:
        source_id: Filter by source ID.
        search: Substring search in title, URL, or source name.
        page: Page number (default 1).
        limit: Results per page (default 50, max 100).
    """
    source_id = request.args.get("source_id", type=int)
    search = request.args.get("search", "").strip() or None
    page = request.args.get("page", 1, type=int)
    limit = min(request.args.get("limit", 50, type=int), 100)

    articles, total = get_ingested_articles(
        page=page, limit=limit, source_id=source_id, search=search
    )
    return jsonify({"articles": articles, "total": total, "page": page, "limit": limit})


@app.route("/api/customers", methods=["GET", "POST"])
def api_customers():
    """List or create customers."""
    if request.method == "GET":
        search = request.args.get("search", "").strip() or None
        return jsonify(get_customers(search=search))

    data = request.get_json(silent=True) or {}
    name = (data.get("name") or "").strip()
    business = (data.get("business") or "").strip()
    country = (data.get("country") or "").strip()
    if not name or not business or not country:
        return jsonify({"error": "name, business, and country are required"}), 400

    affiliates = data.get("known_affiliates") or []
    tech_stack = data.get("known_tech_stack") or []
    if isinstance(affiliates, str):
        affiliates = [s.strip() for s in affiliates.split("\n") if s.strip()]
    if isinstance(tech_stack, str):
        tech_stack = [s.strip() for s in tech_stack.split("\n") if s.strip()]

    try:
        customer = create_customer(name, business, country, affiliates, tech_stack)
        return jsonify(customer), 201
    except Exception as e:
        if "UNIQUE" in str(e):
            return jsonify({"error": "A customer with this name already exists"}), 409
        raise


@app.route("/api/customers/<int:customer_id>", methods=["GET", "PUT", "DELETE"])
def api_customer(customer_id):
    """Retrieve, update, or delete a single customer."""
    if request.method == "GET":
        customer = get_customer(customer_id)
        if not customer:
            return jsonify({"error": "Customer not found"}), 404
        return jsonify(customer)

    if request.method == "DELETE":
        if not delete_customer(customer_id):
            return jsonify({"error": "Customer not found"}), 404
        return jsonify({"status": "ok"})

    data = request.get_json(silent=True) or {}
    name = (data.get("name") or "").strip()
    business = (data.get("business") or "").strip()
    country = (data.get("country") or "").strip()
    if not name or not business or not country:
        return jsonify({"error": "name, business, and country are required"}), 400

    affiliates = data.get("known_affiliates") or []
    tech_stack = data.get("known_tech_stack") or []
    if isinstance(affiliates, str):
        affiliates = [s.strip() for s in affiliates.split("\n") if s.strip()]
    if isinstance(tech_stack, str):
        tech_stack = [s.strip() for s in tech_stack.split("\n") if s.strip()]

    try:
        if not update_customer(customer_id, name, business, country, affiliates, tech_stack):
            return jsonify({"error": "Customer not found"}), 404
        return jsonify(get_customer(customer_id))
    except Exception as e:
        if "UNIQUE" in str(e):
            return jsonify({"error": "A customer with this name already exists"}), 409
        raise


@app.route("/api/emerging-threats")
def api_emerging_threats():
    """Return customer-matched threat intelligence articles (analyst queue).

    Query: triage_status=pending|triaged|all (default pending).
    """
    customer_id = request.args.get("customer_id", type=int)
    page = request.args.get("page", 1, type=int)
    limit = min(request.args.get("limit", 20, type=int), 50)
    triage_status = (request.args.get("triage_status") or "pending").strip().lower()
    if triage_status not in ("pending", "triaged", "all"):
        triage_status = "pending"

    rows, total = get_emerging_threats(
        customer_id=customer_id, page=page, limit=limit, triage_status=triage_status,
    )
    return jsonify({
        "threats": rows,
        "total": total,
        "page": page,
        "limit": limit,
        "triage_status": triage_status,
    })


@app.route("/api/emerging-threats/<int:article_id>")
def api_emerging_threat_detail(article_id):
    """Return threat-intelligence hits for one article (detail / advisory view)."""
    row = get_emerging_threat_article(article_id)
    if not row:
        return jsonify({"error": "Not found"}), 404
    return jsonify(row)


@app.route("/api/emerging-threats/advisory", methods=["POST"])
def api_create_ti_advisory():
    """Generate Scriba advisory PDF for a customer-matched TI article (no CVE required)."""
    from advisory_generator import create_threat_intelligence_advisory

    data = request.get_json(silent=True) or {}
    article_id = data.get("article_id")
    customer_id = data.get("customer_id")
    customer_name = (data.get("customer_name") or "").strip() or None
    match_evidence = (data.get("match_evidence") or "").strip() or None
    matched_tech = data.get("matched_tech")
    matched_affiliates = data.get("matched_affiliates")
    match_dimensions = data.get("match_dimensions")
    distribution_outlook = (data.get("distribution_outlook") or "").strip() or None

    if not article_id:
        return jsonify({"error": "article_id is required"}), 400

    article = get_article(article_id)
    if not article:
        return jsonify({"error": "Article not found"}), 404

    detail = get_emerging_threat_article(article_id)
    hit = None
    if detail and detail.get("hits"):
        if customer_id is not None:
            try:
                cid = int(customer_id)
            except (TypeError, ValueError):
                cid = None
            if cid is not None:
                hit = next(
                    (h for h in detail["hits"] if h.get("customer_id") == cid),
                    None,
                )
        if not hit:
            hit = detail["hits"][0]
        if hit:
            customer_name = customer_name or hit.get("customer_name")
            match_evidence = match_evidence or hit.get("match_evidence")
            matched_tech = matched_tech if matched_tech is not None else hit.get("matched_tech")
            matched_affiliates = (
                matched_affiliates
                if matched_affiliates is not None
                else hit.get("matched_affiliates")
            )
            match_dimensions = (
                match_dimensions
                if match_dimensions is not None
                else hit.get("match_dimensions")
            )
            distribution_outlook = distribution_outlook or hit.get("distribution_outlook")
            if customer_id is None and hit.get("customer_id") is not None:
                customer_id = hit.get("customer_id")

    try:
        result = create_threat_intelligence_advisory(
            article_id=article_id,
            article_title=article.get("title") or "",
            article_content=article.get("content_raw") or "",
            article_url=article.get("url"),
            customer_name=customer_name,
            match_evidence=match_evidence,
            matched_tech=matched_tech,
            matched_affiliates=matched_affiliates,
            match_dimensions=match_dimensions,
            distribution_outlook=distribution_outlook,
            topic=article.get("title") or "threat-intelligence",
        )
        title = article.get("title") or result["stem"]
        try:
            from pathlib import Path
            md = Path(result["markdown_path"])
            if md.is_file():
                for line in md.read_text(encoding="utf-8", errors="ignore").splitlines():
                    if line.startswith("# "):
                        title = line[2:].strip()
                        break
        except OSError:
            pass

        tech_label = None
        if isinstance(matched_tech, list) and matched_tech:
            tech_label = ", ".join(str(t) for t in matched_tech[:5])
        elif isinstance(matched_tech, str) and matched_tech.strip():
            tech_label = matched_tech.strip()

        record = save_advisory(
            stem=result["stem"],
            pdf_filename=result["pdf_filename"],
            title=title,
            kind="threat_intelligence",
            article_id=article_id,
            cve_id=None,
            technology=tech_label,
            markdown_path=result["markdown_path"],
            pdf_path=result["pdf_path"],
            customer_id=int(customer_id) if customer_id else None,
            customer_name=customer_name,
        )
        return jsonify({
            "status": "ok",
            "message": "Threat intelligence advisory created successfully.",
            "stem": result["stem"],
            "markdown_path": result["markdown_path"],
            "pdf_path": result["pdf_path"],
            "pdf_url": f"/api/advisories/pdf/{result['pdf_filename']}",
            "advisory": record,
        })
    except Exception as e:
        logger.exception("TI advisory generation failed")
        return jsonify({"error": str(e)}), 500


@app.route("/api/emerging-threats/<int:article_id>/triage", methods=["POST"])
def api_emerging_threat_triage(article_id):
    """Mark a TI match as triaged (or restore to pending). Does not delete analysis."""
    data = request.get_json(silent=True) or {}
    status = (data.get("triage_status") or data.get("status") or "triaged").strip().lower()
    try:
        row = set_emerging_threat_triage(article_id, status)
    except ValueError as e:
        return jsonify({"error": str(e)}), 400
    if not row:
        return jsonify({"error": "Not found"}), 404
    return jsonify({"status": "ok", **row})


@app.route("/api/emerging-threats/analyze-missing", methods=["POST"])
def api_analyze_missing_threats():
    """Backfill emerging threat analysis for summarized articles missing it."""
    from emerging_threats import analyze_missing_threats

    data = request.get_json(silent=True) or {}
    limit = min(int(data.get("limit", 10)), 25)
    processed = analyze_missing_threats(limit=limit)
    return jsonify({"processed": processed})


@app.route("/api/vulnerabilities")
def api_vulnerabilities():
    """Return CVE + customer tech-stack vulnerability hits (analyst queue).

    Query: triage_status=pending|triaged|all (default pending).
    """
    customer_id = request.args.get("customer_id", type=int)
    page = request.args.get("page", 1, type=int)
    limit = min(request.args.get("limit", 20, type=int), 50)
    triage_status = (request.args.get("triage_status") or "pending").strip().lower()
    if triage_status not in ("pending", "triaged", "all"):
        triage_status = "pending"

    rows, total = get_vulnerability_threats(
        customer_id=customer_id, page=page, limit=limit, triage_status=triage_status,
    )
    return jsonify({
        "threats": rows,
        "total": total,
        "page": page,
        "limit": limit,
        "triage_status": triage_status,
    })


@app.route("/api/vulnerabilities/<int:article_id>")
def api_vulnerability_detail(article_id):
    """Return vulnerability hits for one article (detail / advisory view)."""
    row = get_vulnerability_article(article_id)
    if not row:
        return jsonify({"error": "Not found"}), 404
    return jsonify(row)


@app.route("/api/vulnerabilities/<int:article_id>/triage", methods=["POST"])
def api_vulnerability_triage(article_id):
    """Mark a vulnerability match as triaged (or restore to pending). Does not delete analysis."""
    data = request.get_json(silent=True) or {}
    status = (data.get("triage_status") or data.get("status") or "triaged").strip().lower()
    try:
        row = set_vulnerability_triage(article_id, status)
    except ValueError as e:
        return jsonify({"error": str(e)}), 400
    if not row:
        return jsonify({"error": "Not found"}), 404
    return jsonify({"status": "ok", **row})


@app.route("/api/vulnerabilities/analyze-missing", methods=["POST"])
def api_analyze_missing_vulnerabilities():
    from vulnerability_threats import analyze_missing_vulnerabilities

    data = request.get_json(silent=True) or {}
    limit = min(int(data.get("limit", 10)), 25)
    processed = analyze_missing_vulnerabilities(limit=limit)
    return jsonify({"processed": processed})


@app.route("/api/vulnerabilities/advisory", methods=["POST"])
def api_create_advisory():
    """Generate Scriba markdown advisory and PDF for a CVE + customer tech hit."""
    from advisory_generator import create_advisory

    data = request.get_json(silent=True) or {}
    article_id = data.get("article_id")
    cve_id = (data.get("cve_id") or "").strip()
    matched_tech = (data.get("matched_tech") or "").strip()
    customer_id = data.get("customer_id")
    customer_name = (data.get("customer_name") or "").strip() or None

    if not article_id or not cve_id or not matched_tech:
        return jsonify({"error": "article_id, cve_id, and matched_tech are required"}), 400

    article = get_article(article_id)
    if not article:
        return jsonify({"error": "Article not found"}), 404

    try:
        result = create_advisory(
            cve_id=cve_id,
            technology=matched_tech,
            article_title=article.get("title") or "",
            article_content=article.get("content_raw") or "",
        )
        title = f"{cve_id} — {matched_tech}"
        # Prefer first markdown H1 if present
        try:
            from pathlib import Path
            md = Path(result["markdown_path"])
            if md.is_file():
                for line in md.read_text(encoding="utf-8", errors="ignore").splitlines():
                    if line.startswith("# "):
                        title = line[2:].strip()
                        break
        except OSError:
            pass

        record = save_advisory(
            stem=result["stem"],
            pdf_filename=result["pdf_filename"],
            title=title,
            kind="vulnerability",
            article_id=article_id,
            cve_id=cve_id.upper(),
            technology=matched_tech,
            markdown_path=result["markdown_path"],
            pdf_path=result["pdf_path"],
            customer_id=int(customer_id) if customer_id else None,
            customer_name=customer_name,
        )
        return jsonify({
            "status": "ok",
            "message": "Advisory report created successfully.",
            "stem": result["stem"],
            "markdown_path": result["markdown_path"],
            "pdf_path": result["pdf_path"],
            "pdf_url": f"/api/advisories/pdf/{result['pdf_filename']}",
            "advisory": record,
        })
    except Exception as e:
        logger.exception("Advisory generation failed")
        return jsonify({"error": str(e)}), 500


@app.route("/api/advisories")
def api_advisories():
    """List tracked advisories. Query: kind=all|vulnerability|threat_intelligence|general, search, page, limit."""
    kind = (request.args.get("kind") or "all").strip().lower()
    search = (request.args.get("search") or "").strip() or None
    page = request.args.get("page", 1, type=int)
    limit = min(request.args.get("limit", 20, type=int), 100)
    if kind not in ("all", "vulnerability", "threat_intelligence", "general"):
        kind = "all"
    rows, total = get_advisories(kind=kind, search=search, page=page, limit=limit)
    for row in rows:
        row["pdf_url"] = f"/api/advisories/pdf/{row['pdf_filename']}"
    return jsonify({"advisories": rows, "total": total, "page": page, "limit": limit, "kind": kind})


@app.route("/api/advisories/<int:advisory_id>")
def api_advisory_detail(advisory_id):
    row = get_advisory(advisory_id)
    if not row:
        return jsonify({"error": "Not found"}), 404
    row["pdf_url"] = f"/api/advisories/pdf/{row['pdf_filename']}"
    row["distributions"] = get_advisory_distributions(advisory_id)
    return jsonify(row)


@app.route("/api/advisories/<int:advisory_id>/distribute", methods=["POST"])
def api_advisory_distribute(advisory_id):
    """Post an advisory PDF to the Slack channels named in the request body.

    Kept separate from advisory creation so a Slack failure never discards a
    generated advisory, and so the same endpoint can re-send later.
    """
    from slack_client import distribute_advisory, is_slack_configured

    if not is_slack_configured():
        return jsonify({"error": "Slack integration is not configured"}), 400

    advisory = get_advisory(advisory_id)
    if not advisory:
        return jsonify({"error": "Not found"}), 404

    data = request.get_json(silent=True) or {}
    channels = data.get("channels") or []
    if not isinstance(channels, list) or not channels:
        return jsonify({"error": "No channels selected"}), 400

    channel_names = data.get("channel_names") or {}
    if not isinstance(channel_names, dict):
        channel_names = {}

    article_url = None
    if advisory.get("article_id"):
        article = get_article(advisory["article_id"])
        if article:
            article_url = article.get("url")

    # The cross-article customer roll-up is deliberately not in the Slack
    # message: a shared channel would expose which other customers are
    # vulnerable. It stays in the analyst UI, where it belongs.
    try:
        results = distribute_advisory(advisory, channels, article_url)
    except Exception as e:
        logger.exception("Slack distribution failed")
        return jsonify({"error": str(e)}), 500

    for result in results:
        channel_id = result["channel_id"]
        result["channel_name"] = channel_names.get(channel_id)
        save_advisory_distribution(
            advisory_id=advisory_id,
            channel_id=channel_id,
            channel_name=result["channel_name"],
            status=result["status"],
            error_message=result.get("error_message"),
            slack_ts=result.get("slack_ts"),
        )

    sent = sum(1 for r in results if r["status"] == "sent")
    return jsonify({
        "status": "ok",
        "sent": sent,
        "failed": len(results) - sent,
        "results": results,
    })


@app.route("/api/slack/status", methods=["GET", "POST"])
def api_slack_status():
    """Check Slack connectivity and how many channels the bot can post to.

    POST with ``{"token": "..."}`` verifies a token that has been typed into
    Settings but not saved yet; the token is never persisted here.
    """
    from slack_client import list_member_channels, slack_config, test_connection

    data = request.get_json(silent=True) or {}
    token = (data.get("token") or "").strip()

    ok, message = test_connection(token)
    cfg = slack_config()
    channel_count = 0
    if ok:
        try:
            channel_count = len(list_member_channels(token))
        except Exception as e:
            ok = False
            message = f"Authenticated, but channel listing failed: {e}"
    return jsonify({
        "connected": ok,
        "message": message,
        "enabled": cfg["enabled"],
        "channel_count": channel_count,
    })


@app.route("/api/slack/channels")
def api_slack_channels():
    """Channels the bot has been invited to, for the advisory channel picker."""
    from slack_client import is_slack_configured, list_member_channels

    if not is_slack_configured():
        return jsonify({"configured": False, "channels": []})
    try:
        channels = list_member_channels()
    except Exception as e:
        logger.warning(f"Slack channel listing failed: {e}")
        return jsonify({"configured": True, "channels": [], "error": str(e)}), 502
    return jsonify({"configured": True, "channels": channels})


@app.route("/api/cve/<cve_id>/customers")
def api_cve_customers(cve_id):
    """Every customer this CVE affects across the corpus, not just one article."""
    customers = get_customers_for_cve(cve_id)
    return jsonify({
        "cve_id": cve_id.strip().upper(),
        "customers": customers,
        "total": len(customers),
    })


@app.route("/api/advisories/pdf/<path:filename>")
def api_advisory_pdf(filename):
    """Serve generated advisory PDF from Scriba output directory."""
    from advisory_generator import OUTPUT_DIR

    if ".." in filename or filename.startswith("/"):
        return jsonify({"error": "Invalid filename"}), 400
    pdf_dir = OUTPUT_DIR.resolve()
    return send_from_directory(pdf_dir, filename, mimetype="application/pdf")


@app.route("/api/apt-groups")
def api_apt_groups():
    """Return tracked APT groups aggregated with alias consolidation."""
    search = (request.args.get("search") or "").strip().lower()
    groups = get_apt_groups_from_summaries()
    if search:
        groups = [
            g for g in groups
            if search in g["display_name"].lower()
            or search in g["canonical_tag"]
            or any(search in a.lower() for a in g.get("aliases") or [])
            or any(search in t for t in g.get("matched_tags") or [])
        ]
    return jsonify({"groups": groups, "total": len(groups)})


@app.route("/api/apt-groups/<canonical_tag>")
def api_apt_group_detail(canonical_tag):
    """Return articles and MISP exports for one canonical APT group."""
    detail = get_apt_group_detail(canonical_tag)
    if not detail:
        return jsonify({"error": "APT group not found"}), 404
    return jsonify(detail)


@app.route("/api/misp/status")
def api_misp_status():
    """Check MISP connectivity."""
    from misp_client import misp_config, test_connection

    ok, message = test_connection()
    cfg = misp_config()
    return jsonify({
        "connected": ok,
        "message": message,
        "enabled": cfg["enabled"],
        "url": cfg["url"],
    })


@app.route("/api/apt/reprocess-iocs", methods=["POST"])
def api_reprocess_apt_iocs():
    """Backfill APT IOC extraction + MISP export for summarized articles."""
    from apt_ioc_processor import process_apt_iocs_for_article

    data = request.get_json(silent=True) or {}
    limit = min(int(data.get("limit", 10)), 25)
    conn = get_connection()
    rows = conn.execute(
        """
        SELECT a.id, a.title, a.url, a.content_raw, sm.tags, sm.summary_text, s.name as source_name
        FROM articles a
        JOIN summaries sm ON sm.article_id = a.id
        JOIN sources s ON s.id = a.source_id
        LEFT JOIN apt_ioc_exports e ON e.article_id = a.id
        WHERE sm.model_used IS NOT NULL AND sm.model_used != 'failed'
          AND a.content_raw IS NOT NULL AND a.content_raw != ''
          AND e.id IS NULL
        ORDER BY a.fetched_date DESC
        LIMIT ?
        """,
        (limit,),
    ).fetchall()

    processed = 0
    exported = 0
    for row in rows:
        r = dict(row)
        result = process_apt_iocs_for_article(
            article_id=r["id"],
            title=r["title"],
            content=r["content_raw"],
            tags=r["tags"],
            summary_text=r["summary_text"],
            article_url=r["url"],
            source_name=r["source_name"],
        )
        processed += 1
        if result and result.get("status") == "exported":
            exported += 1

    return jsonify({"processed": processed, "exported": exported})


@app.route("/api/articles/failures")
def api_article_failures():
    """Return a paginated list of articles for a given failure type.

    Query params:
        type: 'unsummarized', 'scrape_failed', or 'failed_summaries'
        page: page number (default 1)
        limit: results per page (default 15, max 50)

    Returns:
        JSON with ``articles`` list and ``total`` count.
    """
    failure_type = request.args.get("type", "").strip()
    valid_types = {"unsummarized", "scrape_failed", "failed_summaries"}
    if failure_type not in valid_types:
        return jsonify({"error": "Invalid type"}), 400

    page = request.args.get("page", 1, type=int)
    limit = request.args.get("limit", 15, type=int)
    limit = min(limit, 50)

    result = get_failure_articles(failure_type, page, limit)
    return jsonify(result)


@app.route("/api/articles/reprocess", methods=["POST"])
def api_articles_reprocess():
    """Reprocess a set of articles that failed at some pipeline stage.

    Body JSON:
        article_ids: list of integer article IDs (max 100)
        failure_type: 'unsummarized', 'scrape_failed', or 'failed_summaries'

    Returns:
        JSON with ``status`` of 'started' or 'already_running'.
    """
    data = request.get_json(force=True) or {}
    article_ids = data.get("article_ids", [])
    failure_type = data.get("failure_type", "")

    valid_types = {"unsummarized", "scrape_failed", "failed_summaries"}
    if not article_ids or not isinstance(article_ids, list):
        return jsonify({"error": "article_ids must be a non-empty list"}), 400
    if len(article_ids) > 100:
        return jsonify({"error": "Too many article IDs (max 100)"}), 400
    if failure_type not in valid_types:
        return jsonify({"error": "Invalid failure_type"}), 400

    article_ids = [int(i) for i in article_ids]

    if is_refreshing():
        return jsonify({"status": "already_running"}), 409

    if failure_type == "scrape_failed":
        reset_scrape_failed_articles(article_ids)
    elif failure_type == "failed_summaries":
        delete_failed_summaries(article_ids)

    trigger_process_pending(article_ids=article_ids)
    return jsonify({"status": "started"})


@app.route("/api/articles/<int:article_id>")
def api_article(article_id):
    """Return a single article as JSON.

    Args:
        article_id: The article's integer ID from the URL path.

    Returns:
        JSON object with article data, or 404 error.
    """
    article = get_article(article_id)
    if not article:
        return jsonify({"error": "Not found"}), 404
    return jsonify(article)


@app.route("/api/articles/categorized")
def api_articles_categorized():
    """Return articles grouped by threat category as JSON.

    Query params:
        limit: Max articles per category (default 10).
        days: Only include articles from the last N days (0 = all).

    Returns:
        JSON array of category objects with nested article arrays.
    """
    limit = request.args.get("limit", 10, type=int)
    days = request.args.get("days", 0, type=int)
    since_days = days if days > 0 else None
    categories = get_categorized_articles(limit_per_category=limit, since_days=since_days)
    return jsonify(categories)


@app.route("/api/sources")
def api_sources():
    """Return all feed sources as JSON."""
    sources = get_sources()
    return jsonify(sources)


@app.route("/api/stats")
def api_stats():
    """Return aggregate dashboard statistics as JSON."""
    from llm_client import has_api_key
    stats = get_stats()
    stats["has_api_key"] = has_api_key()
    cfg = load_config()
    stats["email_mode"] = cfg.get("email_mode", "per_article")
    stats["digest_period"] = cfg.get("digest_period", "day")
    return jsonify(stats)


@app.route("/api/refresh", methods=["POST"])
def api_refresh():
    """Trigger a manual pipeline refresh.

    Request body (JSON):
        since_last_fetch: If true, use incremental fetch mode.
        days: Lookback period in days (default 1, max 365).

    Returns:
        JSON with ``status`` (``"started"`` or ``"already_running"``).
    """
    data = request.get_json(silent=True) or {}
    since_last_fetch = bool(data.get("since_last_fetch", False))
    days = data.get("days", 1)
    try:
        days = max(1, min(int(days), 365))
    except (ValueError, TypeError):
        days = 1
    started = trigger_manual_refresh(lookback_days=days, since_last_fetch=since_last_fetch)
    if started:
        return jsonify({"status": "started", "days": days, "since_last_fetch": since_last_fetch})
    return jsonify({"status": "already_running"})


@app.route("/api/clear-db", methods=["POST"])
def api_clear_db():
    """Clear articles from the database, optionally limited by age.

    Request body (JSON, optional):
        days: If provided and > 0, delete only articles fetched more
              than this many days ago. If 0 or absent, clear everything.

    Returns:
        JSON with ``status`` (``"ok"`` or ``"error"``), and ``deleted``
        count when using the ``days`` filter. Returns 409 if a refresh
        is currently running.
    """
    if is_refreshing():
        return jsonify({"status": "error", "error": "Cannot clear while refresh is running"}), 409
    try:
        data = request.get_json(silent=True) or {}
        days = data.get("days", 0)
        try:
            days = int(days)
        except (ValueError, TypeError):
            days = 0

        if days > 0:
            deleted = clear_articles_before_days(days)
            return jsonify({"status": "ok", "deleted": deleted})
        else:
            clear_database()
            return jsonify({"status": "ok"})
    except Exception as e:
        return jsonify({"status": "error", "error": str(e)}), 500


@app.route("/api/refresh-status")
def api_refresh_status():
    """Check pipeline refresh status including cost confirmation state.

    Returns:
        JSON with ``is_refreshing``, ``is_embedding``, ``is_aborting``,
        ``is_digesting``, ``stage``, ``cost_estimate``, ``actual_cost``.
    """
    return jsonify({
        "is_refreshing": is_refreshing() or is_embedding_only(),
        "is_embedding": is_embedding_only(),
        "is_aborting": is_aborting(),
        "is_digesting": is_digesting(),
        "stage": get_pipeline_stage(),
        "cost_estimate": get_cost_estimate(),
        "actual_cost": get_actual_cost(),
    })


@app.route("/api/send-digest", methods=["POST"])
def api_send_digest():
    """Trigger the digest email job immediately.

    Returns:
        JSON with ``status`` (``"started"`` or ``"error"``).
    """
    ok = trigger_send_digest()
    if ok:
        return jsonify({"status": "started"})
    return jsonify({"status": "error", "error": "Pipeline busy or digest already running"}), 409


@app.route("/api/abort", methods=["POST"])
def api_abort():
    """Request the running pipeline or embed job to stop between stages.

    Returns:
        JSON with ``status`` (``"ok"``).
    """
    abort_pipeline()
    return jsonify({"status": "ok"})


@app.route("/api/embed", methods=["POST"])
def api_embed():
    """Trigger embedding generation for all pending summarized articles.

    Returns:
        JSON with ``status`` (``"started"`` or ``"already_running"`` or ``"error"``).
    """
    if is_refreshing():
        return jsonify({"status": "error", "error": "Cannot embed while refresh is running"})
    if is_embedding_only():
        return jsonify({"status": "already_running"})
    started = trigger_embed()
    if started:
        return jsonify({"status": "started"})
    return jsonify({"status": "already_running"})


@app.route("/api/articles/<int:article_id>/summary", methods=["DELETE"])
def api_delete_article_summary(article_id):
    """Delete all database artifacts for a single article.

    Removes the article row, its summary, embeddings, and correlations so
    it will be treated as brand-new on the next feed fetch.

    Args:
        article_id: The article's integer ID from the URL path.

    Returns:
        JSON with ``status`` (``"ok"`` or ``"error"``).
    """
    try:
        delete_article_summary(article_id)
        return jsonify({"status": "ok"})
    except Exception as e:
        return jsonify({"status": "error", "error": str(e)}), 500


@app.route("/api/available-tags")
def api_available_tags():
    """Return the predefined tag list for the article tag editor.

    Returns:
        JSON with ``categories`` and ``entities`` lists.
    """
    return jsonify(get_available_tags())


@app.route("/api/articles/<int:article_id>/tags", methods=["PATCH"])
def api_update_article_tags(article_id):
    """Update the tags for a single article.

    Args:
        article_id: The article's integer ID from the URL path.

    Returns:
        JSON with ``status`` and updated ``tags`` on success, or
        ``status``/``error`` on failure.
    """
    data = request.get_json(silent=True) or {}
    tags = data.get("tags")
    if not isinstance(tags, list) or not all(isinstance(t, str) for t in tags):
        return jsonify({"status": "error", "error": "tags must be a list of strings"}), 400
    tags = [t.strip().lower() for t in tags if t.strip()]
    try:
        update_article_tags(article_id, tags)
        return jsonify({"status": "ok", "tags": tags})
    except ValueError as e:
        return jsonify({"status": "error", "error": str(e)}), 404
    except Exception as e:
        return jsonify({"status": "error", "error": str(e)}), 500


@app.route("/api/ingest-urls", methods=["POST"])
def api_ingest_urls():
    """Ingest a list of article URLs for one-time processing.

    Inserts each URL into the database under a ``Manual`` source (if
    not already present), then triggers scrape → summarize → embed in
    the background. Requires that no other pipeline job is running.

    Request body (JSON):
        urls: List of article URL strings (http/https only).

    Returns:
        JSON with ``status``, ``inserted`` count, and ``skipped`` count.
    """
    if is_refreshing():
        return jsonify({"status": "error", "error": "Cannot ingest while refresh is running"}), 409

    data = request.get_json(silent=True) or {}
    raw_urls = data.get("urls", [])

    valid_urls = [
        u.strip() for u in raw_urls
        if isinstance(u, str) and u.strip().startswith(("http://", "https://"))
    ]
    if not valid_urls:
        return jsonify({"status": "error", "error": "No valid URLs provided"}), 400

    source_id = upsert_source("Manual", "manual://ingested", enabled=True)

    inserted = 0
    skipped = 0
    inserted_ids = []
    for url in valid_urls:
        if article_exists(url):
            skipped += 1
            continue
        import os as _os
        title = _os.path.basename(url.rstrip("/")) or url
        art_id = insert_article(source_id, title, url)
        if art_id:
            inserted += 1
            inserted_ids.append(art_id)

    if inserted > 0:
        started = trigger_process_pending(article_ids=inserted_ids)
        if not started:
            return jsonify({
                "status": "ok",
                "inserted": inserted,
                "skipped": skipped,
                "note": "URLs inserted; processing will start on next refresh (pipeline busy)",
            })

    return jsonify({"status": "ok", "inserted": inserted, "skipped": skipped})


@app.route("/api/cost/approve", methods=["POST"])
def api_cost_approve():
    """Approve the pending cost estimate to proceed with summarization."""
    approve_cost()
    return jsonify({"status": "ok"})


@app.route("/api/cost/decline", methods=["POST"])
def api_cost_decline():
    """Decline the pending cost estimate to skip summarization."""
    decline_cost()
    return jsonify({"status": "ok"})


@app.route("/api/cost/dismiss", methods=["POST"])
def api_cost_dismiss():
    """Dismiss the actual cost dialog after summarization."""
    dismiss_actual_cost()
    return jsonify({"status": "ok"})


@app.route("/api/settings", methods=["POST"])
def api_settings():
    """Update application settings.

    Accepts a JSON body with any subset of config keys: ``openai_api_key``,
    ``malpedia_api_key``, ``openai_model``, ``fetch_interval_minutes``,
    ``feeds``. Syncs feed sources to the database after saving.

    Returns:
        JSON with ``status`` (``"ok"`` or ``"error"``).
    """
    try:
        data = request.get_json()
        config = load_config()

        if "llm_provider" in data:
            provider = (data["llm_provider"] or "openai").strip().lower()
            if provider not in ("openai", "anthropic", "openrouter"):
                provider = "openai"
            config["llm_provider"] = provider
        if "openai_api_key" in data:
            config["openai_api_key"] = data["openai_api_key"]
        if "openai_model" in data:
            config["openai_model"] = data["openai_model"]
        if "anthropic_api_key" in data:
            config["anthropic_api_key"] = data["anthropic_api_key"]
        if "anthropic_model" in data:
            config["anthropic_model"] = data["anthropic_model"]
        if "openrouter_api_key" in data:
            config["openrouter_api_key"] = data["openrouter_api_key"]
        if "openrouter_model" in data:
            config["openrouter_model"] = data["openrouter_model"]
        if "malpedia_api_key" in data:
            config["malpedia_api_key"] = data["malpedia_api_key"]
        if "fetch_interval_minutes" in data:
            config["fetch_interval_minutes"] = int(data["fetch_interval_minutes"])
        if "feeds" in data:
            safe_feeds = [
                f for f in data["feeds"]
                if isinstance(f.get("url"), str)
                and (f["url"].startswith("http://") or f["url"].startswith("https://"))
            ]
            config["feeds"] = safe_feeds

        # Email notification settings
        for key in ("smtp_host", "smtp_username", "smtp_password", "notification_email"):
            if key in data:
                config[key] = data[key]
        if "smtp_port" in data:
            config["smtp_port"] = int(data["smtp_port"])
        if "smtp_use_tls" in data:
            config["smtp_use_tls"] = bool(data["smtp_use_tls"])
        if "email_notifications_enabled" in data:
            config["email_notifications_enabled"] = bool(data["email_notifications_enabled"])
        if "email_mode" in data and data["email_mode"] in ("per_article", "digest"):
            config["email_mode"] = data["email_mode"]
        if "digest_period" in data and data["digest_period"] in ("day", "week"):
            config["digest_period"] = data["digest_period"]

        for key in ("misp_url", "misp_api_key", "misp_org_name"):
            if key in data:
                config[key] = data[key]
        if "misp_enabled" in data:
            config["misp_enabled"] = bool(data["misp_enabled"])
        if "misp_verify_ssl" in data:
            config["misp_verify_ssl"] = bool(data["misp_verify_ssl"])

        if "slack_bot_token" in data:
            # Tokens are usually pasted, and a trailing space or newline would
            # otherwise produce a confusing invalid_auth.
            config["slack_bot_token"] = (data["slack_bot_token"] or "").strip()
        if "slack_enabled" in data:
            config["slack_enabled"] = bool(data["slack_enabled"])

        save_config(config)
        reschedule_digest()

        # Sync sources to database
        for feed in config.get("feeds", []):
            upsert_source(feed["name"], feed["url"], feed.get("enabled", True))

        return jsonify({"status": "ok"})
    except Exception as e:
        return jsonify({"status": "error", "error": str(e)}), 400


@app.route("/api/test-key", methods=["POST"])
def api_test_key():
    """Validate an OpenAI API key by listing models.

    Request body (JSON):
        api_key: The OpenAI API key to test.

    Returns:
        JSON with ``valid`` boolean and optional ``error`` string.
    """
    data = request.get_json()
    api_key = data.get("api_key", "").strip()
    if not api_key:
        return jsonify({"valid": False, "error": "No API key provided"})

    try:
        from openai import OpenAI

        client = OpenAI(api_key=api_key)
        client.models.list()
        return jsonify({"valid": True})
    except Exception as e:
        return jsonify({"valid": False, "error": str(e)})


@app.route("/api/test-anthropic-key", methods=["POST"])
def api_test_anthropic_key():
    """Validate an Anthropic API key by sending a minimal message.

    Request body (JSON):
        api_key: The Anthropic API key to test.

    Returns:
        JSON with ``valid`` boolean and optional ``error`` string.
    """
    data = request.get_json()
    api_key = data.get("api_key", "").strip()
    if not api_key:
        return jsonify({"valid": False, "error": "No API key provided"})

    try:
        import anthropic

        client = anthropic.Anthropic(api_key=api_key)
        client.messages.create(
            model="claude-haiku-4-5-20251001",
            max_tokens=10,
            messages=[{"role": "user", "content": "Hi"}],
        )
        return jsonify({"valid": True})
    except Exception as e:
        return jsonify({"valid": False, "error": str(e)})


@app.route("/api/test-openrouter-key", methods=["POST"])
def api_test_openrouter_key():
    """Validate an OpenRouter API key with a minimal chat completion.

    Request body (JSON):
        api_key: The OpenRouter API key to test.
        model: Optional model id (defaults to a free model).

    Returns:
        JSON with ``valid`` boolean and optional ``error`` string.
    """
    data = request.get_json() or {}
    api_key = data.get("api_key", "").strip()
    model = (data.get("model") or "meta-llama/llama-3.3-70b-instruct:free").strip()
    if not api_key:
        return jsonify({"valid": False, "error": "No API key provided"})

    try:
        from openai import OpenAI

        client = OpenAI(
            api_key=api_key,
            base_url="https://openrouter.ai/api/v1",
            default_headers={
                "HTTP-Referer": "https://joes.local",
                "X-Title": "JOES Threat Intelligence",
            },
        )
        client.chat.completions.create(
            model=model,
            messages=[{"role": "user", "content": "Hi"}],
            max_tokens=5,
        )
        return jsonify({"valid": True})
    except Exception as e:
        return jsonify({"valid": False, "error": str(e)})


@app.route("/api/test-malpedia-key", methods=["POST"])
def api_test_malpedia_key():
    """Validate a Malpedia API key by hitting the check endpoint.

    Request body (JSON):
        api_key: The Malpedia API key to test.

    Returns:
        JSON with ``valid`` boolean and optional ``error`` string.
    """
    data = request.get_json()
    api_key = data.get("api_key", "").strip()
    if not api_key:
        return jsonify({"valid": False, "error": "No API key provided"})

    try:
        import requests as req

        resp = req.get(
            "https://malpedia.caad.fkie.fraunhofer.de/api/check/apikey",
            headers={"Authorization": f"APIToken {api_key}"},
            timeout=15,
        )
        if resp.status_code == 200:
            return jsonify({"valid": True})
        return jsonify({"valid": False, "error": f"HTTP {resp.status_code}"})
    except Exception as e:
        return jsonify({"valid": False, "error": str(e)})


@app.route("/api/test-email", methods=["POST"])
def api_test_email():
    """Send a test email notification.

    Returns:
        JSON with ``success`` boolean and optional ``error`` string.
    """
    from notifier import send_test_email

    data = request.get_json(silent=True) or {}
    smtp_cfg = None
    if data.get("smtp_host"):
        smtp_cfg = {
            "host": data["smtp_host"],
            "port": int(data.get("smtp_port", 587)),
            "username": data.get("smtp_username", ""),
            "password": data.get("smtp_password", ""),
            "use_tls": bool(data.get("smtp_use_tls", True)),
            "recipient": data.get("notification_email", ""),
        }

    success, error = send_test_email(smtp_cfg=smtp_cfg)
    return jsonify({"success": success, "error": error})


@app.route("/api/report", methods=["POST"])
def api_report():
    cfg = load_config()
    token = cfg.get("report_token", "").strip()
    data = request.get_json(silent=True) or {}

    # Optional token check — skip if no token is configured
    if token and data.get("token") != token:
        return jsonify({"error": "Unauthorized"}), 403

    report_type = data.get("type", "Unknown")
    identifier  = data.get("identifier", "")
    llm_content = data.get("llm_content", "")
    metadata    = data.get("metadata", {})
    user_note   = data.get("user_note", "")

    from notifier import send_report_email
    ok, err = send_report_email(report_type, identifier, llm_content, metadata, user_note)
    if ok:
        return jsonify({"ok": True})
    return jsonify({"ok": False, "error": err}), 500


@app.route("/api/subcategories")
def api_subcategories():
    """Return sub-categories for a broad threat category as JSON.

    Query params:
        category: The broad category name (required).
        limit: Max articles per sub-category (default 50).
        days: Only include articles from the last N days (0 = all).

    Returns:
        JSON array of sub-category objects.
    """
    category = request.args.get("category", "").strip()
    if not category:
        return jsonify([])
    limit = request.args.get("limit", 50, type=int)
    days = request.args.get("days", 0, type=int)
    since_days = days if days > 0 else None
    subs = get_subcategories(category, limit_per_sub=limit, since_days=since_days)
    return jsonify(subs)


@app.route("/api/insight-estimate")
def api_insight_estimate():
    """Return a cost estimate before running a Trend Analysis or Forecast.

    Query params:
        category: The broad category name (required).
        subcategory: Optional entity tag for narrower focus.
        days: Only include articles from the last N days (0 = all).
        type: ``"trend"`` or ``"forecast"`` (default ``"forecast"``).

    Returns:
        JSON with ``article_count``, ``estimated_cost``, ``model``,
        and for trend: ``n_quarters``, ``n_years``.
    """
    from llm_client import get_model_name, has_api_key
    from summarizer import estimate_insight_cost, estimate_trend_cost

    category = request.args.get("category", "").strip()
    if not category:
        return jsonify({"error": "missing category parameter"}), 400

    subcategory = request.args.get("subcategory", "").strip() or None
    days = request.args.get("days", 0, type=int)
    since_days = days if days > 0 else None
    insight_type = request.args.get("type", "forecast")

    if not has_api_key():
        return jsonify({"error": "api_key_missing"})

    articles = get_articles_for_category(category, subcategory_tag=subcategory, since_days=since_days)
    if len(articles) < 3:
        return jsonify({"error": "insufficient_data", "article_count": len(articles)})

    model = get_model_name()

    if insight_type == "trend":
        estimated_cost, n_quarters, n_years = estimate_trend_cost(articles, model)
        return jsonify({
            "article_count": len(articles),
            "estimated_cost": estimated_cost,
            "model": model,
            "n_quarters": n_quarters,
            "n_years": n_years,
        })
    else:
        estimated_cost = estimate_insight_cost(len(articles), model)
        return jsonify({
            "article_count": len(articles),
            "estimated_cost": estimated_cost,
            "model": model,
        })


@app.route("/api/trend-analysis")
def api_trend_analysis():
    """Generate or return cached quarterly and yearly trend analyses for a category.

    Query params:
        category: The broad category name (required).
        subcategory: Optional entity tag for narrower focus.

    Returns:
        JSON with ``quarterly`` list, ``yearly`` list, ``model_used``,
        or an error object.
    """
    from summarizer import generate_trend_analysis

    category = request.args.get("category", "").strip()
    if not category:
        return jsonify({"error": "missing category parameter"}), 400

    subcategory = request.args.get("subcategory", "").strip() or None
    days = request.args.get("days", 0, type=int)
    since_days = days if days > 0 else None

    articles = get_articles_for_category(category, subcategory_tag=subcategory, since_days=since_days)
    if len(articles) < 3:
        return jsonify({"error": "insufficient_data", "article_count": len(articles)})

    pre_it, pre_cc, pre_cr, pre_ot = cost_tracker.get_tokens()
    result = generate_trend_analysis(category, subcategory_tag=subcategory, since_days=since_days)
    if result is None:
        return jsonify({"error": "generation_failed"}), 500

    post_it, post_cc, post_cr, post_ot = cost_tracker.get_tokens()
    inp_price, cache_read_price, out_price = _lookup_pricing(result["model_used"])
    cache_write_price = inp_price * 1.25
    actual_cost = (
        (post_it - pre_it)  * inp_price
        + (post_cc - pre_cc) * cache_write_price
        + (post_cr - pre_cr) * cache_read_price
        + (post_ot - pre_ot) * out_price
    ) / 1_000_000
    result["actual_cost"] = actual_cost

    return jsonify(result)


@app.route("/api/category-insight")
def api_category_insight():
    """Return or generate a trend/forecast insight for a category.

    Checks the cache first (valid for 24 hours if article hash
    matches). Generates a fresh insight via LLM if the cache is stale
    or missing.

    Query params:
        category: The broad category name (required).
        subcategory: Optional entity tag for narrower focus.

    Returns:
        JSON with ``trend``, ``forecast``, ``article_count``,
        ``model_used``, ``cached`` boolean, and ``generated_at``.
    """
    from datetime import datetime, timedelta
    from summarizer import generate_category_insight

    category = request.args.get("category", "").strip()
    if not category:
        return jsonify({"error": "missing category parameter"}), 400

    subcategory = request.args.get("subcategory", "").strip() or None
    days = request.args.get("days", 0, type=int)
    since_days = days if days > 0 else None

    # Build cache key: include time-filter suffix so filtered results don't
    # overwrite the all-time cache entry.
    cache_key = f"{category}::{subcategory}" if subcategory else category
    if since_days:
        cache_key = f"{cache_key}::days{since_days}"

    # Get articles for this category/subcategory and check minimum count
    articles = get_articles_for_category(category, subcategory_tag=subcategory, since_days=since_days)
    if len(articles) < 3:
        return jsonify({"error": "insufficient_data", "article_count": len(articles)})

    current_hash = _compute_category_hash(articles)

    # Check cache
    cached = get_category_insight(cache_key)
    if cached:
        cache_age_ok = False
        if cached["created_date"]:
            try:
                created = datetime.fromisoformat(cached["created_date"])
                cache_age_ok = (datetime.utcnow() - created) < timedelta(hours=24)
            except (ValueError, TypeError):
                pass

        if cached["article_hash"] == current_hash and cache_age_ok:
            return jsonify({
                "trend": cached["trend_text"],
                "forecast": cached["forecast_text"],
                "article_count": cached["article_count"],
                "model_used": cached["model_used"],
                "cached": True,
                "actual_cost": 0.0,
                "generated_at": cached["created_date"],
            })

    # Generate fresh insight, snapshot tokens to compute actual cost
    pre_it, pre_cc, pre_cr, pre_ot = cost_tracker.get_tokens()
    result = generate_category_insight(category, subcategory_tag=subcategory, since_days=since_days)
    if result is None:
        return jsonify({"error": "generation_failed"}), 500

    post_it, post_cc, post_cr, post_ot = cost_tracker.get_tokens()
    inp_price, cache_read_price, out_price = _lookup_pricing(result["model_used"])
    cache_write_price = inp_price * 1.25
    actual_cost = (
        (post_it - pre_it)  * inp_price
        + (post_cc - pre_cc) * cache_write_price
        + (post_cr - pre_cr) * cache_read_price
        + (post_ot - pre_ot) * out_price
    ) / 1_000_000

    # Save to cache
    save_category_insight(
        category_name=cache_key,
        trend_text=result["trend"],
        forecast_text=result["forecast"],
        article_count=result["article_count"],
        article_hash=current_hash,
        model_used=result["model_used"],
    )

    return jsonify({
        "trend": result["trend"],
        "forecast": result["forecast"],
        "article_count": result["article_count"],
        "model_used": result["model_used"],
        "cached": False,
        "actual_cost": actual_cost,
        "generated_at": datetime.utcnow().isoformat(),
    })


# === Intelligence API ===

@app.route("/api/intelligence/chat", methods=["POST"])
def api_intelligence_chat():
    """RAG-based chat endpoint for threat intelligence queries.

    Request body (JSON):
        messages: List of conversation message objects.

    Returns:
        JSON with ``response``, ``articles``, ``model_used``, ``error``.
    """
    from intelligence import chat as intelligence_chat
    data = request.get_json(silent=True) or {}
    messages = data.get("messages", [])
    if not messages:
        return jsonify({"error": "No messages provided"}), 400
    # Optional: explicit time window override (0 = search all, omit = auto-detect from query)
    since_days = data.get("since_days")
    if since_days is not None:
        try:
            since_days = int(since_days)
        except (ValueError, TypeError):
            since_days = None
    result = intelligence_chat(messages, since_days=since_days)
    return jsonify(result)


@app.route("/api/intelligence/search", methods=["POST"])
def api_intelligence_search():
    """Semantic search endpoint over article embeddings.

    Request body (JSON):
        query: The search query string.
        top_k: Number of results to return (default 15, max 50).

    Returns:
        JSON with ``articles`` array and ``error`` field.
    """
    from embeddings import semantic_search
    data = request.get_json(silent=True) or {}
    query = data.get("query", "").strip()
    if not query:
        return jsonify({"articles": [], "error": "No query provided"})
    top_k = min(data.get("top_k", 15), 50)
    articles = semantic_search(query, top_k=top_k)
    return jsonify({"articles": articles, "error": None})


@app.route("/api/intelligence/status")
def api_intelligence_status():
    """Return embedding generation progress statistics.

    Returns:
        JSON with ``total_summarized`` and ``total_embedded`` counts.
    """
    stats = get_embedding_stats()
    return jsonify(stats)


# === Startup ===

def find_free_port(start=5000):
    """Find an available TCP port starting from the given port number.

    Tries ``start``, ``start + 1``, and falls back to ``start + 2``.

    Args:
        start: The first port number to try.

    Returns:
        An available port number.
    """
    for port in (start, start + 1):
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            try:
                s.bind(("127.0.0.1", port))
                return port
            except OSError:
                continue
    return start + 2


def open_browser(port):
    """Open the application in the default web browser.

    Args:
        port: The port number the server is listening on.
    """
    webbrowser.open(f"http://127.0.0.1:{port}")


if __name__ == "__main__":
    # Initialize
    init_db()
    try:
        n = backfill_advisories_from_scriba()
        if n:
            logging.info(f"Backfilled {n} advisories from Scriba output")
    except Exception as e:
        logging.warning(f"Advisory backfill skipped: {e}")
    config = load_config()

    # Sync configured feeds into database
    for feed in config.get("feeds", []):
        upsert_source(feed["name"], feed["url"], feed.get("enabled", True))

    # Start background scheduler
    start_scheduler(app)

    host = os.environ.get("HOST", "127.0.0.1")
    port = int(os.environ.get("PORT", 0)) or find_free_port()

    logging.info(f"Starting JOES Threat Intelligence on http://{host}:{port}")

    # Only open browser for local development (not inside Docker)
    if host == "127.0.0.1":
        threading.Timer(1.5, open_browser, args=[port]).start()

    app.run(host=host, port=port, debug=False)
