import hashlib
import json as _json
import re
import sqlite3
import os
import threading

from config import DATA_DIR
from mitre_data import KNOWN_THREAT_ACTORS, KNOWN_SOFTWARE

DB_PATH = os.path.join(DATA_DIR, "threatlandscape.db")

_local = threading.local()


def get_connection():
    """Get or create a thread-local SQLite database connection.

    Each thread receives its own connection with WAL journal mode and
    foreign keys enabled. Connections are cached in thread-local storage.

    Returns:
        A ``sqlite3.Connection`` with ``Row`` row factory.
    """
    if not hasattr(_local, "conn") or _local.conn is None:
        _local.conn = sqlite3.connect(DB_PATH, check_same_thread=False)
        _local.conn.row_factory = sqlite3.Row
        _local.conn.execute("PRAGMA journal_mode=WAL")
        _local.conn.execute("PRAGMA foreign_keys=ON")
    return _local.conn


def init_db():
    """Initialize the database schema.

    Creates all tables and indexes if they do not already exist:
    ``sources``, ``articles``, ``summaries``, ``article_correlations``,
    ``category_insights``, and ``article_embeddings``.
    """
    conn = get_connection()
    conn.executescript("""
        CREATE TABLE IF NOT EXISTS sources (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT NOT NULL,
            url TEXT NOT NULL UNIQUE,
            enabled INTEGER DEFAULT 1,
            last_fetched TIMESTAMP
        );

        CREATE TABLE IF NOT EXISTS articles (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            source_id INTEGER NOT NULL,
            title TEXT NOT NULL,
            url TEXT NOT NULL UNIQUE,
            author TEXT,
            published_date TIMESTAMP,
            fetched_date TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            content_raw TEXT,
            image_url TEXT,
            FOREIGN KEY (source_id) REFERENCES sources(id)
        );

        CREATE TABLE IF NOT EXISTS summaries (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            article_id INTEGER NOT NULL UNIQUE,
            summary_text TEXT NOT NULL,
            key_points TEXT,
            tags TEXT,
            novelty_notes TEXT,
            network_traffic_reason TEXT,
            model_used TEXT,
            created_date TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (article_id) REFERENCES articles(id)
        );

        CREATE TABLE IF NOT EXISTS article_correlations (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            article_id_1 INTEGER NOT NULL,
            article_id_2 INTEGER NOT NULL,
            correlation_type TEXT,
            confidence REAL,
            description TEXT,
            created_date TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (article_id_1) REFERENCES articles(id),
            FOREIGN KEY (article_id_2) REFERENCES articles(id)
        );

        CREATE TABLE IF NOT EXISTS category_insights (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            category_name TEXT NOT NULL UNIQUE,
            trend_text TEXT,
            forecast_text TEXT,
            article_count INTEGER,
            article_hash TEXT,
            model_used TEXT,
            created_date TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        );

        CREATE TABLE IF NOT EXISTS trend_analyses (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            category_name TEXT NOT NULL,
            period_type TEXT NOT NULL,
            period_label TEXT NOT NULL,
            trend_text TEXT,
            article_count INTEGER,
            article_hash TEXT,
            model_used TEXT,
            created_date TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            UNIQUE(category_name, period_type, period_label)
        );

        CREATE TABLE IF NOT EXISTS article_embeddings (
            article_id INTEGER PRIMARY KEY,
            embedding BLOB NOT NULL,
            model_used TEXT NOT NULL,
            created_date TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (article_id) REFERENCES articles(id)
        );

        CREATE TABLE IF NOT EXISTS digest_log (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            sent_at TEXT NOT NULL,
            article_ids TEXT NOT NULL,
            story_count INTEGER NOT NULL,
            status TEXT DEFAULT 'sent'
        );

        CREATE TABLE IF NOT EXISTS customers (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT NOT NULL UNIQUE,
            business TEXT NOT NULL,
            country TEXT NOT NULL,
            known_affiliates TEXT NOT NULL DEFAULT '[]',
            known_tech_stack TEXT NOT NULL DEFAULT '[]',
            slack_channels TEXT NOT NULL DEFAULT '[]',
            notification_template TEXT NOT NULL DEFAULT '',
            ti_notification_template TEXT NOT NULL DEFAULT '',
            created_date TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            updated_date TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        );

        CREATE TABLE IF NOT EXISTS emerging_threat_analyses (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            article_id INTEGER NOT NULL UNIQUE,
            hits_json TEXT NOT NULL DEFAULT '[]',
            model_used TEXT,
            triage_status TEXT NOT NULL DEFAULT 'pending',
            triaged_date TIMESTAMP,
            created_date TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (article_id) REFERENCES articles(id)
        );

        CREATE INDEX IF NOT EXISTS idx_emerging_threats_article ON emerging_threat_analyses(article_id);

        CREATE TABLE IF NOT EXISTS vulnerability_analyses (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            article_id INTEGER NOT NULL UNIQUE,
            hits_json TEXT NOT NULL DEFAULT '[]',
            model_used TEXT,
            triage_status TEXT NOT NULL DEFAULT 'pending',
            triaged_date TIMESTAMP,
            created_date TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (article_id) REFERENCES articles(id)
        );

        CREATE INDEX IF NOT EXISTS idx_vulnerability_analyses_article ON vulnerability_analyses(article_id);

        CREATE TABLE IF NOT EXISTS apt_ioc_exports (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            article_id INTEGER NOT NULL UNIQUE,
            canonical_apt TEXT NOT NULL,
            apt_display_name TEXT NOT NULL,
            apt_aliases_json TEXT NOT NULL DEFAULT '[]',
            ioc_count INTEGER NOT NULL DEFAULT 0,
            iocs_json TEXT NOT NULL DEFAULT '[]',
            campaign TEXT,
            context TEXT,
            misp_event_id INTEGER,
            misp_event_uuid TEXT,
            misp_galaxy_tag TEXT,
            status TEXT NOT NULL DEFAULT 'pending',
            error_message TEXT,
            created_date TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (article_id) REFERENCES articles(id)
        );

        CREATE INDEX IF NOT EXISTS idx_apt_ioc_exports_apt ON apt_ioc_exports(canonical_apt);

        CREATE TABLE IF NOT EXISTS advisories (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            kind TEXT NOT NULL DEFAULT 'vulnerability',
            article_id INTEGER,
            cve_id TEXT,
            technology TEXT,
            title TEXT NOT NULL,
            stem TEXT NOT NULL UNIQUE,
            markdown_path TEXT,
            pdf_path TEXT,
            pdf_filename TEXT NOT NULL,
            customer_id INTEGER,
            customer_name TEXT,
            created_date TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (article_id) REFERENCES articles(id)
        );

        CREATE TABLE IF NOT EXISTS advisory_distributions (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            advisory_id INTEGER NOT NULL,
            channel_id TEXT NOT NULL,
            channel_name TEXT,
            status TEXT NOT NULL DEFAULT 'sent',
            error_message TEXT,
            slack_ts TEXT,
            created_date TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (advisory_id) REFERENCES advisories(id)
        );

        CREATE INDEX IF NOT EXISTS idx_advisory_distributions_advisory
            ON advisory_distributions(advisory_id, created_date DESC);
        CREATE INDEX IF NOT EXISTS idx_advisories_kind ON advisories(kind);
        CREATE INDEX IF NOT EXISTS idx_advisories_cve ON advisories(cve_id);
        CREATE INDEX IF NOT EXISTS idx_advisories_created ON advisories(created_date DESC);
        CREATE INDEX IF NOT EXISTS idx_articles_source ON articles(source_id);
        CREATE INDEX IF NOT EXISTS idx_articles_published ON articles(published_date DESC);
        CREATE INDEX IF NOT EXISTS idx_summaries_article ON summaries(article_id);
    """)
    conn.commit()

    # Migrations: add columns that may not exist in older databases
    for col_sql in [
        "ALTER TABLE summaries ADD COLUMN network_traffic_reason TEXT",
        "ALTER TABLE emerging_threat_analyses ADD COLUMN triage_status TEXT NOT NULL DEFAULT 'pending'",
        "ALTER TABLE emerging_threat_analyses ADD COLUMN triaged_date TIMESTAMP",
        "ALTER TABLE vulnerability_analyses ADD COLUMN triage_status TEXT NOT NULL DEFAULT 'pending'",
        "ALTER TABLE vulnerability_analyses ADD COLUMN triaged_date TIMESTAMP",
        "ALTER TABLE advisory_distributions ADD COLUMN customer_id INTEGER",
        "ALTER TABLE advisory_distributions ADD COLUMN customer_name TEXT",
        "ALTER TABLE advisory_distributions ADD COLUMN cve_id TEXT",
        "ALTER TABLE customers ADD COLUMN slack_channels TEXT NOT NULL DEFAULT '[]'",
        "ALTER TABLE customers ADD COLUMN notification_template TEXT NOT NULL DEFAULT ''",
        "ALTER TABLE customers ADD COLUMN ti_notification_template TEXT NOT NULL DEFAULT ''",
    ]:
        try:
            conn.execute(col_sql)
            conn.commit()
        except Exception:
            pass  # Column already exists

    try:
        conn.execute(
            "CREATE INDEX IF NOT EXISTS idx_emerging_threats_triage ON emerging_threat_analyses(triage_status)"
        )
        conn.execute(
            "CREATE INDEX IF NOT EXISTS idx_vulnerability_analyses_triage ON vulnerability_analyses(triage_status)"
        )
        # Created after the migrations above, since cve_id is one of them.
        conn.execute(
            "CREATE INDEX IF NOT EXISTS idx_advisory_distributions_cve "
            "ON advisory_distributions(cve_id, customer_id)"
        )
        conn.commit()
    except Exception:
        pass

    seed_default_customers()
    backfill_customer_notification_defaults()
    backfill_distribution_provenance()


def backfill_distribution_provenance():
    """Stamp CVE and customer onto deliveries recorded before those columns.

    Safe to derive because a distribution belongs to exactly one advisory, and
    an advisory carries one CVE and one customer, so nothing here is a guess.
    Without it, a send made before this migration would not count as "already
    distributed" and the analyst would be invited to send it twice.

    Only NULLs are filled, so the send-time snapshot always wins.
    """
    conn = get_connection()
    for column, source in (
        ("cve_id", "a.cve_id"),
        ("customer_id", "a.customer_id"),
        ("customer_name", "a.customer_name"),
    ):
        try:
            conn.execute(
                f"""UPDATE advisory_distributions
                    SET {column} = (SELECT {source} FROM advisories a
                                    WHERE a.id = advisory_distributions.advisory_id)
                    WHERE {column} IS NULL"""
            )
            conn.commit()
        except Exception:
            pass


def backfill_customer_notification_defaults():
    """Fill notification settings for customers that predate these columns.

    The message format used to be hardcoded, so a customer created before this
    migration has no format of its own. Filling an empty template with the
    matching default is behaviour-preserving: the default *is* what that
    customer was already being sent. Non-empty values are never touched, so an
    analyst's edit always wins.
    """
    from advisory_notification import default_templates_for

    conn = get_connection()
    try:
        rows = conn.execute(
            """SELECT id, name, slack_channels, notification_template, ti_notification_template
               FROM customers"""
        ).fetchall()
    except Exception:
        return

    seeded_channels = {
        "evoke": "#evoke-threatintel",
        "fidelidade": "#fidelidade-threatintel",
    }

    for row in rows:
        vuln, ti = default_templates_for(row["name"])
        updates, params = [], []

        if not (row["notification_template"] or "").strip():
            updates.append("notification_template=?")
            params.append(vuln)
        if not (row["ti_notification_template"] or "").strip():
            updates.append("ti_notification_template=?")
            params.append(ti)

        channel = seeded_channels.get((row["name"] or "").strip().lower())
        if channel and not _parse_json_list(row["slack_channels"]):
            updates.append("slack_channels=?")
            params.append(_json.dumps([{"id": "", "name": channel}]))

        if updates:
            params.append(row["id"])
            conn.execute(
                f"UPDATE customers SET {', '.join(updates)} WHERE id=?", params
            )
    conn.commit()


def seed_default_customers():
    """Insert default customer records when the customers table is empty."""
    conn = get_connection()
    count = conn.execute("SELECT COUNT(*) as c FROM customers").fetchone()["c"]
    if count > 0:
        return

    defaults = [
        {
            "name": "Evoke",
            "business": "International betting and gaming (evoke plc, formerly 888 Holdings) — William Hill, 888, Mr Green, and Winner",
            "country": "United Kingdom",
            "slack_channel": "#evoke-threatintel",
            "known_affiliates": [
                "William Hill",
                "888casino",
                "888sport",
                "888poker",
                "Mr Green",
                "Winner",
                "William Hill Vegas",
                "Evoke Gaming Affiliates",
                "Section8 (in-house games studio)",
            ],
            "known_tech_stack": [
                "AWS Cloud",
                "Kubernetes",
                "PostgreSQL",
                "Salesforce CRM",
                "ServiceNow ITSM",
                "Palo Alto Networks NGFW",
                "Okta Identity Cloud",
                "Splunk Enterprise Security",
                "Ivanti VPN",
                "Citrix Virtual Desktops",
            ],
        },
        {
            "name": "Fidelidade",
            "business": "Insurance — market leader in life and non-life insurance in Portugal (Fidelidade – Companhia de Seguros, S.A.)",
            "country": "Portugal",
            "slack_channel": "#fidelidade-threatintel",
            "known_affiliates": [
                "Millennium Gain Limited / Fosun International (parent group)",
                "Caixa Geral de Depósitos (strategic shareholder)",
                "Multicare – Seguros de Saúde",
                "Via Directa – Companhia de Seguros",
                "Fidelidade Assistência",
                "Luz Saúde",
                "Companhia Portuguesa de Resseguros (Fidelidade Re)",
                "Fidelidade Angola",
                "Fidelidade Macau",
            ],
            "known_tech_stack": [
                "SAP ERP",
                "Oracle Database",
                "IBM z/OS Mainframe",
                "Microsoft Active Directory",
                "Palo Alto Networks NGFW",
                "Ivanti Endpoint Manager",
                "Citrix DaaS",
                "Splunk Enterprise Security",
                "BMC Helix ITSM",
                "F5 BIG-IP",
            ],
        },
    ]

    from advisory_notification import default_templates_for

    for row in defaults:
        vuln_template, ti_template = default_templates_for(row["name"])
        conn.execute(
            """INSERT INTO customers (name, business, country, known_affiliates, known_tech_stack,
                                      slack_channels, notification_template, ti_notification_template)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?)""",
            (
                row["name"],
                row["business"],
                row["country"],
                _json.dumps(row["known_affiliates"]),
                _json.dumps(row["known_tech_stack"]),
                # Channel ids are workspace-specific, so only the name is
                # seeded. The picker fills in the id on first save.
                _json.dumps([{"id": "", "name": row["slack_channel"]}]),
                vuln_template,
                ti_template,
            ),
        )
    conn.commit()


def _parse_json_list(value):
    """Parse a JSON array column; return [] on failure."""
    if not value:
        return []
    try:
        data = _json.loads(value)
        return data if isinstance(data, list) else []
    except (_json.JSONDecodeError, TypeError):
        return []


def _customer_row_to_dict(row):
    """Convert a customer SQLite row to a dict with parsed list fields."""
    d = dict(row)
    d["known_affiliates"] = _parse_json_list(d.get("known_affiliates"))
    d["known_tech_stack"] = _parse_json_list(d.get("known_tech_stack"))
    # Each entry is {"id": "C0123ABC", "name": "#evoke-threatintel"}. The id is
    # what files_upload_v2 needs; the name is only for display and audit rows.
    d["slack_channels"] = [
        c for c in _parse_json_list(d.get("slack_channels")) if isinstance(c, dict)
    ]
    d["notification_template"] = d.get("notification_template") or ""
    d["ti_notification_template"] = d.get("ti_notification_template") or ""
    return d


def get_customers(search=None):
    """Return all customers, optionally filtered by name/business/country."""
    conn = get_connection()
    query = "SELECT * FROM customers WHERE 1=1"
    params = []
    if search:
        like = f"%{search}%"
        query += " AND (name LIKE ? OR business LIKE ? OR country LIKE ?)"
        params.extend([like, like, like])
    query += " ORDER BY name COLLATE NOCASE"
    rows = conn.execute(query, params).fetchall()
    return [_customer_row_to_dict(r) for r in rows]


def get_customer(customer_id):
    """Return a single customer by ID, or None."""
    conn = get_connection()
    row = conn.execute("SELECT * FROM customers WHERE id = ?", (customer_id,)).fetchone()
    return _customer_row_to_dict(row) if row else None


def create_customer(name, business, country, known_affiliates=None, known_tech_stack=None,
                    slack_channels=None, notification_template="", ti_notification_template=""):
    """Insert a new customer record."""
    conn = get_connection()
    conn.execute(
        """INSERT INTO customers (name, business, country, known_affiliates, known_tech_stack,
                                  slack_channels, notification_template, ti_notification_template)
           VALUES (?, ?, ?, ?, ?, ?, ?, ?)""",
        (
            name.strip(),
            business.strip(),
            country.strip(),
            _json.dumps(known_affiliates or []),
            _json.dumps(known_tech_stack or []),
            _json.dumps(slack_channels or []),
            notification_template or "",
            ti_notification_template or "",
        ),
    )
    conn.commit()
    row = conn.execute("SELECT * FROM customers WHERE name = ?", (name.strip(),)).fetchone()
    return _customer_row_to_dict(row)


def update_customer(customer_id, name, business, country, known_affiliates=None, known_tech_stack=None,
                    slack_channels=None, notification_template="", ti_notification_template=""):
    """Update an existing customer. Returns True if a row was updated."""
    conn = get_connection()
    cur = conn.execute(
        """UPDATE customers SET name=?, business=?, country=?,
           known_affiliates=?, known_tech_stack=?, slack_channels=?,
           notification_template=?, ti_notification_template=?,
           updated_date=CURRENT_TIMESTAMP
           WHERE id=?""",
        (
            name.strip(),
            business.strip(),
            country.strip(),
            _json.dumps(known_affiliates or []),
            _json.dumps(known_tech_stack or []),
            _json.dumps(slack_channels or []),
            notification_template or "",
            ti_notification_template or "",
            customer_id,
        ),
    )
    conn.commit()
    return cur.rowcount > 0


def get_customer_by_name(name):
    """Return a customer by exact name, or None.

    Advisories store ``customer_name`` alongside ``customer_id``; this is the
    lookup used when only the name survived.
    """
    if not name:
        return None
    conn = get_connection()
    row = conn.execute(
        "SELECT * FROM customers WHERE name = ? COLLATE NOCASE", (name.strip(),)
    ).fetchone()
    return _customer_row_to_dict(row) if row else None


def delete_customer(customer_id):
    """Delete a customer by ID. Returns True if a row was deleted."""
    conn = get_connection()
    cur = conn.execute("DELETE FROM customers WHERE id = ?", (customer_id,))
    conn.commit()
    return cur.rowcount > 0


def save_emerging_threat_analysis(article_id, hits, model_used):
    """Upsert customer-based emerging threat hits for an article.

    Preserves existing triage_status so re-analysis does not put a triaged
    item back into the analyst queue.
    """
    conn = get_connection()
    conn.execute(
        """INSERT INTO emerging_threat_analyses (article_id, hits_json, model_used, triage_status)
           VALUES (?, ?, ?, 'pending')
           ON CONFLICT(article_id) DO UPDATE SET
           hits_json=excluded.hits_json,
           model_used=excluded.model_used,
           created_date=CURRENT_TIMESTAMP""",
        (article_id, _json.dumps(hits or []), model_used),
    )
    conn.commit()


def delete_emerging_threat_analysis(article_id):
    """Remove emerging threat analysis for an article."""
    conn = get_connection()
    conn.execute("DELETE FROM emerging_threat_analyses WHERE article_id = ?", (article_id,))
    conn.commit()


def set_emerging_threat_triage(article_id, triage_status):
    """Set triage status for an emerging-threat analysis. Returns updated row or None."""
    status = (triage_status or "").strip().lower()
    if status not in ("pending", "triaged"):
        raise ValueError("triage_status must be 'pending' or 'triaged'")
    conn = get_connection()
    if status == "triaged":
        conn.execute(
            """UPDATE emerging_threat_analyses
               SET triage_status = 'triaged', triaged_date = CURRENT_TIMESTAMP
               WHERE article_id = ?""",
            (article_id,),
        )
    else:
        conn.execute(
            """UPDATE emerging_threat_analyses
               SET triage_status = 'pending', triaged_date = NULL
               WHERE article_id = ?""",
            (article_id,),
        )
    conn.commit()
    row = conn.execute(
        """SELECT article_id, triage_status, triaged_date
           FROM emerging_threat_analyses WHERE article_id = ?""",
        (article_id,),
    ).fetchone()
    return dict(row) if row else None


def get_emerging_threats(customer_id=None, page=1, limit=20, triage_status="pending"):
    """Return articles with non-empty customer threat hits.

    Args:
        triage_status: ``pending`` (default queue), ``triaged``, or ``all``.

    Returns:
        Tuple of (rows list, total count). Each row includes article fields and parsed hits.
    """
    conn = get_connection()
    base = """
        FROM emerging_threat_analyses eta
        JOIN articles a ON a.id = eta.article_id
        JOIN sources s ON s.id = a.source_id
        WHERE json_array_length(eta.hits_json) > 0
    """
    params = []

    status_filter = (triage_status or "pending").strip().lower()
    if status_filter in ("pending", "triaged"):
        base += " AND COALESCE(eta.triage_status, 'pending') = ?"
        params.append(status_filter)

    if customer_id:
        base += """
            AND EXISTS (
                SELECT 1 FROM json_each(eta.hits_json) je
                WHERE json_extract(je.value, '$.customer_id') = ?
            )
        """
        params.append(customer_id)

    total = conn.execute(f"SELECT COUNT(*) as c {base}", params).fetchone()["c"]

    query = f"""
        SELECT eta.id as analysis_id, eta.article_id, eta.hits_json, eta.created_date as analyzed_date,
               COALESCE(eta.triage_status, 'pending') as triage_status, eta.triaged_date,
               a.title, a.url, a.published_date, a.fetched_date, a.content_raw, s.name as source_name
        {base}
        ORDER BY eta.created_date DESC
        LIMIT ? OFFSET ?
    """
    rows = conn.execute(query, params + [limit, (page - 1) * limit]).fetchall()

    results = []
    for row in rows:
        d = dict(row)
        hits_raw = d.pop("hits_json", "[]")
        try:
            hits = _json.loads(hits_raw) if hits_raw else []
        except (_json.JSONDecodeError, TypeError):
            hits = []
        if not isinstance(hits, list):
            hits = []
        if customer_id:
            hits = [h for h in hits if h.get("customer_id") == customer_id]
        d["hits"] = hits
        results.append(d)

    has_adv = article_ids_with_advisories([r["article_id"] for r in results])
    for r in results:
        r["has_advisory"] = r["article_id"] in has_adv

    return results, total


def get_emerging_threat_article(article_id):
    """Single article with customer threat hits for detail/advisory view."""
    conn = get_connection()
    row = conn.execute(
        """
        SELECT eta.article_id, eta.hits_json, eta.created_date as analyzed_date,
               COALESCE(eta.triage_status, 'pending') as triage_status, eta.triaged_date,
               a.title, a.url, a.published_date, a.fetched_date, a.content_raw, s.name as source_name
        FROM emerging_threat_analyses eta
        JOIN articles a ON a.id = eta.article_id
        JOIN sources s ON s.id = a.source_id
        WHERE eta.article_id = ? AND json_array_length(eta.hits_json) > 0
        """,
        (article_id,),
    ).fetchone()
    if not row:
        return None
    d = dict(row)
    d["hits"] = _json.loads(d.pop("hits_json", "[]") or "[]")
    adv = get_advisory_for_article(article_id)
    d["has_advisory"] = bool(adv)
    d["advisory"] = adv
    return d


def save_vulnerability_analysis(article_id, hits, model_used):
    """Upsert CVE vulnerability hits. Preserves triage_status on re-analysis."""
    conn = get_connection()
    conn.execute(
        """INSERT INTO vulnerability_analyses (article_id, hits_json, model_used, triage_status)
           VALUES (?, ?, ?, 'pending')
           ON CONFLICT(article_id) DO UPDATE SET
           hits_json=excluded.hits_json,
           model_used=excluded.model_used,
           created_date=CURRENT_TIMESTAMP""",
        (article_id, _json.dumps(hits or []), model_used),
    )
    conn.commit()


def delete_vulnerability_analysis(article_id):
    conn = get_connection()
    conn.execute("DELETE FROM vulnerability_analyses WHERE article_id = ?", (article_id,))
    conn.commit()


def set_vulnerability_triage(article_id, triage_status):
    """Set triage status for a vulnerability analysis. Returns updated row or None."""
    status = (triage_status or "").strip().lower()
    if status not in ("pending", "triaged"):
        raise ValueError("triage_status must be 'pending' or 'triaged'")
    conn = get_connection()
    if status == "triaged":
        conn.execute(
            """UPDATE vulnerability_analyses
               SET triage_status = 'triaged', triaged_date = CURRENT_TIMESTAMP
               WHERE article_id = ?""",
            (article_id,),
        )
    else:
        conn.execute(
            """UPDATE vulnerability_analyses
               SET triage_status = 'pending', triaged_date = NULL
               WHERE article_id = ?""",
            (article_id,),
        )
    conn.commit()
    row = conn.execute(
        """SELECT article_id, triage_status, triaged_date
           FROM vulnerability_analyses WHERE article_id = ?""",
        (article_id,),
    ).fetchone()
    return dict(row) if row else None


def get_vulnerability_threats(customer_id=None, page=1, limit=20, triage_status="pending"):
    """Articles with CVE + customer tech-stack hits.

    Args:
        triage_status: ``pending`` (default queue), ``triaged``, or ``all``.
    """
    conn = get_connection()
    base = """
        FROM vulnerability_analyses va
        JOIN articles a ON a.id = va.article_id
        JOIN sources s ON s.id = a.source_id
        WHERE json_array_length(va.hits_json) > 0
    """
    params = []

    status_filter = (triage_status or "pending").strip().lower()
    if status_filter in ("pending", "triaged"):
        base += " AND COALESCE(va.triage_status, 'pending') = ?"
        params.append(status_filter)

    if customer_id:
        base += """
            AND EXISTS (
                SELECT 1 FROM json_each(va.hits_json) je
                WHERE json_extract(je.value, '$.customer_id') = ?
            )
        """
        params.append(customer_id)

    total = conn.execute(f"SELECT COUNT(*) as c {base}", params).fetchone()["c"]

    query = f"""
        SELECT va.id as analysis_id, va.article_id, va.hits_json, va.created_date as analyzed_date,
               COALESCE(va.triage_status, 'pending') as triage_status, va.triaged_date,
               a.title, a.url, a.published_date, a.fetched_date, a.content_raw, s.name as source_name
        {base}
        ORDER BY va.created_date DESC
        LIMIT ? OFFSET ?
    """
    rows = conn.execute(query, params + [limit, (page - 1) * limit]).fetchall()

    results = []
    for row in rows:
        d = dict(row)
        try:
            hits = _json.loads(d.pop("hits_json", "[]") or "[]")
        except (_json.JSONDecodeError, TypeError):
            hits = []
        if customer_id:
            hits = [h for h in hits if h.get("customer_id") == customer_id]
        d["hits"] = hits
        results.append(d)

    # Track whether an advisory was already made for any CVE on this article
    all_cves = []
    for r in results:
        for h in r.get("hits") or []:
            if h.get("cve_id"):
                all_cves.append(h["cve_id"])
    covered = cve_ids_with_advisories(all_cves)
    for r in results:
        hit_cves = { (h.get("cve_id") or "").strip().upper() for h in (r.get("hits") or []) if h.get("cve_id") }
        r["has_advisory"] = bool(hit_cves & covered)
        for h in r.get("hits") or []:
            cid = (h.get("cve_id") or "").strip().upper()
            h["has_advisory"] = cid in covered if cid else False

    return results, total


def get_vulnerability_article(article_id):
    """Single article with vulnerability hits for detail/advisory view."""
    conn = get_connection()
    row = conn.execute(
        """
        SELECT va.article_id, va.hits_json, va.created_date as analyzed_date,
               COALESCE(va.triage_status, 'pending') as triage_status, va.triaged_date,
               a.title, a.url, a.published_date, a.fetched_date, a.content_raw, s.name as source_name
        FROM vulnerability_analyses va
        JOIN articles a ON a.id = va.article_id
        JOIN sources s ON s.id = a.source_id
        WHERE va.article_id = ? AND json_array_length(va.hits_json) > 0
        """,
        (article_id,),
    ).fetchone()
    if not row:
        return None
    d = dict(row)
    d["hits"] = _json.loads(d.pop("hits_json", "[]") or "[]")
    hit_cves = [h.get("cve_id") for h in d["hits"] if h.get("cve_id")]
    covered = cve_ids_with_advisories(hit_cves)
    for h in d["hits"]:
        cid = (h.get("cve_id") or "").strip().upper()
        h["has_advisory"] = cid in covered if cid else False
    adv = get_advisory_for_article(article_id, kind="vulnerability")
    d["has_advisory"] = bool(covered) or bool(adv)
    d["advisory"] = adv
    return d


def save_advisory(
    stem,
    pdf_filename,
    title,
    kind="vulnerability",
    article_id=None,
    cve_id=None,
    technology=None,
    markdown_path=None,
    pdf_path=None,
    customer_id=None,
    customer_name=None,
):
    """Upsert an advisory record keyed by stem (filename without extension)."""
    conn = get_connection()
    conn.execute(
        """INSERT INTO advisories (
               kind, article_id, cve_id, technology, title, stem,
               markdown_path, pdf_path, pdf_filename, customer_id, customer_name
           ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
           ON CONFLICT(stem) DO UPDATE SET
               kind=excluded.kind,
               article_id=COALESCE(excluded.article_id, advisories.article_id),
               cve_id=COALESCE(excluded.cve_id, advisories.cve_id),
               technology=COALESCE(excluded.technology, advisories.technology),
               title=excluded.title,
               markdown_path=COALESCE(excluded.markdown_path, advisories.markdown_path),
               pdf_path=COALESCE(excluded.pdf_path, advisories.pdf_path),
               pdf_filename=excluded.pdf_filename,
               customer_id=COALESCE(excluded.customer_id, advisories.customer_id),
               customer_name=COALESCE(excluded.customer_name, advisories.customer_name),
               created_date=CURRENT_TIMESTAMP""",
        (
            kind,
            article_id,
            cve_id,
            technology,
            title,
            stem,
            markdown_path,
            pdf_path,
            pdf_filename,
            customer_id,
            customer_name,
        ),
    )
    conn.commit()
    row = conn.execute("SELECT * FROM advisories WHERE stem = ?", (stem,)).fetchone()
    return dict(row) if row else None


def get_advisories(kind=None, search=None, page=1, limit=20):
    """List advisories with optional kind filter and search."""
    conn = get_connection()
    base = "FROM advisories WHERE 1=1"
    params = []

    if kind and kind != "all":
        base += " AND kind = ?"
        params.append(kind)

    if search:
        like = f"%{search.strip()}%"
        base += """ AND (
            title LIKE ? OR cve_id LIKE ? OR technology LIKE ?
            OR customer_name LIKE ? OR stem LIKE ? OR pdf_filename LIKE ?
        )"""
        params.extend([like, like, like, like, like, like])

    total = conn.execute(f"SELECT COUNT(*) as c {base}", params).fetchone()["c"]
    rows = conn.execute(
        f"""SELECT * {base}
            ORDER BY created_date DESC
            LIMIT ? OFFSET ?""",
        params + [limit, (page - 1) * limit],
    ).fetchall()
    return [dict(r) for r in rows], total


def get_advisory(advisory_id):
    conn = get_connection()
    row = conn.execute("SELECT * FROM advisories WHERE id = ?", (advisory_id,)).fetchone()
    return dict(row) if row else None


def get_advisory_for_cve(cve_id):
    """Return the latest advisory record linked to a CVE ID (if any)."""
    if not cve_id:
        return None
    conn = get_connection()
    row = conn.execute(
        """SELECT id, cve_id, kind, title, stem, pdf_filename, article_id, created_date
           FROM advisories
           WHERE UPPER(cve_id) = UPPER(?)
           ORDER BY created_date DESC
           LIMIT 1""",
        (cve_id.strip(),),
    ).fetchone()
    return dict(row) if row else None


def get_advisory_for_article(article_id, kind=None):
    """Return the latest advisory linked to an article (optional kind filter)."""
    conn = get_connection()
    if kind:
        row = conn.execute(
            """SELECT id, cve_id, kind, title, stem, pdf_filename, article_id, created_date
               FROM advisories
               WHERE article_id = ? AND kind = ?
               ORDER BY created_date DESC
               LIMIT 1""",
            (article_id, kind),
        ).fetchone()
    else:
        row = conn.execute(
            """SELECT id, cve_id, kind, title, stem, pdf_filename, article_id, created_date
               FROM advisories
               WHERE article_id = ?
               ORDER BY created_date DESC
               LIMIT 1""",
            (article_id,),
        ).fetchone()
    return dict(row) if row else None


def article_ids_with_advisories(article_ids, kind=None):
    """Return set of article_ids that already have an advisory record."""
    if not article_ids:
        return set()
    conn = get_connection()
    placeholders = ",".join("?" * len(article_ids))
    params = list(article_ids)
    sql = f"SELECT DISTINCT article_id FROM advisories WHERE article_id IN ({placeholders})"
    if kind:
        sql += " AND kind = ?"
        params.append(kind)
    rows = conn.execute(sql, params).fetchall()
    return {r["article_id"] for r in rows}


def cve_ids_with_advisories(cve_ids):
    """Return set of uppercase CVE IDs that already have an advisory record."""
    if not cve_ids:
        return set()
    conn = get_connection()
    normalized = [c.strip().upper() for c in cve_ids if c]
    if not normalized:
        return set()
    placeholders = ",".join("?" * len(normalized))
    rows = conn.execute(
        f"SELECT DISTINCT UPPER(cve_id) as cve_id FROM advisories WHERE UPPER(cve_id) IN ({placeholders})",
        normalized,
    ).fetchall()
    return {r["cve_id"] for r in rows}


def save_advisory_distribution(
    advisory_id,
    channel_id,
    channel_name=None,
    status="sent",
    error_message=None,
    slack_ts=None,
    customer_id=None,
    customer_name=None,
    cve_id=None,
):
    """Record one advisory delivery attempt to one Slack channel.

    The customer is stored because an advisory can go to several customers at
    once, each in its own format, so "where was this sent" is only half the
    answer without "on whose behalf".

    The CVE is stored rather than joined through ``advisories`` because this
    table is an audit trail: it should say what was true when the message went
    out, and stay that way even if the advisory row is later corrected.
    """
    conn = get_connection()
    cursor = conn.execute(
        """INSERT INTO advisory_distributions (
               advisory_id, channel_id, channel_name, status, error_message,
               slack_ts, customer_id, customer_name, cve_id
           ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)""",
        (advisory_id, channel_id, channel_name, status, error_message, slack_ts,
         customer_id, customer_name, (cve_id or "").strip().upper() or None),
    )
    conn.commit()
    return cursor.lastrowid


def get_advisory_distributions(advisory_id):
    """Return the delivery history for an advisory, most recent first."""
    conn = get_connection()
    rows = conn.execute(
        """SELECT id, advisory_id, channel_id, channel_name, status,
                  error_message, slack_ts, created_date, customer_id,
                  customer_name, cve_id
           FROM advisory_distributions
           WHERE advisory_id = ?
           ORDER BY created_date DESC, id DESC""",
        (advisory_id,),
    ).fetchall()
    return [dict(r) for r in rows]


def _group_recipients(rows):
    """Collapse delivery rows into one entry per customer.

    Only successful deliveries count as "already notified": a failed upload
    means the customer never saw it, and treating that as sent would suppress
    the retry the analyst needs to make.
    """
    recipients = {}
    for row in rows:
        if row["status"] != "sent":
            continue
        key = row["customer_id"] if row["customer_id"] is not None else \
            (row["customer_name"] or row["channel_id"])
        entry = recipients.get(key)
        if entry is None:
            entry = {
                "customer_id": row["customer_id"],
                "customer_name": row["customer_name"],
                "first_sent": row["created_date"],
                "last_sent": row["created_date"],
                "send_count": 0,
                "channels": [],
                "advisory_ids": [],
            }
            recipients[key] = entry
        entry["send_count"] += 1
        # Rows arrive newest first, so the oldest seen is the first send.
        entry["first_sent"] = row["created_date"]
        name = row["channel_name"] or row["channel_id"]
        if name and name not in entry["channels"]:
            entry["channels"].append(name)
        if row["advisory_id"] not in entry["advisory_ids"]:
            entry["advisory_ids"].append(row["advisory_id"])

    return sorted(
        recipients.values(),
        key=lambda r: (r["customer_name"] or "").lower(),
    )


def get_cve_recipients(cve_id):
    """Return which customers have already been sent an advisory for a CVE.

    Keyed on the CVE rather than the advisory, because the same CVE can be
    written up more than once (a second article, a corrected advisory) and the
    customer does not want it twice. This is the question the distribution
    picker asks before pre-selecting anyone.

    Returns:
        List of ``{customer_id, customer_name, first_sent, last_sent,
        send_count, channels, advisory_ids}`` dicts, sorted by customer name.
    """
    cve_id = (cve_id or "").strip().upper()
    if not cve_id:
        return []
    conn = get_connection()
    rows = conn.execute(
        """SELECT advisory_id, channel_id, channel_name, status, created_date,
                  customer_id, customer_name
           FROM advisory_distributions
           WHERE cve_id = ?
           ORDER BY created_date DESC, id DESC""",
        (cve_id,),
    ).fetchall()
    return _group_recipients(rows)


def get_advisory_recipients(advisory_id):
    """Return which customers have already been sent one specific advisory.

    The fallback for threat intelligence, which has no CVE to key on.
    """
    conn = get_connection()
    rows = conn.execute(
        """SELECT advisory_id, channel_id, channel_name, status, created_date,
                  customer_id, customer_name
           FROM advisory_distributions
           WHERE advisory_id = ?
           ORDER BY created_date DESC, id DESC""",
        (advisory_id,),
    ).fetchall()
    return _group_recipients(rows)


def get_article_recipients(article_id):
    """Return which customers have been sent anything written from an article.

    The dedup key for threat intelligence, which carries no CVE: the unit of
    work there is the article, so a second advisory from the same article is
    the duplicate worth warning about.
    """
    conn = get_connection()
    rows = conn.execute(
        """SELECT d.advisory_id, d.channel_id, d.channel_name, d.status,
                  d.created_date, d.customer_id, d.customer_name
           FROM advisory_distributions d
           JOIN advisories a ON a.id = d.advisory_id
           WHERE a.article_id = ?
           ORDER BY d.created_date DESC, d.id DESC""",
        (article_id,),
    ).fetchall()
    return _group_recipients(rows)


def get_distribution_ledger(limit=200):
    """Return what has been distributed, one row per CVE, with its recipients.

    The analyst-facing answer to "have we handled this CVE, and for whom",
    without needing to open each advisory in turn.
    """
    conn = get_connection()
    rows = conn.execute(
        """SELECT d.cve_id, d.advisory_id, d.channel_id, d.channel_name,
                  d.status, d.created_date, d.customer_id, d.customer_name,
                  a.title, a.kind
           FROM advisory_distributions d
           LEFT JOIN advisories a ON a.id = d.advisory_id
           ORDER BY d.created_date DESC, d.id DESC"""
    ).fetchall()

    ledger = {}
    for row in rows:
        # Threat intelligence has no CVE, so it is tracked per advisory.
        key = row["cve_id"] or f"advisory:{row['advisory_id']}"
        entry = ledger.get(key)
        if entry is None:
            entry = {
                "cve_id": row["cve_id"],
                "advisory_id": row["advisory_id"],
                "title": row["title"],
                "kind": row["kind"],
                "last_sent": row["created_date"],
                "rows": [],
            }
            ledger[key] = entry
        entry["rows"].append(row)

    # Rows are newest first, and dicts keep insertion order, so the first
    # `limit` keys are the most recently distributed.
    out = []
    for entry in list(ledger.values())[:limit]:
        rows_ = entry.pop("rows")
        entry["recipients"] = _group_recipients(rows_)
        entry["failed"] = [
            {"customer_name": r["customer_name"],
             "channel_name": r["channel_name"] or r["channel_id"]}
            for r in rows_ if r["status"] != "sent"
        ]
        out.append(entry)
    return out


def get_customers_for_cve(cve_id):
    """Return every customer affected by a CVE across the whole corpus.

    The vulnerability queue shows one article at a time, so a CVE that hits
    several customers across different articles looks narrower than it is.
    This aggregates every ``vulnerability_analyses`` hit for the CVE into one
    entry per customer.

    Returns:
        List of ``{customer_id, customer_name, matched_tech, articles}`` dicts
        sorted by customer name, where ``articles`` is a list of
        ``{id, title}``.
    """
    if not cve_id or not cve_id.strip():
        return []

    conn = get_connection()
    rows = conn.execute(
        """SELECT json_extract(je.value, '$.customer_id') AS customer_id,
                  json_extract(je.value, '$.customer_name') AS customer_name,
                  json_extract(je.value, '$.matched_tech') AS matched_tech,
                  va.article_id AS article_id,
                  a.title AS article_title
           FROM vulnerability_analyses va
           JOIN articles a ON a.id = va.article_id
           JOIN json_each(va.hits_json) je
           WHERE UPPER(json_extract(je.value, '$.cve_id')) = UPPER(?)""",
        (cve_id.strip(),),
    ).fetchall()

    by_customer = {}
    for row in rows:
        key = row["customer_id"]
        entry = by_customer.setdefault(key, {
            "customer_id": row["customer_id"],
            "customer_name": row["customer_name"],
            "matched_tech": [],
            "articles": [],
        })
        tech = row["matched_tech"]
        if tech and tech not in entry["matched_tech"]:
            entry["matched_tech"].append(tech)
        if not any(a["id"] == row["article_id"] for a in entry["articles"]):
            entry["articles"].append({
                "id": row["article_id"],
                "title": row["article_title"],
            })

    results = list(by_customer.values())
    for entry in results:
        entry["matched_tech"].sort(key=str.lower)
    results.sort(key=lambda e: (e["customer_name"] or "").lower())
    return results


def backfill_advisories_from_scriba():
    """Import existing Scriba PDF outputs into the advisories table if missing."""
    from pathlib import Path
    import re

    scriba_root = Path(__file__).resolve().parent.parent / "scriba"
    output_dir = scriba_root / "output"
    reports_dir = scriba_root / "reports"
    if not output_dir.is_dir():
        return 0

    cve_stem_re = re.compile(r"^(cve-\d{4}-\d+)(?:_(.+))?$", re.I)
    cve_any_re = re.compile(r"cve[-_]?\d{4}[-_]?\d+", re.I)
    # Stems written by ti_advisory_base_name(): ti-<article_id>_<customer>_<topic>.
    # Without this, TI advisories imported from disk land as "general" and are
    # notified with the vulnerability template and empty CVE/version fields.
    ti_stem_re = re.compile(r"^ti-(\d+)_", re.I)
    imported = 0

    for pdf in sorted(output_dir.glob("*.pdf")):
        stem = pdf.stem
        existing = get_connection().execute(
            "SELECT id FROM advisories WHERE stem = ?", (stem,),
        ).fetchone()
        if existing:
            continue

        md_path = reports_dir / f"{stem}.md"
        markdown_path = str(md_path) if md_path.is_file() else None

        cve_id = None
        technology = None
        article_id = None
        kind = "general"
        ti_match = ti_stem_re.match(stem)
        m = cve_stem_re.match(stem)
        if ti_match:
            kind = "threat_intelligence"
            # The stem records the article this came from, but that article may
            # have since been cleared. advisories.article_id is a foreign key,
            # so only link it when the row still exists.
            candidate = int(ti_match.group(1))
            if get_connection().execute(
                "SELECT 1 FROM articles WHERE id = ?", (candidate,)
            ).fetchone():
                article_id = candidate
        elif m:
            raw = m.group(1).upper().replace("_", "-")
            parts = re.match(r"CVE-?(\d{4})-?(\d+)", raw, re.I)
            cve_id = f"CVE-{parts.group(1)}-{parts.group(2)}" if parts else raw
            technology = (m.group(2) or "").replace("-", " ").strip() or None
            kind = "vulnerability"
        elif cve_any_re.search(stem):
            found = cve_any_re.search(stem).group(0).upper().replace("_", "-")
            parts = re.match(r"CVE-?(\d{4})-?(\d+)", found, re.I)
            if parts:
                cve_id = f"CVE-{parts.group(1)}-{parts.group(2)}"
            kind = "vulnerability"

        title = stem.replace("-", " ").replace("_", " — ")
        if markdown_path:
            try:
                text = Path(markdown_path).read_text(encoding="utf-8", errors="ignore")
                for line in text.splitlines():
                    if line.startswith("# ") and len(line) > 4:
                        title = line[2:].strip()
                        break
            except OSError:
                pass

        save_advisory(
            stem=stem,
            pdf_filename=pdf.name,
            title=title,
            kind=kind,
            article_id=article_id,
            cve_id=cve_id,
            technology=technology,
            markdown_path=markdown_path,
            pdf_path=str(pdf),
        )
        imported += 1

    return imported


def save_apt_ioc_export(
    article_id,
    canonical_apt,
    apt_display_name,
    apt_aliases_json="[]",
    ioc_count=0,
    iocs_json="[]",
    campaign=None,
    context=None,
    misp_event_id=None,
    misp_event_uuid=None,
    misp_galaxy_tag=None,
    status="pending",
    error_message=None,
):
    conn = get_connection()
    conn.execute(
        """INSERT INTO apt_ioc_exports (
               article_id, canonical_apt, apt_display_name, apt_aliases_json,
               ioc_count, iocs_json, campaign, context,
               misp_event_id, misp_event_uuid, misp_galaxy_tag, status, error_message
           ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
           ON CONFLICT(article_id) DO UPDATE SET
               canonical_apt=excluded.canonical_apt,
               apt_display_name=excluded.apt_display_name,
               apt_aliases_json=excluded.apt_aliases_json,
               ioc_count=excluded.ioc_count,
               iocs_json=excluded.iocs_json,
               campaign=excluded.campaign,
               context=excluded.context,
               misp_event_id=excluded.misp_event_id,
               misp_event_uuid=excluded.misp_event_uuid,
               misp_galaxy_tag=excluded.misp_galaxy_tag,
               status=excluded.status,
               error_message=excluded.error_message,
               created_date=CURRENT_TIMESTAMP""",
        (
            article_id, canonical_apt, apt_display_name, apt_aliases_json,
            ioc_count, iocs_json, campaign, context,
            misp_event_id, misp_event_uuid, misp_galaxy_tag, status, error_message,
        ),
    )
    conn.commit()


def get_apt_ioc_export(article_id):
    conn = get_connection()
    row = conn.execute(
        "SELECT * FROM apt_ioc_exports WHERE article_id = ?", (article_id,),
    ).fetchone()
    return dict(row) if row else None


def get_apt_ioc_exports(canonical_apt=None, limit=50):
    conn = get_connection()
    base = """
        SELECT e.*, a.title, a.url, s.name as source_name
        FROM apt_ioc_exports e
        JOIN articles a ON a.id = e.article_id
        JOIN sources s ON s.id = a.source_id
    """
    params = []
    if canonical_apt:
        base += " WHERE e.canonical_apt = ?"
        params.append(canonical_apt)
    base += " ORDER BY e.created_date DESC LIMIT ?"
    params.append(limit)
    return [dict(r) for r in conn.execute(base, params).fetchall()]


def get_apt_groups_from_summaries():
    """Aggregate tracked APT groups from summary tags with alias consolidation."""
    from apt_registry import resolve_threat_actor

    conn = get_connection()
    rows = conn.execute(
        """
        SELECT a.id as article_id, a.title, a.url, a.published_date, a.fetched_date,
               sm.tags, s.name as source_name
        FROM summaries sm
        JOIN articles a ON a.id = sm.article_id
        JOIN sources s ON s.id = a.source_id
        WHERE sm.model_used IS NOT NULL AND sm.model_used != 'failed'
          AND sm.tags IS NOT NULL AND sm.tags != '[]'
        """
    ).fetchall()

    groups = {}
    for row in rows:
        try:
            tags = _json.loads(row["tags"] or "[]")
        except (_json.JSONDecodeError, TypeError):
            continue
        article = {
            "article_id": row["article_id"],
            "title": row["title"],
            "url": row["url"],
            "published_date": row["published_date"],
            "fetched_date": row["fetched_date"],
            "source_name": row["source_name"],
        }
        canonical_hits = {}
        for tag in tags:
            resolved = resolve_threat_actor(tag)
            if resolved:
                canonical_hits[resolved["canonical_tag"]] = resolved
        for ct, resolved in canonical_hits.items():
            if ct not in groups:
                groups[ct] = {
                    "canonical_tag": ct,
                    "display_name": resolved["display_name"],
                    "aliases": resolved.get("aliases") or [],
                    "matched_tags": set(),
                    "articles_by_id": {},
                    "misp_export_count": 0,
                }
            groups[ct]["matched_tags"].add(resolved["matched_as"])
            groups[ct]["articles_by_id"][article["article_id"]] = article

    export_rows = conn.execute(
        "SELECT canonical_apt, COUNT(*) as c FROM apt_ioc_exports WHERE status = 'exported' GROUP BY canonical_apt"
    ).fetchall()
    export_map = {r["canonical_apt"]: r["c"] for r in export_rows}

    result = []
    for ct, g in groups.items():
        articles = sorted(
            g["articles_by_id"].values(),
            key=lambda x: x.get("published_date") or x.get("fetched_date") or "",
            reverse=True,
        )
        g["matched_tags"] = sorted(g["matched_tags"])
        g["misp_export_count"] = export_map.get(ct, 0)
        g["article_count"] = len(articles)
        g["articles"] = articles[:5]
        g.pop("articles_by_id", None)
        result.append(g)

    result.sort(key=lambda x: (-x["article_count"], x["display_name"].lower()))
    return result


def get_apt_group_detail(canonical_tag):
    """Full article list and MISP exports for one canonical APT."""
    groups = get_apt_groups_from_summaries()
    group = next((g for g in groups if g["canonical_tag"] == canonical_tag), None)
    if not group:
        from apt_registry import resolve_threat_actor
        resolved = resolve_threat_actor(canonical_tag)
        if not resolved:
            return None
        group = {
            "canonical_tag": resolved["canonical_tag"],
            "display_name": resolved["display_name"],
            "aliases": resolved.get("aliases") or [],
            "matched_tags": [],
            "article_count": 0,
            "articles": [],
            "misp_export_count": 0,
        }

    conn = get_connection()
    rows = conn.execute(
        """
        SELECT a.id as article_id, a.title, a.url, a.published_date, a.fetched_date,
               sm.tags, s.name as source_name
        FROM summaries sm
        JOIN articles a ON a.id = sm.article_id
        JOIN sources s ON s.id = a.source_id
        WHERE sm.model_used IS NOT NULL AND sm.model_used != 'failed'
        ORDER BY COALESCE(a.published_date, a.fetched_date) DESC
        """
    ).fetchall()

    from apt_registry import resolve_threat_actor
    articles = []
    matched_tags = set()
    for row in rows:
        try:
            tags = _json.loads(row["tags"] or "[]")
        except (_json.JSONDecodeError, TypeError):
            continue
        hit = False
        for tag in tags:
            resolved = resolve_threat_actor(tag)
            if resolved and resolved["canonical_tag"] == canonical_tag:
                hit = True
                matched_tags.add(resolved["matched_as"])
        if hit:
            articles.append(dict(row))

    group["articles"] = articles
    group["article_count"] = len(articles)
    group["matched_tags"] = sorted(matched_tags)
    group["misp_exports"] = get_apt_ioc_exports(canonical_apt=canonical_tag, limit=100)
    exp = conn.execute(
        "SELECT COUNT(*) as c FROM apt_ioc_exports WHERE canonical_apt = ? AND status = 'exported'",
        (canonical_tag,),
    ).fetchone()
    group["misp_export_count"] = exp["c"] if exp else 0
    return group


def get_summarized_articles_without_threat_analysis(limit=10):
    """Articles with successful summaries but no emerging threat analysis yet."""
    conn = get_connection()
    rows = conn.execute(
        """
        SELECT a.id, a.title, a.url, a.content_raw, sm.summary_text
        FROM articles a
        JOIN summaries sm ON sm.article_id = a.id
        LEFT JOIN emerging_threat_analyses eta ON eta.article_id = a.id
        WHERE sm.model_used IS NOT NULL AND sm.model_used != 'failed'
          AND a.content_raw IS NOT NULL AND a.content_raw != ''
          AND eta.id IS NULL
        ORDER BY a.fetched_date DESC
        LIMIT ?
        """,
        (limit,),
    ).fetchall()
    return [dict(r) for r in rows]


def upsert_source(name, url, enabled=True):
    """Insert a source or update it if the URL already exists.

    Args:
        name: Display name of the feed source.
        url: Feed URL (used as the unique key).
        enabled: Whether the source is active.

    Returns:
        The integer ID of the upserted source row.
    """
    conn = get_connection()
    conn.execute(
        "INSERT INTO sources (name, url, enabled) VALUES (?, ?, ?) "
        "ON CONFLICT(url) DO UPDATE SET name=excluded.name, enabled=excluded.enabled",
        (name, url, int(enabled)),
    )
    conn.commit()
    row = conn.execute("SELECT id FROM sources WHERE url = ?", (url,)).fetchone()
    return row["id"]


def get_source_id(url):
    """Look up a source's ID by its URL.

    Args:
        url: The feed URL to search for.

    Returns:
        The integer source ID, or None if not found.
    """
    conn = get_connection()
    row = conn.execute("SELECT id FROM sources WHERE url = ?", (url,)).fetchone()
    return row["id"] if row else None


def get_source_last_fetched(source_id):
    """Get the ``last_fetched`` timestamp for a source.

    Args:
        source_id: The source's integer ID.

    Returns:
        The ISO-format timestamp string, or None if never fetched.
    """
    conn = get_connection()
    row = conn.execute("SELECT last_fetched FROM sources WHERE id = ?", (source_id,)).fetchone()
    return row["last_fetched"] if row and row["last_fetched"] else None


def article_exists(url):
    """Check whether an article with the given URL already exists.

    Args:
        url: The article URL to check.

    Returns:
        True if the article exists in the database.
    """
    conn = get_connection()
    row = conn.execute("SELECT 1 FROM articles WHERE url = ?", (url,)).fetchone()
    return row is not None


def insert_article(source_id, title, url, author=None, published_date=None, image_url=None):
    """Insert a new article into the database.

    Skips insertion if an article with the same URL already exists.

    Args:
        source_id: Foreign key to the source that produced this article.
        title: Article headline.
        url: Original article URL (unique constraint).
        author: Article author name.
        published_date: ISO-format publication date string.
        image_url: Thumbnail or hero image URL.

    Returns:
        The new article's integer ID, or None if it already exists or
        insertion fails due to an integrity error.
    """
    if article_exists(url):
        return None
    conn = get_connection()
    try:
        cur = conn.execute(
            "INSERT INTO articles (source_id, title, url, author, published_date, image_url) "
            "VALUES (?, ?, ?, ?, ?, ?)",
            (source_id, title, url, author, published_date, image_url),
        )
        conn.commit()
        return cur.lastrowid
    except sqlite3.IntegrityError:
        return None


def update_article_content(article_id, content_raw):
    """Store scraped article text.

    Args:
        article_id: The article's integer ID.
        content_raw: The scraped article text (may be empty string).
    """
    conn = get_connection()
    conn.execute("UPDATE articles SET content_raw = ? WHERE id = ?", (content_raw, article_id))
    conn.commit()


def update_source_fetched(source_id):
    """Update a source's ``last_fetched`` timestamp to now.

    Args:
        source_id: The source's integer ID.
    """
    conn = get_connection()
    conn.execute(
        "UPDATE sources SET last_fetched = CURRENT_TIMESTAMP WHERE id = ?", (source_id,)
    )
    conn.commit()


def get_articles(source_id=None, search=None, tag=None, page=1, limit=20):
    """Retrieve a paginated list of articles with optional filtering.

    Joins articles with their source and summary data. Supports
    filtering by source, full-text search across title/summary/tags,
    and exact tag matching.

    Args:
        source_id: Filter by this source ID.
        search: Substring to search in title, summary, or tags.
        tag: Exact tag string to filter by (JSON substring match).
        page: Page number (1-indexed).
        limit: Maximum articles per page.

    Returns:
        List of article dicts with source and summary fields.
    """
    conn = get_connection()
    query = """
        SELECT a.id, a.title, a.url, a.author, a.published_date, a.fetched_date,
               a.image_url, s.name as source_name,
               sm.summary_text, sm.key_points, sm.tags, sm.novelty_notes
        FROM articles a
        JOIN sources s ON a.source_id = s.id
        LEFT JOIN summaries sm ON sm.article_id = a.id
        WHERE 1=1
    """
    params = []

    if source_id:
        query += " AND a.source_id = ?"
        params.append(source_id)

    if search:
        query += " AND (a.title LIKE ? OR sm.summary_text LIKE ? OR sm.tags LIKE ?)"
        like = f"%{search}%"
        params.extend([like, like, like])

    if tag:
        query += " AND sm.tags LIKE ?"
        params.append(f'%"{tag}"%')

    query += " ORDER BY a.published_date DESC NULLS LAST, a.fetched_date DESC"
    query += " LIMIT ? OFFSET ?"
    params.extend([limit, (page - 1) * limit])

    rows = conn.execute(query, params).fetchall()
    return [dict(r) for r in rows]


def get_article(article_id):
    """Retrieve a single article with its source and summary data.

    Args:
        article_id: The article's integer ID.

    Returns:
        An article dict with source name and summary fields, or None
        if the article does not exist.
    """
    conn = get_connection()
    row = conn.execute(
        """
        SELECT a.*, s.name as source_name,
               sm.summary_text, sm.key_points, sm.tags, sm.novelty_notes,
               sm.network_traffic_reason, sm.model_used
        FROM articles a
        JOIN sources s ON a.source_id = s.id
        LEFT JOIN summaries sm ON sm.article_id = a.id
        WHERE a.id = ?
        """,
        (article_id,),
    ).fetchone()
    return dict(row) if row else None


def save_summary(article_id, summary_text, key_points, tags, novelty_notes, model_used,
                 network_traffic_reason=None):
    """Upsert a summary for an article.

    Inserts a new summary or updates an existing one if the article
    already has a summary (ON CONFLICT on ``article_id``).

    Args:
        article_id: The article's integer ID.
        summary_text: Markdown-formatted summary text.
        key_points: JSON string of attack flow steps or bullet points.
        tags: JSON array string of categorization tags.
        novelty_notes: What is novel about this threat, or None.
        model_used: The OpenAI model name, or ``"failed"``.
        network_traffic_reason: 1-3 sentence explanation of why the
            network-traffic tag was applied, or None.
    """
    conn = get_connection()
    conn.execute(
        "INSERT INTO summaries (article_id, summary_text, key_points, tags, novelty_notes, "
        "network_traffic_reason, model_used) "
        "VALUES (?, ?, ?, ?, ?, ?, ?) "
        "ON CONFLICT(article_id) DO UPDATE SET "
        "summary_text=excluded.summary_text, key_points=excluded.key_points, "
        "tags=excluded.tags, novelty_notes=excluded.novelty_notes, "
        "network_traffic_reason=excluded.network_traffic_reason, "
        "model_used=excluded.model_used, created_date=CURRENT_TIMESTAMP",
        (article_id, summary_text, key_points, tags, novelty_notes,
         network_traffic_reason, model_used),
    )
    conn.commit()


def get_unsummarized_articles(limit=10, article_ids=None):
    """Fetch articles that have scraped content but no summary yet.

    Args:
        limit: Maximum number of articles to return.
        article_ids: Optional list of article IDs to restrict results to.

    Returns:
        List of dicts with ``id``, ``title``, ``url``, and ``content_raw``.
    """
    conn = get_connection()
    if article_ids:
        placeholders = ",".join("?" * len(article_ids))
        rows = conn.execute(
            f"""
            SELECT a.id, a.title, a.url, a.content_raw
            FROM articles a
            LEFT JOIN summaries sm ON sm.article_id = a.id
            WHERE sm.id IS NULL AND a.content_raw IS NOT NULL AND a.content_raw != ''
              AND a.id IN ({placeholders})
            ORDER BY a.fetched_date DESC
            LIMIT ?
            """,
            (*article_ids, limit),
        ).fetchall()
    else:
        rows = conn.execute(
            """
            SELECT a.id, a.title, a.url, a.content_raw
            FROM articles a
            LEFT JOIN summaries sm ON sm.article_id = a.id
            WHERE sm.id IS NULL AND a.content_raw IS NOT NULL AND a.content_raw != ''
            ORDER BY a.fetched_date DESC
            LIMIT ?
            """,
            (limit,),
        ).fetchall()
    return [dict(r) for r in rows]


def get_unscraped_articles(limit=20, article_ids=None):
    """Fetch articles that have not been scraped yet.

    Args:
        limit: Maximum number of articles to return.
        article_ids: Optional list of article IDs to restrict results to.

    Returns:
        List of dicts with ``id`` and ``url``.
    """
    conn = get_connection()
    if article_ids:
        placeholders = ",".join("?" * len(article_ids))
        rows = conn.execute(
            f"""
            SELECT id, url FROM articles
            WHERE content_raw IS NULL
              AND id IN ({placeholders})
            ORDER BY fetched_date DESC
            LIMIT ?
            """,
            (*article_ids, limit),
        ).fetchall()
    else:
        rows = conn.execute(
            """
            SELECT id, url FROM articles
            WHERE content_raw IS NULL
            ORDER BY fetched_date DESC
            LIMIT ?
            """,
            (limit,),
        ).fetchall()
    return [dict(r) for r in rows]


def get_sources():
    """Retrieve all feed sources ordered by name.

    Returns:
        List of source dicts with all columns.
    """
    conn = get_connection()
    rows = conn.execute("SELECT * FROM sources ORDER BY name").fetchall()
    return [dict(r) for r in rows]


def get_ingested_articles(page=1, limit=50, source_id=None, search=None):
    """Return paginated raw ingested feed articles (no summary required).

    Args:
        page: Page number (1-indexed).
        limit: Maximum articles per page.
        source_id: Optional source filter.
        search: Optional title/URL substring search.

    Returns:
        Tuple of (article list, total count).
    """
    conn = get_connection()
    base = """
        FROM articles a
        JOIN sources s ON a.source_id = s.id
        WHERE 1=1
    """
    params = []

    if source_id:
        base += " AND a.source_id = ?"
        params.append(source_id)

    if search:
        base += " AND (a.title LIKE ? OR a.url LIKE ? OR s.name LIKE ?)"
        like = f"%{search}%"
        params.extend([like, like, like])

    total = conn.execute(f"SELECT COUNT(*) as c {base}", params).fetchone()["c"]

    query = f"""
        SELECT a.id, a.title, a.url, a.author, a.published_date, a.fetched_date,
               s.name as source_name, s.id as source_id,
               CASE
                 WHEN a.content_raw IS NULL THEN 'unscraped'
                 WHEN a.content_raw = '' THEN 'scrape_failed'
                 ELSE 'scraped'
               END as scrape_status,
               length(a.content_raw) as content_length,
               substr(a.content_raw, 1, 400) as content_preview
        {base}
        ORDER BY a.fetched_date DESC, a.published_date DESC NULLS LAST
        LIMIT ? OFFSET ?
    """
    rows = conn.execute(query, params + [limit, (page - 1) * limit]).fetchall()
    return [dict(r) for r in rows], total


def get_unsummarized_count():
    """Count articles with scraped content but no summary."""
    conn = get_connection()
    return conn.execute(
        """
        SELECT COUNT(*) as c FROM articles a
        LEFT JOIN summaries sm ON sm.article_id = a.id
        WHERE sm.id IS NULL AND a.content_raw IS NOT NULL AND a.content_raw != ''
        """
    ).fetchone()["c"]


def get_scrape_failed_count():
    """Count articles where scraping was attempted but returned empty content."""
    conn = get_connection()
    return conn.execute(
        "SELECT COUNT(*) as c FROM articles WHERE content_raw = ''"
    ).fetchone()["c"]


def get_failure_articles(failure_type, page, limit):
    """Return a paginated list of articles for a given failure type.

    Args:
        failure_type: One of 'unsummarized', 'scrape_failed', 'failed_summaries'.
        page: 1-based page number.
        limit: Number of results per page.

    Returns:
        Dict with keys ``articles`` (list of dicts) and ``total`` (int).
    """
    conn = get_connection()
    offset = (page - 1) * limit

    source_join = "LEFT JOIN sources s ON s.id = a.source_id "

    if failure_type == "unsummarized":
        base_where = (
            "FROM articles a "
            "LEFT JOIN summaries sm ON sm.article_id = a.id "
            f"{source_join}"
            "WHERE sm.id IS NULL AND a.content_raw IS NOT NULL AND a.content_raw != ''"
        )
        total = conn.execute(f"SELECT COUNT(*) as c {base_where}").fetchone()["c"]
        rows = conn.execute(
            f"SELECT a.id, a.title, a.url, a.fetched_date, s.name as source_name {base_where} "
            "ORDER BY a.fetched_date DESC LIMIT ? OFFSET ?",
            (limit, offset),
        ).fetchall()
    elif failure_type == "scrape_failed":
        total = conn.execute(
            "SELECT COUNT(*) as c FROM articles WHERE content_raw = ''"
        ).fetchone()["c"]
        rows = conn.execute(
            f"SELECT a.id, a.title, a.url, a.fetched_date, s.name as source_name "
            f"FROM articles a {source_join}"
            "WHERE a.content_raw = '' ORDER BY a.fetched_date DESC LIMIT ? OFFSET ?",
            (limit, offset),
        ).fetchall()
    else:  # failed_summaries
        base_where = (
            "FROM articles a "
            "JOIN summaries sm ON sm.article_id = a.id "
            f"{source_join}"
            "WHERE (sm.model_used = 'failed' OR sm.summary_text IS NULL OR sm.summary_text = '') "
            "AND a.content_raw IS NOT NULL AND a.content_raw != ''"
        )
        total = conn.execute(f"SELECT COUNT(*) as c {base_where}").fetchone()["c"]
        rows = conn.execute(
            f"SELECT a.id, a.title, a.url, a.fetched_date, s.name as source_name {base_where} "
            "ORDER BY a.fetched_date DESC LIMIT ? OFFSET ?",
            (limit, offset),
        ).fetchall()

    return {
        "articles": [dict(r) for r in rows],
        "total": total,
    }


def reset_scrape_failed_articles(article_ids):
    """Reset content_raw to NULL for scrape-failed articles so they can be re-scraped.

    Args:
        article_ids: List of integer article IDs.
    """
    if not article_ids:
        return
    conn = get_connection()
    placeholders = ",".join("?" * len(article_ids))
    conn.execute(
        f"UPDATE articles SET content_raw = NULL WHERE id IN ({placeholders})",
        article_ids,
    )
    conn.commit()


def delete_failed_summaries(article_ids):
    """Delete failed summary rows so articles can be re-summarized.

    Args:
        article_ids: List of integer article IDs.
    """
    if not article_ids:
        return
    conn = get_connection()
    placeholders = ",".join("?" * len(article_ids))
    conn.execute(
        f"DELETE FROM summaries WHERE article_id IN ({placeholders}) "
        "AND (model_used = 'failed' OR summary_text IS NULL OR summary_text = '')",
        article_ids,
    )
    conn.commit()


def get_stats():
    """Compute aggregate statistics for the dashboard.

    Returns:
        A dict with keys ``total_articles``, ``total_sources``,
        ``total_summaries``, ``articles_last_24h``, ``unsummarized``,
        and ``scrape_failed``.
    """
    conn = get_connection()
    total_articles = conn.execute("SELECT COUNT(*) as c FROM articles").fetchone()["c"]
    total_sources = conn.execute("SELECT COUNT(*) as c FROM sources WHERE enabled=1").fetchone()["c"]
    total_summaries = conn.execute(
        "SELECT COUNT(*) as c FROM summaries "
        "WHERE model_used != 'failed' AND summary_text IS NOT NULL AND summary_text != ''"
    ).fetchone()["c"]
    recent = conn.execute(
        "SELECT COUNT(*) as c FROM articles WHERE fetched_date >= datetime('now', '-24 hours')"
    ).fetchone()["c"]
    unsummarized = get_unsummarized_count()
    scrape_failed = get_scrape_failed_count()
    failed_summaries = conn.execute(
        "SELECT COUNT(*) as c FROM summaries sm "
        "JOIN articles a ON a.id = sm.article_id "
        "WHERE (sm.model_used = 'failed' OR sm.summary_text IS NULL OR sm.summary_text = '') "
        "AND a.content_raw IS NOT NULL AND a.content_raw != ''"
    ).fetchone()["c"]
    return {
        "total_articles": total_articles,
        "total_sources": total_sources,
        "total_summaries": total_summaries,
        "articles_last_24h": recent,
        "unsummarized": unsummarized,
        "scrape_failed": scrape_failed,
        "failed_summaries": failed_summaries,
    }


def save_embedding(article_id, embedding_bytes, model_used):
    """Upsert an embedding BLOB for an article.

    Args:
        article_id: The article's integer ID.
        embedding_bytes: Raw bytes of the float32 numpy embedding vector.
        model_used: The embedding model name (e.g. ``"text-embedding-3-small"``).
    """
    conn = get_connection()
    conn.execute(
        "INSERT INTO article_embeddings (article_id, embedding, model_used) "
        "VALUES (?, ?, ?) "
        "ON CONFLICT(article_id) DO UPDATE SET "
        "embedding=excluded.embedding, model_used=excluded.model_used, "
        "created_date=CURRENT_TIMESTAMP",
        (article_id, embedding_bytes, model_used),
    )
    conn.commit()


def get_all_embeddings(model_used=None):
    """Fetch all stored embeddings from the database.

    Args:
        model_used: If provided, filter to embeddings generated by
            this model only.

    Returns:
        List of dicts with ``article_id`` and ``embedding`` (BLOB).
    """
    conn = get_connection()
    if model_used:
        rows = conn.execute(
            "SELECT article_id, embedding FROM article_embeddings WHERE model_used = ?",
            (model_used,),
        ).fetchall()
    else:
        rows = conn.execute(
            "SELECT article_id, embedding FROM article_embeddings"
        ).fetchall()
    return [dict(r) for r in rows]


def get_unembedded_articles(limit=50, article_ids=None, model_used=None):
    """Fetch articles that have summaries but no embedding yet.

    Excludes articles whose summary has ``model_used='failed'``.

    Args:
        limit: Maximum number of articles to return.
        article_ids: Optional list of article IDs to restrict results to.
        model_used: If provided, an article counts as unembedded unless it has
            an embedding from *this* model. Switching embedding provider then
            re-embeds the backlog, instead of leaving articles holding vectors
            that cannot be compared against the new model's output.

    Returns:
        List of dicts with ``id``, ``title``, and ``summary_text``.
    """
    conn = get_connection()
    # Restricting the join (not the WHERE clause) is what preserves the
    # "no row means unembedded" test after filtering by model.
    join_clause = "LEFT JOIN article_embeddings ae ON ae.article_id = a.id"
    join_params = ()
    if model_used:
        join_clause += " AND ae.model_used = ?"
        join_params = (model_used,)

    if article_ids:
        placeholders = ",".join("?" * len(article_ids))
        rows = conn.execute(
            f"""
            SELECT a.id, a.title, sm.summary_text
            FROM articles a
            JOIN summaries sm ON sm.article_id = a.id
            {join_clause}
            WHERE ae.article_id IS NULL
              AND sm.summary_text IS NOT NULL AND sm.summary_text != ''
              AND sm.model_used != 'failed'
              AND a.id IN ({placeholders})
            ORDER BY a.fetched_date DESC
            LIMIT ?
            """,
            (*join_params, *article_ids, limit),
        ).fetchall()
    else:
        rows = conn.execute(
            f"""
            SELECT a.id, a.title, sm.summary_text
            FROM articles a
            JOIN summaries sm ON sm.article_id = a.id
            {join_clause}
            WHERE ae.article_id IS NULL
              AND sm.summary_text IS NOT NULL AND sm.summary_text != ''
              AND sm.model_used != 'failed'
            ORDER BY a.fetched_date DESC
            LIMIT ?
            """,
            (*join_params, limit),
        ).fetchall()
    return [dict(r) for r in rows]


def get_embedding_stats():
    """Get counts of embedded vs summarized articles.

    ``total_embedded`` is restricted to articles that also have a valid
    (non-failed, non-empty) summary, so it can never exceed
    ``total_summarized`` even if stale embeddings exist for articles
    whose summaries were later invalidated or regenerated as failed.

    Returns:
        A dict with ``total_summarized`` and ``total_embedded`` counts.
    """
    conn = get_connection()
    total_summarized = conn.execute(
        "SELECT COUNT(*) as c FROM summaries "
        "WHERE model_used != 'failed' "
        "AND summary_text IS NOT NULL AND summary_text != ''"
    ).fetchone()["c"]
    total_embedded = conn.execute(
        """
        SELECT COUNT(*) as c
        FROM article_embeddings ae
        JOIN summaries sm ON sm.article_id = ae.article_id
        WHERE sm.model_used != 'failed'
          AND sm.summary_text IS NOT NULL AND sm.summary_text != ''
        """
    ).fetchone()["c"]
    return {
        "total_summarized": total_summarized,
        "total_embedded": total_embedded,
    }


def get_article_ids_since_days(since_days, model_used=None):
    """Return the set of article IDs that have embeddings and were published within ``since_days`` days.

    Uses ``published_date`` when available, falling back to ``fetched_date``.

    Args:
        since_days: Number of days to look back from now.
        model_used: If provided, restrict to embeddings from this model.

    Returns:
        A set of integer article IDs.
    """
    conn = get_connection()
    cutoff = f"-{int(since_days)} days"
    if model_used:
        rows = conn.execute(
            """
            SELECT ae.article_id FROM article_embeddings ae
            JOIN articles a ON a.id = ae.article_id
            WHERE ae.model_used = ?
              AND date(COALESCE(a.published_date, a.fetched_date)) >= date('now', ?)
            """,
            (model_used, cutoff),
        ).fetchall()
    else:
        rows = conn.execute(
            """
            SELECT ae.article_id FROM article_embeddings ae
            JOIN articles a ON a.id = ae.article_id
            WHERE date(COALESCE(a.published_date, a.fetched_date)) >= date('now', ?)
            """,
            (cutoff,),
        ).fetchall()
    return {row["article_id"] for row in rows}


def get_articles_by_ids(article_ids):
    """Fetch full article and summary data for a list of IDs.

    Results are returned in the same order as the input ``article_ids``.

    Args:
        article_ids: List of article integer IDs.

    Returns:
        List of article dicts with source and summary fields,
        preserving the order of ``article_ids``.
    """
    if not article_ids:
        return []
    conn = get_connection()
    ph = ",".join("?" * len(article_ids))
    rows = conn.execute(
        f"""
        SELECT a.id, a.title, a.url, a.author, a.published_date, a.fetched_date,
               a.image_url, s.name as source_name,
               sm.summary_text, sm.key_points, sm.tags, sm.novelty_notes
        FROM articles a
        JOIN sources s ON a.source_id = s.id
        LEFT JOIN summaries sm ON sm.article_id = a.id
        WHERE a.id IN ({ph})
        """,
        list(article_ids),
    ).fetchall()
    # Preserve the ranked order from article_ids
    by_id = {r["id"]: dict(r) for r in rows}
    return [by_id[aid] for aid in article_ids if aid in by_id]


# Mapping from specific tags to broad categories.
# Tags not matching any pattern are ignored (the article still appears
# under whichever broad categories its other tags match).
_CATEGORY_RULES = [
    ("Malware", [
        "malware", "trojan", "backdoor", "infostealer", "info-stealer",
        "stealer", "loader", "dropper", "rootkit", "spyware", "adware",
        "keylogger", "rat", "worm", "cryptominer", "cryptojack", "miner",
        "ransomware", "lockbit", "blackcat", "alphv", "clop", "cl0p", "revil",
        "conti", "hive", "akira", "play", "medusa", "rhysida", "blackbasta",
        "black basta", "royal", "phobos", "babuk", "ragnar", "vice society",
        "bianlian", "8base", "noescape", "cactus", "hunters international",
        "emotet", "qakbot", "qbot", "trickbot", "icedid", "bumblebee",
        "pikabot", "darkgate", "asyncrat", "remcos", "redline", "raccoon",
        "vidar", "lumma", "stealc", "amadey", "smokeloader",
    ]),
    ("Vulnerabilities", [
        "vulnerability", "cve", "zero-day", "0-day", "0day", "exploit",
        "rce", "remote-code-execution", "buffer-overflow", "use-after-free",
        "deserialization", "proof-of-concept", "poc", "patch", "security-update",
        "security-flaw", "privilege-escalation", "code-execution",
    ]),
    ("Threat Actors", [
        "apt", "threat-actor", "nation-state", "cyber-espionage", "espionage",
        "campaign", "lazarus", "lazarus-group", "apt29", "apt28", "cozy-bear",
        "fancy-bear", "turla", "sandworm", "kimsuky", "mustang-panda",
        "charming-kitten", "hafnium", "nobelium", "volt-typhoon",
        "salt-typhoon", "scattered-spider", "lapsus",
    ]),
    ("Data Leaks", [
        "data-leak", "data-breach", "breach", "data-exposure",
        "data leak", "data breach", "data exposure", "exfiltration",
    ]),
    ("Phishing & Social Engineering", [
        "phishing", "spear-phishing", "social-engineering", "smishing",
        "vishing", "business-email-compromise", "bec", "credential-stuffing",
        "credential-theft",
    ]),
    ("Supply Chain", [
        "supply-chain", "supply chain", "dependency-confusion",
        "typosquatting", "malicious-package", "npm", "pypi",
    ]),
    ("Botnet & DDoS", [
        "botnet", "ddos", "dos", "mirai",
    ]),
    ("C2 & Offensive Tooling", [
        "c2", "command-and-control", "cobalt-strike", "metasploit",
        "sliver", "brute-ratel", "havoc", "mythic", "implant",
    ]),
    ("IoT & Hardware", [
        "iot", "firmware", "hardware", "embedded", "scada", "ics",
        "ot-security", "industrial",
    ]),
]

# Manual additions for entities commonly referenced in threat intelligence
# but absent from MITRE ATT&CK or listed under a different (versioned/full) name.
_EXTRA_THREAT_ACTORS = {
    "lapsus": "LAPSUS$",
    "lazarus": "Lazarus Group",
}

_EXTRA_SOFTWARE = {
    # Unversioned / short forms of MITRE entries
    "lockbit": "LockBit",
    "redline": "RedLine Stealer",
    "raccoon": "Raccoon Stealer",
    "lumma": "Lumma Stealer",
    "smokeloader": "SmokeLoader",
    # Alternate spellings
    "cl0p": "Clop",
    "blackbasta": "Black Basta",
    "ragnar": "Ragnar Locker",
    # Entities not (yet) catalogued in MITRE ATT&CK
    "hive": "Hive",
    "rhysida": "Rhysida",
    "phobos": "Phobos",
    "vice-society": "Vice Society",
    "bianlian": "BianLian",
    "8base": "8Base",
    "noescape": "NoEscape",
    "cactus": "Cactus",
    "hunters-international": "Hunters International",
    "stealc": "StealC",
    "vidar": "Vidar",
    "phorpiex": "Phorpiex",
    "globeimposter": "GlobeImposter",
    "medusalocker": "MedusaLocker",
    "trigona": "Trigona",
    "snatch": "Snatch",
    "mallox": "Mallox",
    "fog": "Fog",
    "interlock": "Interlock",
}

# Allowlist of known entities per subcategorizable category.
# Only tags that appear in these dicts become sub-categories.
# Everything else is grouped into "General".
# Core data from MITRE ATT&CK (enterprise-attack-18.1.json),
# supplemented with manual extras above.
_KNOWN_ENTITIES = {
    "Threat Actors": {**KNOWN_THREAT_ACTORS, **_EXTRA_THREAT_ACTORS},
    "Malware": {**KNOWN_SOFTWARE, **_EXTRA_SOFTWARE},
    "C2 & Offensive Tooling": {**KNOWN_SOFTWARE, **_EXTRA_SOFTWARE},
}


def _tag_to_category(tag):
    """Map a single tag to a broad category name.

    Uses safe matching for short keywords (<=3 chars): exact match,
    hyphen-component match, or prefix+digit match (e.g. ``"apt"``
    matches ``"apt29"``). Longer keywords use substring matching.
    Falls back to MITRE ATT&CK entity lookup for tags not covered
    by ``_CATEGORY_RULES``.

    Args:
        tag: A lowercase tag string.

    Returns:
        The category name string, or None if the tag is unmapped.
    """
    tag_lower = tag.strip().lower()
    parts = tag_lower.split("-")
    for category_name, keywords in _CATEGORY_RULES:
        for kw in keywords:
            if len(kw) <= 3:
                # Short keywords: exact, component, or prefix+digit
                if tag_lower == kw or kw in parts:
                    return category_name
                if tag_lower.startswith(kw) and tag_lower[len(kw):].isdigit():
                    return category_name
            else:
                if kw in tag_lower or tag_lower in kw:
                    return category_name
    # Fallback: check MITRE ATT&CK known entities (merged with extras)
    if tag_lower in _KNOWN_ENTITIES.get("Threat Actors", {}):
        return "Threat Actors"
    if tag_lower in _KNOWN_ENTITIES.get("Malware", {}):
        return "Malware"
    return None


# Regex to strip version suffixes from tags/display names.
# Matches: "-3.0", "-v2", "-_v2", " 2.0", etc. at end of string.
_VERSION_SUFFIX_RE = re.compile(r'[-_.\s]*(v?\d+(\.\d+)?|_v\d+)\s*$', re.IGNORECASE)


def _canonical_entity_tag(tag_lower, category_name):
    """Consolidate versioned entity variants under their base family name.

    Examples::

        'lockbit-3.0' -> 'lockbit'   (known entity base)
        'apt29'       -> 'apt29'     (no version suffix)
        'emotet'      -> 'emotet'    (unchanged)

    Only strips the version suffix if the resulting base name is itself
    a known entity, preventing over-stripping (e.g. ``'apt29'`` does
    NOT become ``'apt'``).

    Args:
        tag_lower: Lowercase tag string, possibly with version suffix.
        category_name: The broad category to look up known entities in.

    Returns:
        The canonical base tag string.
    """
    entities = _KNOWN_ENTITIES.get(category_name, {})

    # 1. Try stripping version directly from the tag
    m = _VERSION_SUFFIX_RE.search(tag_lower)
    if m:
        base = tag_lower[:m.start()].rstrip("-_. ")
        if base and base != tag_lower and base in entities:
            return base

    # 2. Try stripping version from the entity's display name
    #    Handles aliases like "lockbit-black" → display "LockBit 3.0" → "LockBit"
    if tag_lower in entities:
        display = entities[tag_lower]
        m2 = _VERSION_SUFFIX_RE.search(display)
        if m2:
            base_display = display[:m2.start()].strip()
            if base_display and base_display != display:
                base_tag = base_display.lower().replace(" ", "-")
                if base_tag in entities:
                    return base_tag

    return tag_lower


def _is_generic_tag(tag, category_name):
    """Check whether a tag is a generic keyword rather than a named entity.

    Uses an allowlist approach: only tags matching a known MITRE ATT&CK
    threat actor, malware family, or tool name are considered entities.
    Versioned variants (e.g. ``'lockbit-3.0'``) are recognized via
    canonicalization. Everything else is generic and falls into the
    ``"General"`` bucket.

    Args:
        tag: The tag string to classify.
        category_name: The broad category to check entities against.

    Returns:
        True if the tag is generic (not a known entity).
    """
    entities = _KNOWN_ENTITIES.get(category_name)
    if entities is None:
        return True  # not a subcategorizable category
    tag_lower = tag.strip().lower()
    # Direct lookup
    if tag_lower in entities:
        return False
    # Check if it's a versioned variant of a known entity
    canonical = _canonical_entity_tag(tag_lower, category_name)
    return canonical == tag_lower  # True (generic) if canonicalization didn't change it


def _format_entity_name(tag):
    """Return a human-friendly display name for a tag.

    Looks up the tag in the merged MITRE ATT&CK entity dicts (threat
    actors first, then software/tools). Falls back to title-cased
    formatting with hyphens replaced by spaces.

    Args:
        tag: The lowercase tag string to format.

    Returns:
        A display-friendly name string.
    """
    key = tag.strip().lower()
    for entities in _KNOWN_ENTITIES.values():
        if key in entities:
            return entities[key]
    return tag.replace("-", " ").title()


def get_subcategories(category_name, limit_per_sub=50, since_days=None):
    """Return sub-categories for a broad category based on named entities.

    Only works for categories listed in ``_KNOWN_ENTITIES`` (currently
    ``"Threat Actors"``, ``"Malware"``, ``"C2 & Offensive Tooling"``).
    Groups articles by their entity tags and returns named-entity
    sub-categories sorted by article count descending, plus a
    ``"General"`` bucket for unmatched articles.

    Args:
        category_name: Broad category name (e.g. ``"Malware"``).
        limit_per_sub: Maximum articles to include per sub-category.
        since_days: If provided, only include articles published within
            this many days.

    Returns:
        List of sub-category dicts with keys ``tag``, ``display_name``,
        ``count``, and ``articles``. Returns an empty list if the
        category is not subcategorizable.
    """
    if category_name not in _KNOWN_ENTITIES:
        return []

    articles = get_articles_for_category(category_name, since_days=since_days)

    # tag -> {article_id: article_dict}
    sub_map = {}
    sub_order = []
    matched_ids = set()

    for article in articles:
        try:
            tags = _json.loads(article.get("tags") or "[]")
        except (_json.JSONDecodeError, TypeError):
            tags = []

        for tag in tags:
            cat = _tag_to_category(tag)
            if cat == category_name and not _is_generic_tag(tag, category_name):
                # Canonicalize to base family name for grouping
                tag_lower = tag.strip().lower()
                canonical = _canonical_entity_tag(tag_lower, category_name)
                if canonical not in sub_map:
                    sub_map[canonical] = {}
                    sub_order.append(canonical)
                if article["id"] not in sub_map[canonical]:
                    sub_map[canonical][article["id"]] = article
                    matched_ids.add(article["id"])

    result = []
    for tag_key in sorted(sub_order, key=lambda t: -len(sub_map[t])):
        arts = list(sub_map[tag_key].values())
        result.append({
            "tag": tag_key,
            "display_name": _format_entity_name(tag_key),
            "count": len(arts),
            "articles": arts[:limit_per_sub],
        })

    # "General" bucket: articles not matched to any known entity
    general_articles = [a for a in articles if a["id"] not in matched_ids]
    if general_articles:
        result.append({
            "tag": "__general__",
            "display_name": "General",
            "count": len(general_articles),
            "articles": general_articles[:limit_per_sub],
        })

    return result


def get_categorized_articles(limit_per_category=10, since_days=None):
    """Return articles grouped into broad threat categories.

    Tags are consolidated into a small set of meaningful categories
    via ``_tag_to_category``. Articles with tags spanning multiple
    categories appear in each relevant category.

    Args:
        limit_per_category: Maximum articles to include per category.
        since_days: If provided, only include articles published within
            this many days.

    Returns:
        List of category dicts sorted by count descending, each with
        keys ``name``, ``count``, and ``articles``.
    """
    conn = get_connection()
    params = []
    date_filter = ""
    if since_days:
        date_filter = f" AND date(a.published_date) >= date('now', ?)"
        params.append(f"-{since_days} days")
    rows = conn.execute(
        f"""
        SELECT a.id, a.title, a.url, a.author, a.published_date, a.fetched_date,
               a.image_url, s.name as source_name,
               sm.summary_text, sm.key_points, sm.tags, sm.novelty_notes
        FROM articles a
        JOIN sources s ON a.source_id = s.id
        LEFT JOIN summaries sm ON sm.article_id = a.id
        WHERE sm.tags IS NOT NULL AND sm.tags != '[]'{date_filter}
        ORDER BY a.published_date DESC NULLS LAST, a.fetched_date DESC
        LIMIT 500
        """,
        params,
    ).fetchall()

    # Build category -> articles map (deduplicate by article id)
    cat_map = {}      # category_name -> {article_id: article_dict}
    cat_order = []     # preserve insertion order for stable sorting

    for row in rows:
        article = dict(row)
        try:
            tags = _json.loads(article.get("tags") or "[]")
        except (_json.JSONDecodeError, TypeError):
            tags = []

        assigned = set()
        for tag in tags:
            cat = _tag_to_category(tag)
            if cat and cat not in assigned:
                assigned.add(cat)
                if cat not in cat_map:
                    cat_map[cat] = {}
                    cat_order.append(cat)
                if article["id"] not in cat_map[cat]:
                    cat_map[cat][article["id"]] = article

    # Build result sorted by article count descending; cap per category
    categories = []
    for cat_name in sorted(cat_order, key=lambda c: -len(cat_map[c])):
        articles = list(cat_map[cat_name].values())
        categories.append({
            "name": cat_name,
            "count": len(articles),
            "articles": articles[:limit_per_category],
        })

    return categories


def _compute_category_hash(articles):
    """Compute a content hash for cache invalidation.

    Produces a truncated SHA-256 hash of sorted ``(article_id,
    summary_length)`` tuples so that adding or modifying articles
    invalidates the cached insight.

    Args:
        articles: List of article dicts with ``id`` and ``summary_text``.

    Returns:
        A 16-character hex string.
    """
    tuples = sorted(
        (a["id"], len(a.get("summary_text") or "")) for a in articles
    )
    raw = str(tuples).encode()
    return hashlib.sha256(raw).hexdigest()[:16]


def get_articles_for_category(category_name, subcategory_tag=None, since_days=None):
    """Return all summarized articles belonging to a broad category.

    Scans all articles with tags and filters to those whose tags map
    to the given category via ``_tag_to_category``.

    Args:
        category_name: Broad category name (e.g. ``"Malware"``).
        subcategory_tag: If provided, further filters to articles
            whose tags contain a match for this specific entity.
        since_days: If provided, only include articles published within
            this many days.

    Returns:
        List of article dicts with summary data, ordered by
        publication date descending.
    """
    conn = get_connection()
    params = []
    date_filter = ""
    if since_days:
        date_filter = f" AND date(a.published_date) >= date('now', ?)"
        params.append(f"-{since_days} days")
    rows = conn.execute(
        f"""
        SELECT a.id, a.title, a.url, a.published_date,
               sm.summary_text, sm.tags
        FROM articles a
        JOIN summaries sm ON sm.article_id = a.id
        WHERE sm.tags IS NOT NULL AND sm.tags != '[]'{date_filter}
        ORDER BY a.published_date DESC NULLS LAST, a.fetched_date DESC
        LIMIT 500
        """,
        params,
    ).fetchall()

    articles = []
    seen_ids = set()
    sub_lower = subcategory_tag.strip().lower() if subcategory_tag else None

    for row in rows:
        article = dict(row)
        try:
            tags = _json.loads(article.get("tags") or "[]")
        except (_json.JSONDecodeError, TypeError):
            tags = []

        for tag in tags:
            cat = _tag_to_category(tag)
            if cat != category_name:
                continue
            if sub_lower is not None:
                tag_lower = tag.strip().lower()
                if not (sub_lower in tag_lower or tag_lower in sub_lower):
                    continue
            if article["id"] not in seen_ids:
                seen_ids.add(article["id"])
                articles.append(article)
                break

    return articles


def get_category_insight(category_name):
    """Fetch a cached trend/forecast insight for a category.

    Args:
        category_name: The cache key (e.g. ``"Malware"`` or
            ``"Malware::lockbit"`` for subcategories).

    Returns:
        A dict with all ``category_insights`` columns, or None if
        no cached insight exists.
    """
    conn = get_connection()
    row = conn.execute(
        "SELECT * FROM category_insights WHERE category_name = ?",
        (category_name,),
    ).fetchone()
    return dict(row) if row else None


def save_category_insight(category_name, trend_text, forecast_text,
                          article_count, article_hash, model_used):
    """Upsert a category insight into the cache.

    Args:
        category_name: Cache key (e.g. ``"Malware"`` or
            ``"Malware::lockbit"``).
        trend_text: Markdown trend analysis text.
        forecast_text: Markdown forecast text.
        article_count: Number of articles used to generate the insight.
        article_hash: Content hash for cache invalidation.
        model_used: The OpenAI model that generated the insight.
    """
    conn = get_connection()
    conn.execute(
        "INSERT INTO category_insights "
        "(category_name, trend_text, forecast_text, article_count, article_hash, model_used, created_date) "
        "VALUES (?, ?, ?, ?, ?, ?, CURRENT_TIMESTAMP) "
        "ON CONFLICT(category_name) DO UPDATE SET "
        "trend_text=excluded.trend_text, forecast_text=excluded.forecast_text, "
        "article_count=excluded.article_count, article_hash=excluded.article_hash, "
        "model_used=excluded.model_used, created_date=CURRENT_TIMESTAMP",
        (category_name, trend_text, forecast_text, article_count, article_hash, model_used),
    )
    conn.commit()


def delete_article(article_id):
    """Delete an article and all its related records.

    Removes the article's embeddings, summary, correlations, and
    finally the article row itself.

    Args:
        article_id: The article's integer ID.
    """
    conn = get_connection()
    conn.execute("DELETE FROM article_embeddings WHERE article_id = ?", (article_id,))
    conn.execute("DELETE FROM summaries WHERE article_id = ?", (article_id,))
    conn.execute(
        "DELETE FROM article_correlations WHERE article_id_1 = ? OR article_id_2 = ?",
        (article_id, article_id),
    )
    conn.execute("DELETE FROM articles WHERE id = ?", (article_id,))
    conn.commit()


def delete_file_url_articles():
    """Delete articles whose URLs point to downloadable files.

    Scans all articles and removes those with file-based URLs
    (PDF, DOC, ZIP, etc.) that cannot be meaningfully scraped.
    Also deletes their associated embeddings, summaries, and
    correlations.

    Returns:
        Number of articles deleted.
    """
    from urllib.parse import urlparse

    skip_ext = {
        ".pdf", ".doc", ".docx", ".xls", ".xlsx", ".ppt", ".pptx",
        ".zip", ".rar", ".7z", ".gz", ".tar", ".tgz",
        ".exe", ".msi", ".dmg", ".apk", ".iso",
    }
    conn = get_connection()
    rows = conn.execute("SELECT id, url FROM articles").fetchall()

    ids = []
    for row in rows:
        try:
            path = urlparse(row["url"]).path.lower()
            if any(path.endswith(ext) for ext in skip_ext):
                ids.append(row["id"])
        except Exception:
            continue

    if not ids:
        return 0

    ph = ",".join("?" * len(ids))
    conn.execute(f"DELETE FROM article_embeddings WHERE article_id IN ({ph})", ids)
    conn.execute(f"DELETE FROM summaries WHERE article_id IN ({ph})", ids)
    conn.execute(
        f"DELETE FROM article_correlations WHERE article_id_1 IN ({ph}) OR article_id_2 IN ({ph})",
        ids + ids,
    )
    conn.execute(f"DELETE FROM articles WHERE id IN ({ph})", ids)
    conn.commit()
    return len(ids)


def clear_database():
    """Delete all data and reset source timestamps.

    Removes all articles, summaries, embeddings, correlations, and
    category insights. Resets every source's ``last_fetched`` to NULL.
    """
    conn = get_connection()
    conn.executescript("""
        DELETE FROM article_embeddings;
        DELETE FROM trend_analyses;
        DELETE FROM category_insights;
        DELETE FROM article_correlations;
        DELETE FROM summaries;
        DELETE FROM emerging_threat_analyses;
        DELETE FROM vulnerability_analyses;
        DELETE FROM apt_ioc_exports;
        DELETE FROM advisories;
        DELETE FROM articles;
        DELETE FROM digest_log;
        UPDATE sources SET last_fetched = NULL;
    """)
    conn.commit()


def clear_articles_before_days(days):
    """Delete articles (and their summaries/embeddings) fetched more than ``days`` days ago.

    Args:
        days: Number of days. Articles with ``fetched_date`` older than
            this threshold are deleted along with their summaries,
            embeddings, and correlations.

    Returns:
        Number of articles deleted.
    """
    conn = get_connection()
    cutoff = f"-{int(days)} days"
    rows = conn.execute(
        "SELECT id FROM articles WHERE fetched_date < datetime('now', ?)",
        (cutoff,),
    ).fetchall()
    ids = [r[0] for r in rows]
    if not ids:
        return 0
    ph = ",".join("?" * len(ids))
    conn.execute(f"DELETE FROM article_embeddings WHERE article_id IN ({ph})", ids)
    conn.execute(f"DELETE FROM summaries WHERE article_id IN ({ph})", ids)
    conn.execute(
        f"DELETE FROM article_correlations "
        f"WHERE article_id_1 IN ({ph}) OR article_id_2 IN ({ph})",
        ids + ids,
    )
    conn.execute(f"DELETE FROM articles WHERE id IN ({ph})", ids)
    conn.commit()
    return len(ids)


def delete_article_summary(article_id):
    """Delete all database artifacts for a single article.

    Removes entries from ``article_embeddings``, ``article_correlations``,
    ``summaries``, and the ``articles`` row itself so that the article will
    be treated as brand-new the next time it is encountered in a feed.

    Args:
        article_id: The article's integer ID.
    """
    conn = get_connection()
    conn.execute("DELETE FROM article_embeddings WHERE article_id = ?", (article_id,))
    conn.execute(
        "DELETE FROM article_correlations WHERE article_id_1 = ? OR article_id_2 = ?",
        (article_id, article_id),
    )
    conn.execute("DELETE FROM summaries WHERE article_id = ?", (article_id,))
    conn.execute("DELETE FROM emerging_threat_analyses WHERE article_id = ?", (article_id,))
    conn.execute("DELETE FROM vulnerability_analyses WHERE article_id = ?", (article_id,))
    conn.execute("DELETE FROM apt_ioc_exports WHERE article_id = ?", (article_id,))
    conn.execute("UPDATE advisories SET article_id = NULL WHERE article_id = ?", (article_id,))
    conn.execute("DELETE FROM articles WHERE id = ?", (article_id,))
    conn.commit()


def update_article_tags(article_id, tags):
    """Update (or create) the tags for an article.

    If the article already has a ``summaries`` row the tags column is
    updated in place.  If no summary row exists yet, a minimal row is
    inserted so the tags are still persisted.

    Args:
        article_id: The article's integer ID.
        tags: A list of lowercase tag strings.

    Raises:
        ValueError: If the article does not exist in the ``articles`` table.
    """
    conn = get_connection()
    exists = conn.execute(
        "SELECT 1 FROM articles WHERE id = ?", (article_id,)
    ).fetchone()
    if not exists:
        raise ValueError(f"Article {article_id} not found")
    tags_json = _json.dumps(tags)
    has_summary = conn.execute(
        "SELECT 1 FROM summaries WHERE article_id = ?", (article_id,)
    ).fetchone()
    if has_summary:
        conn.execute(
            "UPDATE summaries SET tags = ? WHERE article_id = ?",
            (tags_json, article_id),
        )
    else:
        conn.execute(
            """INSERT INTO summaries (article_id, summary_text, tags)
               VALUES (?, '', ?)
               ON CONFLICT(article_id) DO UPDATE SET tags = excluded.tags""",
            (article_id, tags_json),
        )
    conn.commit()


def get_available_tags():
    """Return the full predefined tag list for the article tag editor.

    Returns a dict with two keys:

    * ``categories`` – the 9 broad-category tags, each with ``tag`` and
      ``label`` fields.
    * ``entities`` – every known MITRE entity (threat actors + software),
      deduplicated by tag key, each with ``tag``, ``label``, and
      ``category`` fields.

    Returns:
        dict with ``categories`` and ``entities`` lists.
    """
    categories = [
        {"tag": "malware", "label": "Malware"},
        {"tag": "vulnerability", "label": "Vulnerabilities"},
        {"tag": "threat-actor", "label": "Threat Actors"},
        {"tag": "data-breach", "label": "Data Leaks"},
        {"tag": "phishing", "label": "Phishing & Social Engineering"},
        {"tag": "supply-chain", "label": "Supply Chain"},
        {"tag": "botnet", "label": "Botnet & DDoS"},
        {"tag": "c2", "label": "C2 & Offensive Tooling"},
        {"tag": "iot", "label": "IoT & Hardware"},
    ]

    seen = set()
    entities = []

    def _add_entities(mapping, category):
        for tag_key, display_name in sorted(mapping.items()):
            if tag_key in seen:
                continue
            seen.add(tag_key)
            entities.append({"tag": tag_key, "label": display_name, "category": category})

    _add_entities(_KNOWN_ENTITIES.get("Threat Actors", {}), "Threat Actors")
    _add_entities(_KNOWN_ENTITIES.get("Malware", {}), "Malware")
    _add_entities(_KNOWN_ENTITIES.get("C2 & Offensive Tooling", {}), "C2 & Offensive Tooling")

    return {"categories": categories, "entities": entities}


def get_trend_analyses(category_name):
    """Return all trend analysis rows for a category, ordered by period.

    Args:
        category_name: Category name (e.g. ``"Malware"``).

    Returns:
        List of row dicts ordered by ``period_type, period_label``.
    """
    conn = get_connection()
    rows = conn.execute(
        "SELECT * FROM trend_analyses WHERE category_name = ? ORDER BY period_type, period_label",
        (category_name,),
    ).fetchall()
    return [dict(r) for r in rows]


def get_trend_analysis(category_name, period_type, period_label):
    """Return a single trend analysis row, or None if not cached.

    Args:
        category_name: Category name.
        period_type: ``"quarterly"`` or ``"yearly"``.
        period_label: Period string (e.g. ``"2024-Q1"`` or ``"2024"``).

    Returns:
        Row dict or None.
    """
    conn = get_connection()
    row = conn.execute(
        "SELECT * FROM trend_analyses WHERE category_name = ? AND period_type = ? AND period_label = ?",
        (category_name, period_type, period_label),
    ).fetchone()
    return dict(row) if row else None


def save_trend_analysis(category_name, period_type, period_label, trend_text, article_count, article_hash, model_used):
    """Upsert a trend analysis row.

    Args:
        category_name: Category name.
        period_type: ``"quarterly"`` or ``"yearly"``.
        period_label: Period string.
        trend_text: Markdown trend text.
        article_count: Number of articles used.
        article_hash: Content hash for cache invalidation.
        model_used: Model name string.
    """
    conn = get_connection()
    conn.execute(
        """INSERT INTO trend_analyses
               (category_name, period_type, period_label, trend_text, article_count, article_hash, model_used, created_date)
           VALUES (?, ?, ?, ?, ?, ?, ?, CURRENT_TIMESTAMP)
           ON CONFLICT(category_name, period_type, period_label) DO UPDATE SET
               trend_text = excluded.trend_text,
               article_count = excluded.article_count,
               article_hash = excluded.article_hash,
               model_used = excluded.model_used,
               created_date = CURRENT_TIMESTAMP""",
        (category_name, period_type, period_label, trend_text, article_count, article_hash, model_used),
    )
    conn.commit()


# ============================================================
# Digest helpers
# ============================================================

def get_last_digest_sent_at():
    """Return the ISO timestamp of the most recent digest, or None."""
    conn = get_connection()
    row = conn.execute(
        "SELECT sent_at FROM digest_log ORDER BY id DESC LIMIT 1"
    ).fetchone()
    return row["sent_at"] if row else None


def log_digest_sent(sent_at, article_ids, story_count):
    """Record a sent digest in digest_log.

    Args:
        sent_at: ISO datetime string of when the digest was sent.
        article_ids: List of integer article IDs included in the digest.
        story_count: Number of story clusters in the digest.
    """
    conn = get_connection()
    conn.execute(
        "INSERT INTO digest_log (sent_at, article_ids, story_count) VALUES (?, ?, ?)",
        (sent_at, _json.dumps(article_ids), story_count),
    )
    conn.commit()


def get_articles_with_embeddings_since(since_dt, model_used=None):
    """Return articles that have summaries and embeddings created after since_dt.

    Args:
        since_dt: ISO datetime string (exclusive lower bound on summaries.created_date).
        model_used: If provided, restrict to embeddings from this model. The
            caller clusters these vectors against each other, so a mixed set
            would compare vectors from different models and cluster on noise.

    Returns:
        List of dicts with keys: id, title, url, source_name, summary_text,
        executive_summary, details, mitigations, embedding (bytes blob).
    """
    conn = get_connection()
    model_clause = " AND ae.model_used = ?" if model_used else ""
    params = (since_dt, model_used) if model_used else (since_dt,)
    rows = conn.execute(
        f"""
        SELECT a.id, a.title, a.url, s.name AS source_name,
               sm.summary_text, sm.novelty_notes, ae.embedding
        FROM articles a
        JOIN sources s ON a.source_id = s.id
        JOIN summaries sm ON sm.article_id = a.id
        JOIN article_embeddings ae ON ae.article_id = a.id
        WHERE sm.created_date > ?
          AND sm.model_used IS NOT NULL
          AND sm.model_used != 'failed'
          AND sm.model_used != ''{model_clause}
        ORDER BY sm.created_date ASC
        """,
        params,
    ).fetchall()
    return [dict(r) for r in rows]
