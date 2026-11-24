PRAGMA journal_mode = WAL;
PRAGMA synchronous = NORMAL;
PRAGMA foreign_keys = ON;

-- Primitive 1: Connectors & Multi-Account Identity Vault (Integrations view)
CREATE TABLE IF NOT EXISTS oauth_accounts (
    id TEXT PRIMARY KEY,
    slug TEXT UNIQUE NOT NULL,
    provider TEXT NOT NULL,
    display_name TEXT NOT NULL,
    account_identifier TEXT,
    scopes_json TEXT NOT NULL,
    encrypted_secrets BLOB NOT NULL,
    status TEXT NOT NULL DEFAULT 'ok',
    last_checked_at TEXT,
    last_error TEXT,
    owner_email TEXT NOT NULL DEFAULT '',
    visibility TEXT NOT NULL DEFAULT 'shared',
    allowed_groups_json TEXT NOT NULL DEFAULT '[]',
    created_at TEXT NOT NULL
);

-- Primitive 1B: Model Providers & Budgets (Models view)
CREATE TABLE IF NOT EXISTS model_providers (
    id TEXT PRIMARY KEY,
    slug TEXT UNIQUE NOT NULL,
    provider_type TEXT NOT NULL,
    model_id TEXT NOT NULL,
    api_base TEXT,
    encrypted_api_key BLOB,
    is_default INTEGER NOT NULL DEFAULT 0,
    daily_token_limit INTEGER,
    monthly_budget_usd REAL,
    input_price_per_million REAL,
    output_price_per_million REAL,
    created_at TEXT NOT NULL
);

-- Primitive 2: Declarative Bots & Execution Audit (Bots & Activity views)
CREATE TABLE IF NOT EXISTS bots (
    id TEXT PRIMARY KEY,
    slug TEXT UNIQUE NOT NULL,
    name TEXT NOT NULL,
    role TEXT NOT NULL,
    enabled INTEGER NOT NULL DEFAULT 1,
    card_json TEXT NOT NULL,
    owner_email TEXT NOT NULL DEFAULT '',
    visibility TEXT NOT NULL DEFAULT 'shared',
    allowed_groups_json TEXT NOT NULL DEFAULT '[]',
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS bot_runs (
    id TEXT PRIMARY KEY,
    correlation_id TEXT NOT NULL,
    bot_slug TEXT NOT NULL,
    trigger_type TEXT NOT NULL,
    hop_count INTEGER NOT NULL DEFAULT 1,
    llm_model_used TEXT,
    input_tokens INTEGER DEFAULT 0,
    output_tokens INTEGER DEFAULT 0,
    estimated_cost_usd REAL DEFAULT 0.0,
    status TEXT NOT NULL,
    summary TEXT,
    triggered_by_email TEXT NOT NULL DEFAULT '',
    started_at TEXT NOT NULL,
    finished_at TEXT
);

CREATE TABLE IF NOT EXISTS events_log (
    id TEXT PRIMARY KEY,
    correlation_id TEXT NOT NULL,
    source_slug TEXT NOT NULL,
    target_slug TEXT,
    event_type TEXT NOT NULL,
    payload_json TEXT NOT NULL,
    created_at TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_events_corr ON events_log(correlation_id, created_at);

-- Primitive 3: Schema-Less Collections & Full-Text Search
CREATE TABLE IF NOT EXISTS collections (
    slug TEXT PRIMARY KEY,
    description TEXT NOT NULL,
    schema_hint_json TEXT,
    created_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS collection_documents (
    id TEXT PRIMARY KEY,
    collection TEXT NOT NULL,
    external_key TEXT,
    search_text TEXT NOT NULL DEFAULT '',
    doc_json TEXT NOT NULL,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL,
    UNIQUE(collection, external_key)
);
CREATE INDEX IF NOT EXISTS idx_docs_coll_updated ON collection_documents(collection, updated_at);

-- External-content FTS5 columns must match collection_documents column names directly.
CREATE VIRTUAL TABLE IF NOT EXISTS collection_documents_fts USING fts5(
    id UNINDEXED,
    collection UNINDEXED,
    search_text,
    content='collection_documents',
    content_rowid='rowid'
);

CREATE TRIGGER IF NOT EXISTS trg_collection_documents_ai AFTER INSERT ON collection_documents BEGIN
    INSERT INTO collection_documents_fts(rowid, id, collection, search_text)
    VALUES (new.rowid, new.id, new.collection, new.search_text);
END;

CREATE TRIGGER IF NOT EXISTS trg_collection_documents_ad AFTER DELETE ON collection_documents BEGIN
    INSERT INTO collection_documents_fts(collection_documents_fts, rowid, id, collection, search_text)
    VALUES ('delete', old.rowid, old.id, old.collection, old.search_text);
END;

CREATE TRIGGER IF NOT EXISTS trg_collection_documents_au AFTER UPDATE ON collection_documents BEGIN
    INSERT INTO collection_documents_fts(collection_documents_fts, rowid, id, collection, search_text)
    VALUES ('delete', old.rowid, old.id, old.collection, old.search_text);
    INSERT INTO collection_documents_fts(rowid, id, collection, search_text)
    VALUES (new.rowid, new.id, new.collection, new.search_text);
END;

-- Primitive 4: Human Approval Queue & Style Learning (Approvals view)
CREATE TABLE IF NOT EXISTS approvals_outbox (
    id TEXT PRIMARY KEY,
    correlation_id TEXT NOT NULL,
    bot_slug TEXT NOT NULL,
    target_account_slug TEXT NOT NULL,
    action_type TEXT NOT NULL,
    status TEXT NOT NULL CHECK (status IN (
        'pending', 'approved', 'executed', 'rejected', 'superseded'
    )),
    payload_json TEXT NOT NULL,
    edited_payload_json TEXT,
    source_url TEXT,
    source_excerpt TEXT,
    escalation_note TEXT,
    approved_by TEXT,
    telegram_chat_id TEXT,
    telegram_message_id INTEGER,
    error_message TEXT,
    created_at TEXT NOT NULL,
    resolved_at TEXT
);

CREATE TABLE IF NOT EXISTS style_memory (
    id TEXT PRIMARY KEY,
    scope_slug TEXT NOT NULL,
    rule_text TEXT NOT NULL,
    example_diff_json TEXT,
    active INTEGER NOT NULL DEFAULT 1,
    created_at TEXT NOT NULL
);

-- Primitive 5: Dynamic Dual-Mode Views (Pages view)
CREATE TABLE IF NOT EXISTS pages (
    id TEXT PRIMARY KEY,
    slug TEXT UNIQUE NOT NULL,
    title TEXT NOT NULL,
    icon TEXT NOT NULL DEFAULT 'file-text',
    render_mode TEXT NOT NULL CHECK (render_mode IN ('declarative_json', 'sandboxed_html')),
    content_payload TEXT NOT NULL,
    allowed_collections_json TEXT NOT NULL,
    owner_bot_slug TEXT NOT NULL,
    created_by_email TEXT NOT NULL DEFAULT '',
    visibility TEXT NOT NULL DEFAULT 'shared',
    allowed_groups_json TEXT NOT NULL DEFAULT '[]',
    pinned INTEGER NOT NULL DEFAULT 1,
    updated_at TEXT NOT NULL
);
