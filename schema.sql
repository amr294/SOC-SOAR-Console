-- ============================================================
-- SOC SOAR PLATFORM DATABASE SCHEMA
-- SQLite
-- ============================================================

PRAGMA foreign_keys = ON;

-- ============================================================
-- 1. ANALYSTS
-- ============================================================

CREATE TABLE IF NOT EXISTS analysts (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT NOT NULL UNIQUE,
    availability TEXT NOT NULL DEFAULT 'Away / Offline'
        CHECK (availability IN ('Available', 'Away / Offline')),
    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);

-- ============================================================
-- 2. ALERTS
-- ============================================================

CREATE TABLE IF NOT EXISTS alerts (
    id TEXT PRIMARY KEY,
    source TEXT NOT NULL,
    source_event_id TEXT,
    rule_id TEXT,
    rule_desc TEXT NOT NULL,
    
    source_severity INTEGER,
    
    severity TEXT NOT NULL
        CHECK (severity IN ('CRITICAL', 'HIGH', 'MEDIUM', 'LOW')),

    state TEXT NOT NULL DEFAULT 'NEW'
        CHECK (state IN (
            'NEW',
            'ASSIGNED',
            'INVESTIGATING',
            'CLOSED',
            'ESCALATED'
        )),

    assigned_to INTEGER,

    src_ip TEXT,
    dst_ip TEXT,
    service TEXT,
    action TEXT,
    agent TEXT,

    raw_event TEXT,
    
    event_timestamp TEXT,
    
    disposition TEXT,

    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,

    FOREIGN KEY (assigned_to)
        REFERENCES analysts(id)
        ON DELETE SET NULL
);

CREATE INDEX IF NOT EXISTS idx_alerts_state
    ON alerts(state);

CREATE INDEX IF NOT EXISTS idx_alerts_severity
    ON alerts(severity);

CREATE INDEX IF NOT EXISTS idx_alerts_assigned_to
    ON alerts(assigned_to);

CREATE INDEX IF NOT EXISTS idx_alerts_created_at
    ON alerts(created_at);

CREATE UNIQUE INDEX IF NOT EXISTS idx_alerts_source_event
    ON alerts(source, source_event_id)
    WHERE source_event_id IS NOT NULL;

CREATE INDEX IF NOT EXISTS idx_alerts_event_timestamp
    ON alerts(event_timestamp);

-- ============================================================
-- 3. INVESTIGATIONS
-- ============================================================

CREATE TABLE IF NOT EXISTS investigations (
    id INTEGER PRIMARY KEY AUTOINCREMENT,

    alert_id TEXT NOT NULL UNIQUE,

    notes TEXT NOT NULL DEFAULT '',
    findings TEXT NOT NULL DEFAULT '',
    evidence TEXT NOT NULL DEFAULT '',

    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,

    FOREIGN KEY (alert_id)
        REFERENCES alerts(id)
        ON DELETE CASCADE
);

-- ============================================================
-- 4. IOCs
-- ============================================================

CREATE TABLE IF NOT EXISTS iocs (
    id INTEGER PRIMARY KEY AUTOINCREMENT,

    value TEXT NOT NULL UNIQUE,
    type TEXT NOT NULL,

    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX IF NOT EXISTS idx_iocs_value
    ON iocs(value);

CREATE INDEX IF NOT EXISTS idx_iocs_type
    ON iocs(type);

-- ============================================================
-- 5. ALERT <-> IOC RELATIONSHIP
-- ============================================================

CREATE TABLE IF NOT EXISTS alert_iocs (
    alert_id TEXT NOT NULL,
    ioc_id INTEGER NOT NULL,

    PRIMARY KEY (alert_id, ioc_id),

    FOREIGN KEY (alert_id)
        REFERENCES alerts(id)
        ON DELETE CASCADE,

    FOREIGN KEY (ioc_id)
        REFERENCES iocs(id)
        ON DELETE CASCADE
);

CREATE INDEX IF NOT EXISTS idx_alert_iocs_ioc
    ON alert_iocs(ioc_id);

-- ============================================================
-- 6. IOC INTELLIGENCE CACHE
-- ============================================================

CREATE TABLE IF NOT EXISTS ioc_intelligence (
    id INTEGER PRIMARY KEY AUTOINCREMENT,

    ioc_id INTEGER NOT NULL UNIQUE,

    status TEXT NOT NULL DEFAULT 'Unknown'
        CHECK (status IN (
            'Unknown',
            'Requested',
            'Cached Intelligence Available',
            'Failed'
        )),

    reputation TEXT,
    source TEXT,
    score TEXT,

    first_seen TEXT,
    last_checked TEXT,

    raw_data TEXT,

    FOREIGN KEY (ioc_id)
        REFERENCES iocs(id)
        ON DELETE CASCADE
);

CREATE INDEX IF NOT EXISTS idx_ioc_intelligence_status
    ON ioc_intelligence(status);

-- ============================================================
-- 7. ENRICHMENT REQUESTS
-- ============================================================

CREATE TABLE IF NOT EXISTS enrichment_requests (
    id INTEGER PRIMARY KEY AUTOINCREMENT,

    ioc_id INTEGER NOT NULL,
    alert_id TEXT,

    requested_by INTEGER NOT NULL,

    status TEXT NOT NULL DEFAULT 'Requested'
        CHECK (status IN (
            'Requested',
            'In Progress',
            'Completed',
            'Failed'
        )),

    requested_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
    completed_at TEXT,

    FOREIGN KEY (ioc_id)
        REFERENCES iocs(id)
        ON DELETE CASCADE,

    FOREIGN KEY (alert_id)
        REFERENCES alerts(id)
        ON DELETE SET NULL,

    FOREIGN KEY (requested_by)
        REFERENCES analysts(id)
        ON DELETE RESTRICT
);

CREATE INDEX IF NOT EXISTS idx_enrichment_requests_ioc
    ON enrichment_requests(ioc_id);

CREATE INDEX IF NOT EXISTS idx_enrichment_requests_status
    ON enrichment_requests(status);

-- ============================================================
-- 8. REPORTS
-- ============================================================

CREATE TABLE IF NOT EXISTS reports (
    id TEXT PRIMARY KEY,

    alert_id TEXT NOT NULL,
    analyst_id INTEGER NOT NULL,

    severity TEXT NOT NULL,

    status TEXT NOT NULL DEFAULT 'Awaiting Management',

    summary TEXT NOT NULL,
    evidence TEXT NOT NULL,
    findings TEXT NOT NULL,
    recommendation TEXT NOT NULL,

    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,

    FOREIGN KEY (alert_id)
        REFERENCES alerts(id)
        ON DELETE CASCADE,

    FOREIGN KEY (analyst_id)
        REFERENCES analysts(id)
        ON DELETE RESTRICT
);

CREATE INDEX IF NOT EXISTS idx_reports_alert
    ON reports(alert_id);

CREATE INDEX IF NOT EXISTS idx_reports_analyst
    ON reports(analyst_id);

-- ============================================================
-- 9. AUDIT LOG
-- ============================================================

CREATE TABLE IF NOT EXISTS audit_log (
    id INTEGER PRIMARY KEY AUTOINCREMENT,

    timestamp TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,

    analyst_id INTEGER,

    action TEXT NOT NULL,

    alert_id TEXT,

    details TEXT,

    FOREIGN KEY (analyst_id)
        REFERENCES analysts(id)
        ON DELETE SET NULL,

    FOREIGN KEY (alert_id)
        REFERENCES alerts(id)
        ON DELETE SET NULL
);

CREATE INDEX IF NOT EXISTS idx_audit_log_alert
    ON audit_log(alert_id);

CREATE INDEX IF NOT EXISTS idx_audit_log_timestamp
    ON audit_log(timestamp);