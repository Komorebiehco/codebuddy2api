"""PostgreSQL stores used when a managed database URL is configured.

The local SQLite stores remain the default for development and tests.  This
module deliberately keeps the same public store contracts so the gateway does
not need a second management implementation.
"""
from __future__ import annotations

import copy
import json
import threading
import time
import uuid

from .audit_store import METRICS, _CLEANUP_BATCH, _CLEANUP_SECONDS, number, safe_attempt, safe_label
from .control_store import ConflictError, _identifier, validate_model
from .settings import validate_settings


def _json(value):
    if isinstance(value, str):
        return json.loads(value)
    return value


def _json_text(value) -> str:
    return json.dumps(value, ensure_ascii=False, separators=(",", ":"), allow_nan=False)


def _connect(database_url):
    try:
        import psycopg
        from psycopg.rows import dict_row
    except ImportError as exc:
        raise RuntimeError("PostgreSQL 已配置，但 psycopg 未安装") from exc
    # Supabase's transaction pooler is compatible with a single guarded
    # connection; disabling prepared statements avoids transaction-mode issues.
    return psycopg.connect(database_url, autocommit=True, prepare_threshold=None,
                           row_factory=dict_row)


class PostgresControlStore:
    SCHEMA_VERSION = 1

    def __init__(self, database_url):
        self._lock = threading.RLock()
        self._db = _connect(database_url)
        try:
            with self._db.transaction():
                self._db.execute("""
                    CREATE TABLE IF NOT EXISTS codebuddy_control (
                        id INTEGER PRIMARY KEY CHECK (id = 1),
                        revision BIGINT NOT NULL,
                        payload JSONB NOT NULL
                    )
                """)
                self._db.execute("""
                    INSERT INTO codebuddy_control (id, revision, payload)
                    VALUES (1, 0, CAST(%s AS jsonb))
                    ON CONFLICT (id) DO NOTHING
                """, (_json_text({"settings": {}, "models": {}, "credentials": {}}),))
                self._snapshot = self._load()
        except Exception:
            self._db.close()
            raise

    @staticmethod
    def _load_data(revision, data):
        if not isinstance(data, dict) or set(data) != {"settings", "models", "credentials"}:
            raise ValueError("管理数据库状态无效")
        validate_settings(data["settings"])
        if not isinstance(data["models"], dict) or not isinstance(data["credentials"], dict):
            raise ValueError("管理数据库策略无效")
        for source, rule in data["models"].items():
            validate_model(source, rule, data["models"])
        for identity, metadata in data["credentials"].items():
            try:
                _identifier(identity, "账号指纹")
            except ValueError:
                raise ValueError("管理数据库凭证元数据无效") from None
            if not isinstance(metadata, dict):
                raise ValueError("管理数据库凭证元数据无效")
            if set(metadata) - {"enabled", "label"} or type(metadata.get("enabled")) is not bool:
                raise ValueError("管理数据库凭证元数据无效")
        return {"revision": int(revision), **data}

    def _load(self):
        row = self._db.execute(
            "SELECT revision, payload FROM codebuddy_control WHERE id=1"
        ).fetchone()
        if row is None:
            raise ValueError("管理数据库状态缺失")
        return self._load_data(row["revision"], _json(row["payload"]))

    def snapshot(self):
        with self._lock:
            return copy.deepcopy(self._snapshot)

    def _update(self, revision, change):
        with self._lock:
            with self._db.transaction():
                row = self._db.execute(
                    "SELECT revision, payload FROM codebuddy_control WHERE id=1 FOR UPDATE"
                ).fetchone()
                if row is None:
                    raise ValueError("管理数据库状态缺失")
                state = self._load_data(row["revision"], _json(row["payload"]))
                if revision is not None and (type(revision) is not int or revision != state["revision"]):
                    raise ConflictError("配置已更新，请刷新后重试")
                change(state)
                state["revision"] += 1
                payload = {key: state[key] for key in ("settings", "models", "credentials")}
                self._db.execute(
                    "UPDATE codebuddy_control SET revision=%s, payload=CAST(%s AS jsonb) WHERE id=1",
                    (state["revision"], _json_text(payload)),
                )
                published = copy.deepcopy(state)
            self._snapshot = published
            return copy.deepcopy(published)

    def update_settings(self, values, revision):
        if type(revision) is not int:
            raise ValueError("revision 必须为整数")
        clean = validate_settings(values)
        return self._update(revision, lambda state: state["settings"].update(clean))

    def update_model(self, source, rule, revision, known_models=()):
        if type(revision) is not int:
            raise ValueError("revision 必须为整数")

        def change(state):
            state["models"][source] = validate_model(source, rule, state["models"], known_models)

        return self._update(revision, change)

    def set_credential(self, account_key, enabled):
        _identifier(account_key, "账号指纹")
        if type(enabled) is not bool:
            raise ValueError("enabled 必须为布尔值")
        return self._update(
            None,
            lambda state: state["credentials"].setdefault(account_key, {}).update(enabled=enabled),
        )

    def close(self):
        with self._lock:
            self._db.close()


class PostgresAuditStore:
    SCHEMA_VERSION = 1

    def __init__(self, database_url, max_bytes=256 * 1024 * 1024, retention_days=30,
                 preview_limit=8192):
        self._validate(max_bytes, retention_days, preview_limit)
        self.max_bytes, self.retention_days, self.preview_limit = max_bytes, retention_days, preview_limit
        self._lock = threading.Lock()
        self._health_lock = threading.Lock()
        self.failure_count = self.dropped_records = 0
        self.last_error = None
        self._closed = False
        self._epoch = 0
        self._db = _connect(database_url)
        try:
            with self._db.transaction():
                self._db.execute("""
                    CREATE TABLE IF NOT EXISTS codebuddy_audit_state (
                        id INTEGER PRIMARY KEY CHECK (id = 1),
                        epoch BIGINT NOT NULL,
                        detail_generation BIGINT NOT NULL,
                        cleared_at DOUBLE PRECISION NOT NULL
                    )
                """)
                self._db.execute("""
                    INSERT INTO codebuddy_audit_state VALUES (1, 0, 0, 0)
                    ON CONFLICT (id) DO NOTHING
                """)
                self._db.execute("""
                    CREATE TABLE IF NOT EXISTS codebuddy_audit_ingest (
                        id TEXT PRIMARY KEY,
                        kind TEXT NOT NULL
                    )
                """)
                self._db.execute("""
                    CREATE TABLE IF NOT EXISTS codebuddy_audit_requests (
                        id TEXT PRIMARY KEY,
                        started_at DOUBLE PRECISION NOT NULL,
                        model TEXT,
                        profile TEXT,
                        credential TEXT,
                        outcome TEXT,
                        status_code INTEGER,
                        payload JSONB NOT NULL,
                        logical_bytes BIGINT NOT NULL
                    )
                """)
                self._db.execute("""
                    CREATE INDEX IF NOT EXISTS codebuddy_audit_requests_time
                    ON codebuddy_audit_requests (started_at, id)
                """)
                self._db.execute("""
                    CREATE TABLE IF NOT EXISTS codebuddy_audit_attempts (
                        request_id TEXT NOT NULL REFERENCES codebuddy_audit_requests(id) ON DELETE CASCADE,
                        ordinal INTEGER NOT NULL,
                        payload JSONB NOT NULL,
                        PRIMARY KEY (request_id, ordinal)
                    )
                """)
                self._db.execute("""
                    CREATE TABLE IF NOT EXISTS codebuddy_audit_events (
                        id TEXT PRIMARY KEY,
                        started_at DOUBLE PRECISION NOT NULL,
                        kind TEXT NOT NULL,
                        action TEXT,
                        payload JSONB NOT NULL,
                        logical_bytes BIGINT NOT NULL
                    )
                """)
                self._db.execute("""
                    CREATE INDEX IF NOT EXISTS codebuddy_audit_events_time
                    ON codebuddy_audit_events (started_at, id)
                """)
                self._db.execute("""
                    CREATE TABLE IF NOT EXISTS codebuddy_audit_accounting (
                        id INTEGER PRIMARY KEY CHECK (id = 1),
                        logical_bytes BIGINT NOT NULL,
                        request_count BIGINT NOT NULL,
                        event_count BIGINT NOT NULL,
                        ingest_count BIGINT NOT NULL,
                        cleanup_target BIGINT
                    )
                """)
                self._db.execute("""
                    INSERT INTO codebuddy_audit_accounting
                    VALUES (1, 0, 0, 0, 0, NULL)
                    ON CONFLICT (id) DO NOTHING
                """)
                for table in ("stats_hourly", "stats_daily", "stats_totals"):
                    self._db.execute(f"""
                        CREATE TABLE IF NOT EXISTS codebuddy_audit_{table} (
                            bucket BIGINT NOT NULL,
                            dimension TEXT NOT NULL,
                            dimension_key TEXT NOT NULL,
                            payload JSONB NOT NULL,
                            PRIMARY KEY (bucket, dimension, dimension_key)
                        )
                    """)
                self._epoch = self._db.execute(
                    "SELECT epoch FROM codebuddy_audit_state WHERE id=1"
                ).fetchone()["epoch"]
        except Exception:
            self._db.close()
            raise

    @staticmethod
    def _validate(max_bytes, retention_days, preview_limit):
        if isinstance(max_bytes, bool) or not isinstance(max_bytes, int) or not 0 <= max_bytes <= 2**40:
            raise ValueError("invalid max_bytes")
        if isinstance(retention_days, bool) or not isinstance(retention_days, int) or not 1 <= retention_days <= 36500:
            raise ValueError("invalid retention_days")
        if isinstance(preview_limit, bool) or not isinstance(preview_limit, int) or not 0 <= preview_limit <= 65536:
            raise ValueError("invalid preview_limit")

    def _fault(self, exc, dropped=False):
        with self._health_lock:
            self.failure_count += 1
            self.dropped_records += int(dropped)
            self.last_error = type(exc).__name__

    def note_failure(self, code="ObservationError"):
        self._fault(RuntimeError(), dropped=True)

    def _run(self, callback, fallback=None, write=False, dropped=False, on_commit=None):
        if not self._lock.acquire(timeout=0.25):
            self._fault(TimeoutError(), dropped=dropped)
            return fallback
        try:
            if self._closed:
                raise RuntimeError("closed")
            if write:
                with self._db.transaction():
                    result = callback()
            else:
                result = callback()
            if on_commit is not None:
                on_commit(result)
            return result
        except Exception as exc:
            self._fault(exc, dropped=dropped)
            return fallback
        finally:
            self._lock.release()

    @property
    def epoch(self):
        return self.ticket()["epoch"]

    def ticket(self):
        def fetch():
            row = self._db.execute(
                "SELECT epoch, detail_generation FROM codebuddy_audit_state WHERE id=1"
            ).fetchone()
            self._epoch = int(row["epoch"])
            return {"epoch": self._epoch, "detail_generation": int(row["detail_generation"])}

        return self._run(fetch, {"epoch": self._epoch, "detail_generation": -1})

    @staticmethod
    def _empty_stats():
        return {"requests": 0, "success": 0, "error": 0, "cancelled": 0,
                **{key: None for key in METRICS},
                **{key + "_known": 0 for key in METRICS},
                "duration_ms_sum": 0, "duration_ms_known": 0,
                "first_token_ms_sum": 0, "first_token_ms_known": 0}

    @staticmethod
    def _merge(target, source):
        for key, value in source.items():
            if isinstance(value, (int, float)):
                target[key] = (target.get(key) or 0) + value
        return target

    def _aggregate(self, record):
        increment = self._empty_stats()
        increment["requests"] = 1
        increment[record["outcome"]] = 1
        for key in METRICS:
            increment[key] = record[key]
            increment[key + "_known"] = int(record[key] is not None)
        for key in ("duration_ms", "first_token_ms"):
            increment[key + "_sum"] = record[key] or 0
            increment[key + "_known"] = int(record[key] is not None)
        dimensions = [("global", "")]
        dimensions += [(key, record.get("public_model" if key == "model" else key) or "")
                       for key in ("model", "profile", "credential")]
        for table, seconds in (("stats_hourly", 3600), ("stats_daily", 86400), ("stats_totals", 0)):
            bucket = int(record["started_at"] // seconds) * seconds if seconds else 0
            for dimension, key in dimensions:
                full = f"codebuddy_audit_{table}"
                old = self._db.execute(
                    f"SELECT payload FROM {full} WHERE bucket=%s AND dimension=%s AND dimension_key=%s",
                    (bucket, dimension, key),
                ).fetchone()
                stats = self._merge(_json(old["payload"]) if old else self._empty_stats(), increment)
                self._db.execute(
                    f"""
                    INSERT INTO {full} (bucket, dimension, dimension_key, payload)
                    VALUES (%s, %s, %s, CAST(%s AS jsonb))
                    ON CONFLICT (bucket, dimension, dimension_key) DO UPDATE SET payload=EXCLUDED.payload
                    """,
                    (bucket, dimension, key, _json_text(stats)),
                )

    def _sanitize_record(self, source):
        result = {key: safe_label(source.get(key)) for key in
                  ("upstream_model", "profile", "credential", "protocol", "error_code", "usage_source")}
        result["public_model"] = safe_label(source.get("public_model", source.get("model")))
        result["model"] = result["public_model"]
        result["id"] = safe_label(source.get("id", source.get("event_id"))) or uuid.uuid4().hex
        result["event_id"] = result["id"]
        result["epoch"] = source.get("epoch", self._epoch)
        result["started_at"] = number(source.get("started_at"))
        if result["started_at"] is None:
            result["started_at"] = time.time()
        result["outcome"] = source.get("outcome") if source.get("outcome") in ("success", "error", "cancelled") else "error"
        result["streaming"] = source.get("streaming") is True
        for key in (*METRICS, "duration_ms", "first_token_ms", "status_code"):
            result[key] = number(source.get(key))
        if result["cache_read_tokens"] is None:
            result["cache_read_tokens"] = number(source.get("cache", source.get("cached_tokens")))
        if result["reasoning_tokens"] is None:
            result["reasoning_tokens"] = number(source.get("reasoning"))
        sources = source.get("usage_sources")
        result["usage_sources"] = {key: safe_label(sources.get(key)) for key in METRICS
                                   if safe_label(sources.get(key)) is not None} if isinstance(sources, dict) else {}
        result["attempts"] = []
        used = 0
        attempts = source.get("attempts", [])
        if isinstance(attempts, (tuple, list)):
            for item in attempts[:32]:
                attempt = safe_attempt(item)
                used += len(_json_text(attempt).encode())
                if used > self.preview_limit:
                    break
                if attempt:
                    result["attempts"].append(attempt)
        return result

    def _accounting(self):
        return self._db.execute(
            "SELECT logical_bytes, cleanup_target FROM codebuddy_audit_accounting WHERE id=1"
        ).fetchone()

    def _delete_detail(self, table, record_id):
        row = self._db.execute(
            f"SELECT logical_bytes FROM codebuddy_audit_{table} WHERE id=%s", (record_id,)
        ).fetchone()
        if row is None:
            return
        if table == "requests":
            self._db.execute("DELETE FROM codebuddy_audit_requests WHERE id=%s", (record_id,))
        else:
            self._db.execute("DELETE FROM codebuddy_audit_events WHERE id=%s", (record_id,))
        self._db.execute(
            f"""
            UPDATE codebuddy_audit_accounting
            SET logical_bytes=logical_bytes-%s,
                {"request_count" if table == "requests" else "event_count"}=
                {"request_count" if table == "requests" else "event_count"}-1
            WHERE id=1
            """,
            (row["logical_bytes"],),
        )

    def _oldest(self, cutoff=None):
        rows = []
        for table in ("requests", "events"):
            full = f"codebuddy_audit_{table}"
            condition = " WHERE started_at < %s" if cutoff is not None else ""
            params = (cutoff, _CLEANUP_BATCH) if cutoff is not None else (_CLEANUP_BATCH,)
            rows.extend(
                (row["started_at"], row["id"], table, row["logical_bytes"])
                for row in self._db.execute(
                    f"SELECT started_at, id, logical_bytes FROM {full}{condition} "
                    "ORDER BY started_at, id LIMIT %s", params
                ).fetchall()
            )
        return sorted(rows)[:_CLEANUP_BATCH]

    def _expire(self, retention_days=None, deadline=None):
        cutoff = time.time() - (self.retention_days if retention_days is None else retention_days) * 86400
        deadline = deadline or (time.monotonic() + _CLEANUP_SECONDS)
        for _, record_id, table, _ in self._oldest(cutoff):
            if time.monotonic() >= deadline:
                break
            self._delete_detail(table, record_id)

    def _cleanup_pending(self, budget=None, retention_days=None):
        budget = self.max_bytes if budget is None else budget
        cutoff = time.time() - (self.retention_days if retention_days is None else retention_days) * 86400
        accounting = self._accounting()
        return bool(
            accounting["logical_bytes"] > budget or accounting["cleanup_target"] is not None
            or self._db.execute(
                "SELECT 1 FROM codebuddy_audit_requests WHERE started_at < %s LIMIT 1", (cutoff,)
            ).fetchone()
            or self._db.execute(
                "SELECT 1 FROM codebuddy_audit_events WHERE started_at < %s LIMIT 1", (cutoff,)
            ).fetchone()
        )

    def _prune(self, max_bytes=None, retention_days=None):
        deadline = time.monotonic() + _CLEANUP_SECONDS
        self._expire(retention_days, deadline)
        budget = self.max_bytes if max_bytes is None else max_bytes
        accounting = self._accounting()
        used, target = accounting["logical_bytes"], accounting["cleanup_target"]
        if max_bytes is not None:
            target = None
        if used > budget and target is None:
            target = budget * 9 // 10
        if target is not None:
            target = min(target, budget)
            for _, record_id, table, cost in self._oldest():
                if used <= target or (used <= budget and used - cost < target):
                    target = None
                    break
                if time.monotonic() >= deadline:
                    break
                self._delete_detail(table, record_id)
                used -= cost
            if used <= (target if target is not None else budget):
                target = None
        self._db.execute(
            "UPDATE codebuddy_audit_accounting SET cleanup_target=%s WHERE id=1", (target,)
        )

    def record_request(self, record):
        def commit():
            data = self._sanitize_record(record)
            state = self._db.execute("SELECT * FROM codebuddy_audit_state WHERE id=1").fetchone()
            if data["epoch"] != state["epoch"]:
                return {"ok": True, "recorded": False, "reason": "stale_epoch"}
            inserted = self._db.execute(
                """
                INSERT INTO codebuddy_audit_ingest (id, kind) VALUES (%s, 'request')
                ON CONFLICT (id) DO NOTHING
                """, (data["id"],)
            ).rowcount
            if not inserted:
                return {"ok": True, "recorded": False, "reason": "duplicate"}
            self._db.execute(
                "UPDATE codebuddy_audit_accounting SET ingest_count=ingest_count+1 WHERE id=1"
            )
            self._aggregate(data)
            generation = record.get("detail_generation")
            keep = (data["started_at"] > state["cleared_at"] and
                    (generation is None or generation == state["detail_generation"]))
            if keep:
                payload = _json_text(data)
                logical_bytes = len(payload.encode()) + sum(
                    len(_json_text(a).encode()) + 32 for a in data["attempts"]
                ) + 256
                self._db.execute(
                    """
                    INSERT INTO codebuddy_audit_requests
                    (id, started_at, model, profile, credential, outcome, status_code, payload, logical_bytes)
                    VALUES (%s, %s, %s, %s, %s, %s, %s, CAST(%s AS jsonb), %s)
                    """,
                    (data["id"], data["started_at"], data["model"], data["profile"], data["credential"],
                     data["outcome"], data["status_code"], payload, logical_bytes),
                )
                for ordinal, attempt in enumerate(data["attempts"]):
                    self._db.execute(
                        """
                        INSERT INTO codebuddy_audit_attempts (request_id, ordinal, payload)
                        VALUES (%s, %s, CAST(%s AS jsonb))
                        """, (data["id"], ordinal, _json_text(attempt))
                    )
                self._db.execute(
                    """
                    UPDATE codebuddy_audit_accounting
                    SET logical_bytes=logical_bytes+%s, request_count=request_count+1
                    WHERE id=1
                    """, (logical_bytes,)
                )
            self._prune()
            details = bool(self._db.execute(
                "SELECT 1 FROM codebuddy_audit_requests WHERE id=%s", (data["id"],)
            ).fetchone())
            return {"ok": True, "recorded": True, "details": details}

        return self._run(commit, {"ok": False, "recorded": False, "reason": "storage_failure"},
                         write=True, dropped=True)

    def event(self, kind, action, details=None):
        if kind not in ("runtime", "admin"):
            raise ValueError("invalid event kind")
        started_at = time.time()

        def commit():
            source = details if isinstance(details, dict) else {}
            state = self._db.execute("SELECT * FROM codebuddy_audit_state WHERE id=1").fetchone()
            if source.get("epoch", state["epoch"]) != state["epoch"]:
                return {"ok": True, "recorded": False, "reason": "stale_epoch"}
            event_id = safe_label(source.get("event_id", source.get("id"))) or uuid.uuid4().hex
            inserted = self._db.execute(
                """
                INSERT INTO codebuddy_audit_ingest (id, kind) VALUES (%s, %s)
                ON CONFLICT (id) DO NOTHING
                """, (event_id, kind)
            ).rowcount
            if not inserted:
                return {"ok": True, "recorded": False, "reason": "duplicate"}
            self._db.execute(
                "UPDATE codebuddy_audit_accounting SET ingest_count=ingest_count+1 WHERE id=1"
            )
            if (started_at <= state["cleared_at"] or
                    source.get("detail_generation", state["detail_generation"]) != state["detail_generation"]):
                return {"ok": True, "recorded": False, "reason": "details_cleared"}
            data = {"id": event_id, "kind": kind, "action": safe_label(action),
                    "started_at": started_at, "details": safe_attempt(source)}
            payload = _json_text(data)
            logical_bytes = len(payload.encode()) + 128
            self._db.execute(
                """
                INSERT INTO codebuddy_audit_events
                (id, started_at, kind, action, payload, logical_bytes)
                VALUES (%s, %s, %s, %s, CAST(%s AS jsonb), %s)
                """, (event_id, started_at, kind, data["action"], payload, logical_bytes)
            )
            self._db.execute(
                """
                UPDATE codebuddy_audit_accounting
                SET logical_bytes=logical_bytes+%s, event_count=event_count+1
                WHERE id=1
                """, (logical_bytes,)
            )
            self._prune()
            return {"ok": True, "recorded": True, "id": event_id}

        return self._run(commit, {"ok": False, "recorded": False}, write=True, dropped=True)

    def list_records(self, kind="request", limit=50, cursor=None, **filters):
        if kind not in ("request", "runtime", "admin"):
            raise ValueError("invalid record kind")
        limit = max(1, min(int(limit), 200))
        table = "requests" if kind == "request" else "events"
        clauses, params = ["started_at >= %s"], [None]
        if kind != "request":
            clauses.append("kind = %s")
            params.append(kind)
        if cursor:
            try:
                stamp, record_id = json.loads(cursor)
                if number(stamp) is None or not safe_label(record_id):
                    raise ValueError()
            except (ValueError, TypeError):
                raise ValueError("invalid cursor") from None
            clauses.append("(started_at < %s OR (started_at = %s AND id < %s))")
            params.extend((stamp, stamp, record_id))
        if kind == "request":
            for key in ("model", "profile", "credential", "outcome", "status_code"):
                value = filters.get(key)
                if value is not None and value != "":
                    clauses.append(f"{key} = %s")
                    params.append(value)
            status = filters.get("status")
            if status is not None and status != "":
                column = "outcome" if status in ("success", "error", "cancelled") else "status_code"
                clauses.append(f"{column} = %s")
                params.append(status)
        for key, op in (("since", ">="), ("until", "<=")):
            if filters.get(key) is not None:
                clauses.append(f"started_at {op} %s")
                params.append(float(filters[key]))
        if filters.get("search"):
            term = str(filters["search"])[:160].replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_")
            columns = ("id", "model", "profile", "credential") if kind == "request" else ("id", "action")
            clauses.append("(" + " OR ".join(f"{col} LIKE %s ESCAPE %s" for col in columns) + ")")
            for _ in columns:
                params.extend(["%" + term + "%", "\\"])
        where = " WHERE " + " AND ".join(clauses)

        def fetch():
            self._prune()
            params[0] = time.time() - self.retention_days * 86400
            rows = self._db.execute(
                f"""
                SELECT payload, started_at, id
                FROM codebuddy_audit_{table}{where}
                ORDER BY started_at DESC, id DESC
                LIMIT %s
                """, (*params, limit + 1)
            ).fetchall()
            more = len(rows) > limit
            rows = rows[:limit]
            return {
                "items": [_json(row["payload"]) for row in rows],
                "next_cursor": json.dumps([rows[-1]["started_at"], rows[-1]["id"]]) if more else None,
                "has_more": more,
            }

        return self._run(fetch, {"items": [], "next_cursor": None, "has_more": False, "degraded": True},
                         write=True)

    def get_request(self, id):
        def fetch():
            self._prune()
            row = self._db.execute(
                """
                SELECT payload FROM codebuddy_audit_requests
                WHERE id=%s AND started_at >= %s
                """, (id, time.time() - self.retention_days * 86400)
            ).fetchone()
            return _json(row["payload"]) if row else None

        return self._run(fetch, write=True)

    def dashboard(self, days=30):
        days = int(days)
        if not 1 <= days <= 36500:
            raise ValueError("invalid days")
        now = time.time()
        start = int(now // 86400) * 86400 - (days - 1) * 86400

        def fetch():
            summary = self._empty_stats()
            series, models, profiles = [], {}, {}
            rows = self._db.execute(
                """
                SELECT bucket, dimension, dimension_key, payload
                FROM codebuddy_audit_stats_daily
                WHERE bucket >= %s AND bucket <= %s
                ORDER BY bucket
                """, (start, now)
            ).fetchall()
            for row in rows:
                stats = _json(row["payload"])
                if row["dimension"] == "global":
                    self._merge(summary, stats)
                    series.append({"bucket": row["bucket"],
                                   "date": time.strftime("%Y-%m-%d", time.gmtime(row["bucket"])),
                                   **stats})
                elif row["dimension"] in ("model", "profile"):
                    target = models if row["dimension"] == "model" else profiles
                    self._merge(target.setdefault(row["dimension_key"], self._empty_stats()), stats)
            summary["success_rate"] = summary["success"] / summary["requests"] if summary["requests"] else None
            return {"summary": summary, "series": series,
                    "models": [{"model": key, **value} for key, value in models.items()],
                    "profiles": [{"profile": key, **value} for key, value in profiles.items()],
                    "generated_at": now,
                    "range": {"days": days, "start": start, "end": now, "timezone": "UTC"}}

        return self._run(fetch, {"summary": self._empty_stats(), "series": [], "models": [], "profiles": [],
                                 "generated_at": now, "range": {"days": days, "start": start, "end": now},
                                 "degraded": True})

    def storage(self):
        def fetch():
            self._prune()
            self._epoch = int(self._db.execute(
                "SELECT epoch FROM codebuddy_audit_state WHERE id=1"
            ).fetchone()["epoch"])
            row = self._db.execute(
                """
                SELECT logical_bytes, request_count, event_count, ingest_count
                FROM codebuddy_audit_accounting WHERE id=1
                """
            ).fetchone()
            size = self._db.execute(
                "SELECT pg_database_size(current_database()) AS size"
            ).fetchone()["size"]
            return {**row, "pending_cleanup": self._cleanup_pending(),
                    "db_bytes": int(size), "wal_bytes": 0, "shm_bytes": 0}

        result = self._run(fetch, {"logical_bytes": None, "pending_cleanup": None}, write=True)
        return {"db_bytes": result.pop("db_bytes", None),
                "wal_bytes": result.pop("wal_bytes", 0),
                "shm_bytes": result.pop("shm_bytes", 0), **result,
                "max_bytes": self.max_bytes, "retention_days": self.retention_days,
                "preview_limit": self.preview_limit, "schema_version": self.SCHEMA_VERSION,
                "epoch": self._epoch, "degraded": bool(self.failure_count),
                "failure_count": self.failure_count, "dropped_records": self.dropped_records,
                "last_error": self.last_error, "closed": self._closed,
                "budget_scope": "details_logical_bytes", "fault_counter_scope": "process_lifetime",
                "automatic_vacuum": False, "backend": "postgresql",
                "lock_timeout_ms": 250, "sql_deadline_ms": 1000}

    def clear(self, scope="details"):
        if scope not in ("details", "all"):
            raise ValueError("invalid clear scope")

        def commit():
            self._db.execute("DELETE FROM codebuddy_audit_requests")
            self._db.execute("DELETE FROM codebuddy_audit_events")
            self._db.execute("DELETE FROM codebuddy_audit_attempts")
            self._db.execute("""
                UPDATE codebuddy_audit_accounting
                SET logical_bytes=0, request_count=0, event_count=0, cleanup_target=NULL
                WHERE id=1
            """)
            self._db.execute("""
                UPDATE codebuddy_audit_state
                SET detail_generation=detail_generation+1, cleared_at=%s
                WHERE id=1
            """, (time.time(),))
            if scope == "all":
                for table in ("stats_hourly", "stats_daily", "stats_totals"):
                    self._db.execute(f"DELETE FROM codebuddy_audit_{table}")
                self._db.execute("DELETE FROM codebuddy_audit_ingest")
                self._db.execute("UPDATE codebuddy_audit_state SET epoch=epoch+1 WHERE id=1")
                self._db.execute("UPDATE codebuddy_audit_accounting SET ingest_count=0 WHERE id=1")
            epoch = self._db.execute(
                "SELECT epoch FROM codebuddy_audit_state WHERE id=1"
            ).fetchone()["epoch"]
            return {"ok": True, "scope": scope, "epoch": epoch, "aggregates_preserved": scope == "details"}

        return self._run(commit, {"ok": False, "scope": scope}, write=True,
                         on_commit=lambda result: setattr(self, "_epoch", result["epoch"]))

    def configure(self, max_bytes=None, retention_days=None, preview_limit=None):
        values = (self.max_bytes if max_bytes is None else max_bytes,
                  self.retention_days if retention_days is None else retention_days,
                  self.preview_limit if preview_limit is None else preview_limit)
        self._validate(*values)

        def commit():
            current = (self.max_bytes if max_bytes is None else max_bytes,
                       self.retention_days if retention_days is None else retention_days,
                       self.preview_limit if preview_limit is None else preview_limit)
            self._prune(max_bytes=current[0], retention_days=current[1])
            return {"ok": True, "max_bytes": current[0], "retention_days": current[1],
                    "preview_limit": current[2],
                    "pending_cleanup": self._cleanup_pending(current[0], current[1])}

        def publish(result):
            self.max_bytes, self.retention_days, self.preview_limit = (
                result["max_bytes"], result["retention_days"], result["preview_limit"])

        return self._run(commit, {"ok": False}, write=True, on_commit=publish)

    def close(self):
        if self._closed:
            return
        with self._lock:
            if not self._closed:
                self._db.close()
                self._closed = True
