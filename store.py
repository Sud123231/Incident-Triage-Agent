import json
import sqlite3
import threading


class Store:
    def __init__(self, path):
        self.path = path
        self.lock = threading.RLock()
        with self.connect() as connection:
            connection.execute(
                "CREATE TABLE IF NOT EXISTS runs ("
                "run_id TEXT PRIMARY KEY, content_hash TEXT NOT NULL, state TEXT NOT NULL, "
                "initial_response TEXT)"
            )
            connection.execute(
                "CREATE TABLE IF NOT EXISTS receipts ("
                "run_id TEXT NOT NULL, receipt_id TEXT NOT NULL, content_hash TEXT NOT NULL, "
                "response_json TEXT, PRIMARY KEY(run_id, receipt_id))"
            )
            # Migrate databases created by earlier versions without deleting stored runs.
            run_columns = {row[1] for row in connection.execute("PRAGMA table_info(runs)")}
            if "initial_response" not in run_columns:
                connection.execute("ALTER TABLE runs ADD COLUMN initial_response TEXT")
            receipt_columns = {row[1] for row in connection.execute("PRAGMA table_info(receipts)")}
            if "response_json" not in receipt_columns:
                connection.execute("ALTER TABLE receipts ADD COLUMN response_json TEXT")

    def connect(self):
        connection = sqlite3.connect(self.path, timeout=10)
        connection.row_factory = sqlite3.Row
        return connection

    def get_run(self, run_id):
        with self.lock, self.connect() as connection:
            row = connection.execute("SELECT state FROM runs WHERE run_id=?", (run_id,)).fetchone()
            return json.loads(row["state"]) if row else None

    def get_create_response(self, run_id):
        with self.lock, self.connect() as connection:
            row = connection.execute(
                "SELECT initial_response FROM runs WHERE run_id=?", (run_id,)
            ).fetchone()
            return row["initial_response"] if row else None

    def create_run(self, state, initial_response):
        with self.lock, self.connect() as connection:
            connection.execute(
                "INSERT INTO runs(run_id,content_hash,state,initial_response) VALUES(?,?,?,?)",
                (state["runId"], state["content_hash"], json.dumps(state), initial_response),
            )

    def update_run(self, state):
        with self.lock, self.connect() as connection:
            connection.execute(
                "UPDATE runs SET content_hash=?,state=? WHERE run_id=?",
                (state["content_hash"], json.dumps(state), state["runId"]),
            )

    def save_receipt(self, run_id, receipt_id, content_hash, response_json):
        with self.lock, self.connect() as connection:
            connection.execute(
                "INSERT OR IGNORE INTO receipts(run_id,receipt_id,content_hash,response_json) VALUES(?,?,?,?)",
                (run_id, receipt_id, content_hash, response_json),
            )

    def commit_receipt(self, state, receipt_id, content_hash, response_json):
        """Persist updated run state and the exact receipt response in one transaction."""
        with self.lock, self.connect() as connection:
            connection.execute(
                "UPDATE runs SET content_hash=?,state=? WHERE run_id=?",
                (state["content_hash"], json.dumps(state), state["runId"]),
            )
            connection.execute(
                "INSERT INTO receipts(run_id,receipt_id,content_hash,response_json) VALUES(?,?,?,?)",
                (state["runId"], receipt_id, content_hash, response_json),
            )

    def get_receipt(self, run_id, receipt_id):
        with self.lock, self.connect() as connection:
            row = connection.execute(
                "SELECT content_hash,response_json FROM receipts WHERE run_id=? AND receipt_id=?",
                (run_id, receipt_id),
            ).fetchone()
            return dict(row) if row else None
