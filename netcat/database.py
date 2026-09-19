import sqlite3
import os
import logging
from datetime import datetime

class DatabaseManager:
    def __init__(self, db_path="netcat.db"):
        self.db_path = db_path
        self.conn = None
        self.initialize_db()

    def get_connection(self):
        try:
            conn = sqlite3.connect(self.db_path)
            conn.row_factory = sqlite3.Row
            return conn
        except Exception as e:
            logging.error(f"Failed to connect to SQLite database {self.db_path}: {e}")
            return None

    def initialize_db(self):
        conn = self.get_connection()
        if not conn:
            return
        try:
            cursor = conn.cursor()
            
            # Create threat events table
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS threat_events (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    timestamp TEXT NOT NULL,
                    src_ip TEXT NOT NULL,
                    rule TEXT NOT NULL,
                    severity TEXT NOT NULL,
                    detail TEXT
                )
            """)
            
            # Create block actions table
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS block_actions (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    timestamp TEXT NOT NULL,
                    ip TEXT NOT NULL,
                    action TEXT NOT NULL, -- "blocked", "unblocked"
                    backend TEXT NOT NULL, -- "firewall", "windivert", "both", "manual"
                    reason TEXT
                )
            """)

            # Create threat analysis table (Priority 3)
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS threat_analysis (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    alert_id INTEGER NOT NULL UNIQUE,
                    json_blob TEXT NOT NULL,
                    created_at TEXT NOT NULL,
                    FOREIGN KEY (alert_id) REFERENCES threat_events (id)
                )
            """)
            
            conn.commit()
            logging.info("Database initialized successfully.")
        except Exception as e:
            logging.error(f"Error initializing SQLite database: {e}")
        finally:
            conn.close()
 
    def log_threat_event(self, src_ip, rule, severity, detail):
        conn = self.get_connection()
        if not conn:
            return None
        try:
            cursor = conn.cursor()
            timestamp = datetime.now().isoformat()
            cursor.execute("""
                INSERT INTO threat_events (timestamp, src_ip, rule, severity, detail)
                VALUES (?, ?, ?, ?, ?)
            """, (timestamp, src_ip, rule, severity, detail))
            conn.commit()
            logging.debug(f"Logged threat: {src_ip} | {rule} | {severity}")
            return cursor.lastrowid
        except Exception as e:
            logging.error(f"Failed to log threat event in database: {e}")
            return None
        finally:
            conn.close()

    def log_threat_analysis(self, alert_id, json_blob):
        conn = self.get_connection()
        if not conn:
            return False
        try:
            cursor = conn.cursor()
            timestamp = datetime.now().isoformat()
            cursor.execute("""
                INSERT OR REPLACE INTO threat_analysis (alert_id, json_blob, created_at)
                VALUES (?, ?, ?)
            """, (alert_id, json_blob, timestamp))
            conn.commit()
            return True
        except Exception as e:
            logging.error(f"Failed to log threat analysis: {e}")
            return False
        finally:
            conn.close()

    def get_threat_analysis(self, alert_id):
        conn = self.get_connection()
        if not conn:
            return None
        try:
            cursor = conn.cursor()
            cursor.execute("SELECT json_blob FROM threat_analysis WHERE alert_id = ?", (alert_id,))
            row = cursor.fetchone()
            return row["json_blob"] if row else None
        except Exception as e:
            logging.error(f"Failed to retrieve threat analysis: {e}")
            return None
        finally:
            conn.close()

    def log_block_action(self, ip, action, backend, reason):
        conn = self.get_connection()
        if not conn:
            return
        try:
            cursor = conn.cursor()
            timestamp = datetime.now().isoformat()
            cursor.execute("""
                INSERT INTO block_actions (timestamp, ip, action, backend, reason)
                VALUES (?, ?, ?, ?, ?)
            """, (timestamp, ip, action, backend, reason))
            conn.commit()
            logging.info(f"Logged block action: {ip} | {action} | {backend} | {reason}")
        except Exception as e:
            logging.error(f"Failed to log block action in database: {e}")
        finally:
            conn.close()

    def get_all_threat_events(self, limit=100):
        conn = self.get_connection()
        if not conn:
            return []
        try:
            cursor = conn.cursor()
            cursor.execute("""
                SELECT * FROM threat_events ORDER BY id DESC LIMIT ?
            """, (limit,))
            rows = cursor.fetchall()
            return [dict(row) for row in rows]
        except Exception as e:
            logging.error(f"Failed to fetch threat events: {e}")
            return []
        finally:
            conn.close()

    def get_block_history(self, limit=100):
        conn = self.get_connection()
        if not conn:
            return []
        try:
            cursor = conn.cursor()
            cursor.execute("""
                SELECT * FROM block_actions ORDER BY id DESC LIMIT ?
            """, (limit,))
            rows = cursor.fetchall()
            return [dict(row) for row in rows]
        except Exception as e:
            logging.error(f"Failed to fetch block history: {e}")
            return []
        finally:
            conn.close()

    def clear_logs(self):
        conn = self.get_connection()
        if not conn:
            return
        try:
            cursor = conn.cursor()
            cursor.execute("DELETE FROM threat_events")
            cursor.execute("DELETE FROM block_actions")
            conn.commit()
            logging.info("Cleared database logs.")
        except Exception as e:
            logging.error(f"Failed to clear database logs: {e}")
        finally:
            conn.close()
