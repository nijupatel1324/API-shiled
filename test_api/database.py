"""Tiny SQLite helper for the training test API.

Simulates SQL execution for the SQL-injection demonstration. The 'query'
routine should NEVER be used in production; it exists only to let students
see what happens when string interpolation reaches a database layer.
"""

import sqlite3
import os

DB_PATH = os.path.join(os.path.dirname(__file__), "test_api_learn.db")


def get_connection():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


def init_db():
    conn = get_connection()
    conn.execute(
        "CREATE TABLE IF NOT EXISTS products ("
        "id INTEGER PRIMARY KEY, name TEXT, category TEXT, price REAL)"
    )
    sample = [(1, "Wireless Mouse", "electronics", 19.99),
              (2, "Mechanical Keyboard", "electronics", 89.99),
              (3, "USB-C Hub", "accessories", 39.99)]
    count = conn.execute("SELECT COUNT(*) AS c FROM products").fetchone()["c"]
    if count == 0:
        conn.executemany(
            "INSERT INTO products (id, name, category, price) VALUES (?,?,?,?)", sample
        )
    conn.commit()
    conn.close()


def search_products_by_name_untrusted(search_term):
    """Deliberately injectable query — training only, NEVER for production."""
    conn = get_connection()
    try:
        rows = conn.execute(
            "SELECT id, name, category, price FROM products "
            "WHERE name LIKE '%" + search_term + "%'"
        ).fetchall()
        conn.close()
        return [dict(r) for r in rows]
    except sqlite3.Error as exc:
        conn.close()
        raise ValueError(f"{type(exc).__name__}: syntax error near crafted keyword") from exc