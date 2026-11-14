import os
import psycopg
from psycopg.rows import dict_row
from fastapi import FastAPI

DB_URL = os.environ["DATABASE_URL"]
app = FastAPI(title="NETWATCH API")

def query(sql, params=()):
    with psycopg.connect(DB_URL, row_factory=dict_row) as conn:
        return conn.execute(sql, params).fetchall()

@app.get("/")
def home():
    return {"service": "NETWATCH API", "endpoints":["/alerts","/alerts/summary"]}

@app.get("/alerts")
def alerts(kind: str | None = None, limit: int=50):
    sql = "SELECT time, kind, source_ip, target_ip, message FROM alerts"
    params = []
    if kind:
        sql += " WHERE kind = %s"
        params.append(kind)
    sql += " ORDER BY time DESC LIMIT %s"
    params.append(limit)
    return query(sql, params)

@app.get("/alerts/summary")
def summary():
    return query("SELECT kind, COUNT(*) AS count from alerts GROUP BY kind ORDER BY count DESC")

