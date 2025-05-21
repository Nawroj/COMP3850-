import os, socket
from datetime import datetime, timedelta, timezone
from concurrent.futures import ThreadPoolExecutor, as_completed
import geoip2.database
import psycopg2
from psycopg2.extras import execute_batch
from dotenv import load_dotenv

# ─── LOAD CONFIG ─────────────────────────────────────────────────────────────

HERE = os.path.dirname(__file__)
load_dotenv(os.path.join(HERE, ".env"))

DB_PARAMS   = dict(
    dbname=os.getenv("DB_NAME"),
    user=os.getenv("DB_USER"),
    password=os.getenv("DB_PASS"),
    host=os.getenv("DB_HOST"),
    port=os.getenv("DB_PORT")
)
MMDB_PATH   = os.getenv("GEOLITE2_PATH")
WORKERS     = 50
BATCH_SIZE  = 1000

# ─── CONNECT ────────────────────────────────────────────────────────────────
conn = psycopg2.connect(**DB_PARAMS)
cur = conn.cursor()

cur.execute("""
    SELECT id, value, type
      FROM attributes_minimal
     WHERE country_name IS NULL
       AND type IN ('ip-src','ip-dst','ip','cidr','domain')
""")
rows = cur.fetchall()
total = len(rows)
print(f"{total:,} attributes to enrich with GeoLite2")

# ─── OPEN THE MMDB ───────────────────────────────────────────────────────────

reader = geoip2.database.Reader(MMDB_PATH)
dns_cache = {}

def enrich(r):
    aid, val, typ = r
    ip = val
    if typ == "domain":
        if val in dns_cache:
            ip = dns_cache[val]
        else:
            try:
                ip = socket.gethostbyname(val)
            except:
                return None
            dns_cache[val] = ip
    try:
        city = reader.city(ip)
    except:
        return None
    return {
        "id":           aid,
        "country_name": city.country.name,
        "country_code": city.country.iso_code,
        "region_name":  city.subdivisions.most_specific.name,
        "city":         city.city.name
    }


# ─── PARALLEL LOOKUPS ────────────────────────────────────────────────────────

updates = []
start = datetime.now(timezone.utc)
with ThreadPoolExecutor(max_workers=WORKERS) as ex:
    futures = {ex.submit(enrich, row): row for row in rows}
    for i, futures in enumerate(as_completed(futures), 1):
        res = futures.result()
        if res:
            updates.append(res)
        if i % 10000 == 0 or i == total:
            elapsed = (datetime.now(timezone.utc) - start).total_seconds()
            print(f"Processed {i:,}/{total:,}; enriched {len(updates):,}; {elapsed:.1f}s")

reader.close()
print(f"Lookup done in {(datetime.now(timezone.utc)-start).total_seconds():.1f}s; {len(updates):,} results")


# ─── BATCH-UPDATE POSTGRES ──────────────────────────────────────────────────

sql = """
UPDATE attributes_minimal
   SET country_name = %(country_name)s,
       country_code = %(country_code)s,
       region_name  = %(region_name)s,
       city         = %(city)s
 WHERE id = %(id)s;
"""
for i in range(0, len(updates), BATCH_SIZE):
    chunk = updates[i:i+BATCH_SIZE]
    execute_batch(cur, sql, chunk, page_size=BATCH_SIZE)
    conn.commit()
    print(f"Committed rows {i+1:,}–{i+len(chunk):,}")

cur.close()
conn.close()
print("Geo backfill complete.")