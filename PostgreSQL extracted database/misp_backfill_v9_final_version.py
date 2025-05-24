import os, json, csv, socket, tempfile
from datetime import datetime, timezone
from concurrent.futures import ThreadPoolExecutor
import psycopg2
import requests, urllib3
from psycopg2.extras import execute_batch
from requests.adapters import HTTPAdapter
from urllib3.util import Retry
from dotenv import load_dotenv

# ─── LOAD CONFIG ─────────────────────────────────────────────────────────────
HERE = os.path.dirname(__file__)
load_dotenv(os.path.join(HERE, ".env"))

MISP_URL    = os.getenv("MISP_BASEURL")
API_KEY     = os.getenv("MISP_KEY")
VERIFY_CERT = os.getenv("VERIFY_CERT","false").lower() in ("1","true","yes")

DB_PARAMS = dict(
    dbname=os.getenv("DB_NAME"),
    user=os.getenv("DB_USER"),
    password=os.getenv("DB_PASS"),
    host=os.getenv("DB_HOST"),
    port=os.getenv("DB_PORT")
)

# ─── TUNABLES ────────────────────────────────────────────────────────────────
ATTR_PAGE  = 100_000
WORKERS    = 20
EV_BATCH   = 500
CSV_CHUNK  = 100_000   # rows per COPY chunk

# ─── HELPERS ────────────────────────────────────────────────────────────────
def to_dt(ts):
    try: return datetime.fromtimestamp(int(ts), tz=timezone.utc)
    except: return None

def parse_ts(v):
    if not v: return None
    try: return datetime.fromtimestamp(int(v)/1e6, tz=timezone.utc)
    except:
        try: return datetime.fromisoformat(v)
        except: return None

# ─── HTTP SETUP ──────────────────────────────────────────────────────────────
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
session = requests.Session()
session.mount(
    "https://",
    HTTPAdapter(max_retries=Retry(total=3, backoff_factor=0.3,
                                  status_forcelist=[500,502,503,504]))
)
session.headers.update({
    "Accept":"application/json",
    "Content-Type":"application/json",
    "Authorization": API_KEY
})

# ─── DB CONNECTION ───────────────────────────────────────────────────────────
conn = psycopg2.connect(**DB_PARAMS)
cur  = conn.cursor()

# ─── SQL TEMPLATES ───────────────────────────────────────────────────────────
EVT_SQL = """
INSERT INTO events_minimal (
  id, org_id, info, uuid, date,
  attribute_count, last_modified,
  threat_level_id, publish_timestamp,
  feed_name, orgc_name
) VALUES (
  %(id)s, %(org_id)s, %(info)s, %(uuid)s, %(date)s,
  %(attribute_count)s, %(timestamp)s,
  %(threat_level_id)s, %(publish_timestamp)s,
  %(feed_name)s, %(orgc_name)s
) ON CONFLICT (id) DO NOTHING;
"""

# for attribute_correlations
CORR_SQL = """
INSERT INTO attribute_correlations (
  attr_id, related_attr_id, related_event_id,
  relationship_type, first_seen, last_seen, comment
) VALUES (
  %(attr_id)s, %(related_attr_id)s, %(related_event_id)s,
  %(relationship_type)s, %(first_seen)s, %(last_seen)s, %(comment)s
) ON CONFLICT (attr_id, related_attr_id) DO NOTHING;
"""

# final list of columns for COPY
ATTR_COLS = [
  "id","event_id","category","type","value","to_ids","uuid","created_ts",
  "comment","first_seen","last_seen",
  "country_name","country_code","region_name","city",
  "related_event_info","event_info","event_galaxy_names"
]

# ─── PHASE 1: FETCH ALL ATTRIBUTES ───────────────────────────────────────────
attrs = []
page = 1
while True:
    resp = session.post(
        f"{MISP_URL}/attributes/restSearch",
        json={
          "returnFormat":"json","page":page,"limit":ATTR_PAGE,
          "includeRelatedAttributes": True,
          "includeObjectRefs": True
        },
        verify=VERIFY_CERT
    )
    resp.raise_for_status()
    block = resp.json().get("response", {}).get("Attribute", [])
    if not block:
        break
    attrs.extend(block)
    print(f" → got {len(block)} attrs (total {len(attrs)})")
    page += 1

# build id→value for related attrs
id_to_value = { int(a["id"]): a.get("value","") for a in attrs }

# ─── PHASE 2: FETCH EVENTS ──────────────────────────────────────────────────
evt_ids = { int(a["event_id"]) for a in attrs }
def fetch_ev(eid):
    r = session.post(
      f"{MISP_URL}/events/view/{eid}",
      json={"returnFormat":"json","withAttachments":0,
            "includeGalaxy":True,"includeObjectRefs":True},
      verify=VERIFY_CERT
    )
    r.raise_for_status()
    return r.json().get("Event", {})
print(f"Fetching {len(evt_ids)} events with {WORKERS} workers…")
with ThreadPoolExecutor(max_workers=WORKERS) as ex:
    evs = list(ex.map(fetch_ev, evt_ids))

# map event_id→object
event_map = { int(e["id"]): e for e in evs }

# ─── PHASE 3a: UPSERT EVENTS ─────────────────────────────────────────────────
evt_params = [{
  "id":e["id"],"org_id":e.get("org_id"),"info":e.get("info"),
  "uuid":e.get("uuid"),"date":e.get("date"),
  "attribute_count":e.get("attribute_count"),
  "timestamp":to_dt(e.get("timestamp")),
  "threat_level_id":e.get("threat_level_id"),
  "publish_timestamp":to_dt(e.get("publish_timestamp")),
  "feed_name":e.get("Feed",{}).get("name"),
  "orgc_name":e.get("Orgc",{}).get("name")
} for e in evs]
print("Upserting events…")
execute_batch(cur, EVT_SQL, evt_params, page_size=EV_BATCH)

# ─── PHASE 3b: UPSERT RAW CORRELATIONS ────────────────────────────────────────
corr_params = []
for a in attrs:
    aid = int(a["id"])
    for r in a.get("RelatedAttribute", []):
        corr_params.append({
          "attr_id":           aid,
          "related_attr_id":   int(r["id"]),
          "related_event_id":  int(r["event_id"]),
          "relationship_type": r.get("object_relation",""),
          "first_seen":        parse_ts(r.get("first_seen")),
          "last_seen":         parse_ts(r.get("last_seen")),
          "comment":           r.get("comment","")
        })
# upsert correlations
if corr_params:
    print("Upserting attribute_correlations…")
    execute_batch(cur, CORR_SQL, corr_params, page_size=EV_BATCH)

conn.commit()

# ─── PHASE 4: STREAM-LOAD ATTRIBUTES ────────────────────────────────────────
def write_csv(rows, tf):
    w = csv.writer(tf)
    for a in rows:
        aid = int(a["id"])
        ev  = int(a["event_id"])
        fs  = parse_ts(a.get("first_seen"))
        ls  = parse_ts(a.get("last_seen"))

        # build related_event_info
        rel_parts = []
        for r in a.get("RelatedAttribute", []):
            rid     = int(r["id"])
            rel_evt = int(r["event_id"])
            evt_obj = event_map.get(rel_evt, {})
            desc    = evt_obj.get("info","").replace("\n"," ")[:50]
            val     = id_to_value.get(rid,"")
            rel_parts.append(f"{rel_evt}:{desc}|{val}")
        related_event_info = ", ".join(rel_parts)

        # parent-event info & galaxies
        evt_obj          = event_map.get(ev, {})
        event_info       = evt_obj.get("info","").replace("\n"," ")
        event_galaxy_names = ", ".join(g.get("name")
                                        for g in evt_obj.get("Galaxy", []))

        w.writerow([
          aid, ev,
          a.get("category"), a.get("type"), a.get("value","").replace("\n"," "),
          't' if a.get("to_ids", False) else 'f',
          a.get("uuid"),
          to_dt(a.get("timestamp")).isoformat() if a.get("timestamp") else r"\N",
          a.get("comment","").replace("\n"," "),
          fs.isoformat() if fs else r"\N",
          ls.isoformat() if ls else r"\N",
          # geo placeholders
          r"\N", r"\N", r"\N", r"\N",
          # new TEXT columns:
          related_event_info,
          event_info,
          event_galaxy_names
        ])

total = len(attrs)
for start in range(0, total, CSV_CHUNK):
    chunk = attrs[start:start+CSV_CHUNK]
    end   = start + len(chunk)
    print(f"COPY attributes rows {start+1}–{end} of {total}…")
    with tempfile.NamedTemporaryFile(
        mode="w+", delete=False, newline="", encoding="utf-8"
    ) as tf:
        write_csv(chunk, tf)
        tf.flush(); tf.seek(0)
        cur.copy_expert(
          f"COPY attributes_minimal ({','.join(ATTR_COLS)}) "
          "FROM STDIN WITH (FORMAT csv, NULL '\\N')",
          tf
        )
    conn.commit()

cur.execute("UPDATE sync_state SET last_run = %s WHERE id=1", (datetime.now(timezone.utc),))
conn.commit()
print("Backfill complete.")