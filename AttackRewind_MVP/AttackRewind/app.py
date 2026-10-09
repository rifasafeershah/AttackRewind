import os
import json
from datetime import datetime
from pathlib import Path

import pandas as pd
import plotly.express as px
import streamlit as st
from dotenv import load_dotenv

load_dotenv()
st.set_page_config(page_title="AttackRewind", page_icon="🛡️", layout="wide")
BASE = Path(__file__).resolve().parent
FIELDS = ["timestamp", "src_ip", "username", "event_type", "details", "session_id", "status", "bytes_transferred"]

st.markdown("""<style>
.block-container{padding-top:1.6rem;max-width:1400px}
[data-testid="stMetric"]{background:#172338;border:1px solid #334155;border-radius:12px;padding:15px}
.event-card{padding:20px;border:1px solid #334155;border-radius:14px;background:#172338}
</style>""", unsafe_allow_html=True)


def normalize(df):
    missing = sorted(set(FIELDS) - set(df.columns))
    if missing:
        raise ValueError("Missing required columns: " + ", ".join(missing))
    df = df[FIELDS].copy()
    df["timestamp"] = pd.to_datetime(df["timestamp"], utc=True, errors="coerce")
    if df["timestamp"].isna().any():
        raise ValueError("Invalid timestamps found in uploaded file")
    for col in ["src_ip", "username", "event_type", "details", "session_id", "status"]:
        df[col] = df[col].fillna("").astype(str)
    df["bytes_transferred"] = pd.to_numeric(df["bytes_transferred"], errors="coerce").fillna(0).clip(lower=0).astype("int64")
    return df.sort_values("timestamp").reset_index(drop=True)


@st.cache_resource(show_spinner=False)
def clickhouse_client(host, port, user, password):
    import clickhouse_connect
    client = clickhouse_connect.get_client(host=host, port=port, username=user,
                                            password=password, secure=True,
                                            autogenerate_session_id=False)
    client.command("""CREATE TABLE IF NOT EXISTS attackrewind_events (
        timestamp DateTime64(3, 'UTC'), src_ip String, username String,
        event_type String, details String, session_id String,
        status String, bytes_transferred UInt64
    ) ENGINE = MergeTree ORDER BY (timestamp, src_ip, event_type)""")
    return client


def get_client():
    host = os.getenv("CLICKHOUSE_HOST", "").strip()
    password = os.getenv("CLICKHOUSE_PASSWORD", "").strip()
    if not host or host.startswith("your-") or not password or password == "replace-me":
        return None
    return clickhouse_client(host, int(os.getenv("CLICKHOUSE_PORT", "8443")),
                             os.getenv("CLICKHOUSE_USER", "default"), password)


def insert_clickhouse(client, df):
    payload = df.copy()
    payload["timestamp"] = payload["timestamp"].dt.tz_convert("UTC").dt.tz_localize(None)
    client.insert("attackrewind_events", list(payload.itertuples(index=False, name=None)),
                  column_names=FIELDS)


def read_clickhouse(client):
    # Limit results for a responsive hackathon MVP.
    result = client.query("""SELECT timestamp, src_ip, username, event_type, details,
        session_id, status, bytes_transferred FROM attackrewind_events
        ORDER BY timestamp DESC LIMIT 20000""")
    return normalize(pd.DataFrame(result.result_rows, columns=FIELDS)) if result.result_rows else pd.DataFrame(columns=FIELDS)


def detect(df):
    findings = []
    if df.empty:
        return findings
    # Correlation rules are deterministic; evidence is always drawn from real rows.
    for ip, group in df.groupby("src_ip"):
        group = group.sort_values("timestamp")
        failed = group[group.event_type == "failed_login"]
        successes = group[group.event_type == "successful_login"]
        for _, success in successes.iterrows():
            recent = failed[(failed.timestamp <= success.timestamp) &
                            (failed.timestamp >= success.timestamp - pd.Timedelta(minutes=5))]
            if len(recent) >= 10:
                findings.append({"timestamp": success.timestamp, "src_ip": ip,
                    "title": "Possible account takeover", "severity": "Critical",
                    "details": f"{len(recent)} failed logins within five minutes before successful authentication for {success.username}",
                    "session_id": success.session_id})
        if len(failed) >= 10 and successes.empty:
            findings.append({"timestamp": failed.timestamp.max(), "src_ip": ip,
                "title": "Repeated authentication failures", "severity": "High",
                "details": f"{len(failed)} failed logins observed", "session_id": ""})
        for _, event in group[group.event_type == "role_change"].iterrows():
            findings.append({"timestamp": event.timestamp, "src_ip": ip,
                "title": "Privilege change", "severity": "High",
                "details": event.details, "session_id": event.session_id})
        for _, event in group[group.event_type == "sensitive_download"].iterrows():
            findings.append({"timestamp": event.timestamp, "src_ip": ip,
                "title": "Sensitive download requires review", "severity": "High",
                "details": f"{event.details} ({event.bytes_transferred:,} bytes)",
                "session_id": event.session_id})
    return sorted(findings, key=lambda item: item["timestamp"])


st.title("🛡️ AttackRewind")
st.caption("Replay an incident from real log records • ClickHouse-powered security investigation")
with st.sidebar:
    st.header("Data source")
    mode = st.radio("Mode", ["Local demo", "ClickHouse Cloud"], index=0)
    uploaded = st.file_uploader("Upload security log CSV", type="csv")
    st.caption("Required fields: " + ", ".join(FIELDS))
    if st.button("Reset replay"):
        st.session_state.step = 0
    st.info("Uses synthetic examples. Correlation findings are investigative leads, not proof of compromise.")

try:
    client = get_client() if mode == "ClickHouse Cloud" else None
    if mode == "ClickHouse Cloud" and client is None:
        st.warning("Set CLICKHOUSE_HOST and CLICKHOUSE_PASSWORD in .env, then restart the app.")
        st.stop()
    if uploaded is not None:
        input_df = normalize(pd.read_csv(uploaded))
        if mode == "ClickHouse Cloud":
            if st.button("Import uploaded logs into ClickHouse", type="primary"):
                insert_clickhouse(client, input_df)
                st.success(f"Imported {len(input_df)} events. Re-importing adds duplicates.")
                st.rerun()
        else:
            st.success(f"Loaded {len(input_df)} uploaded events locally")
    if mode == "ClickHouse Cloud":
        if st.button("Import bundled sample logs into ClickHouse"):
            insert_clickhouse(client, normalize(pd.read_csv(BASE / "sample_logs.csv")))
            st.success("Sample logs imported. Re-importing adds duplicates.")
            st.rerun()
        df = read_clickhouse(client)
        st.caption("Source: ClickHouse Cloud · Last 20,000 stored events")
    else:
        df = input_df if uploaded is not None else normalize(pd.read_csv(BASE / "sample_logs.csv"))
        st.caption("Source: local CSV · Switch to ClickHouse Cloud to query the database")
except Exception as exc:
    st.error(f"Unable to load events: {exc}")
    st.stop()

if df.empty:
    st.info("No events yet. Import the bundled sample CSV or upload your own logs.")
    st.stop()

findings = detect(df)
failed = df[df.event_type == "failed_login"]
a, b, c, d = st.columns(4)
a.metric("Total events", f"{len(df):,}")
b.metric("Failed logins", f"{len(failed):,}")
c.metric("Source IPs", f"{df.src_ip.nunique():,}")
d.metric("Flagged findings", f"{len(findings):,}")

timeline, investigation, raw = st.tabs(["🎬 Attack replay", "🔎 Findings", "📋 Raw logs"])
with timeline:
    ips = sorted(df.src_ip.unique().tolist())
    default_ip = "203.0.113.42" if "203.0.113.42" in ips else ips[0]
    
    ip_counts = df["src_ip"].value_counts()
    sorted_ips = ip_counts.index.tolist()

    ip = st.selectbox(
        "Investigate source IP",
        sorted_ips,
        format_func=lambda x: f"{x} ({ip_counts[x]} events)"
    )

    events = df[df.src_ip == ip].sort_values("timestamp").reset_index(drop=True)
    st.write(f"**{len(events)} events** associated with {ip}")
    if "step" not in st.session_state:
        st.session_state.step = 0
    st.session_state.step = min(st.session_state.step, len(events)-1)
    
    if len(events) > 1:
        step = st.slider(
            "Replay position",
            min_value=0,
            max_value=len(events) - 1,
            value=min(st.session_state.step, len(events) - 1)
        )
    else:
        step = 0
        st.info("Only one event found for this IP. No replay needed.")
    st.session_state.step = step
    left, middle, right = st.columns([1, 1, 3])
    with left:
        if st.button("◀ Previous", disabled=step == 0):
            st.session_state.step = step-1
            st.rerun()
    with middle:
        if st.button("Next ▶", disabled=step == len(events)-1):
            st.session_state.step = step+1
            st.rerun()
    current = events.iloc[step]
    st.markdown(f"### {current['event_type'].replace('_', ' ').title()}")
    st.write(f"**Time:** {current['timestamp']}  |  **User:** {current['username']}  |  **Status:** {current['status']}")
    st.info(current["details"] or "No details supplied")
    st.code(json.dumps({k: str(v) for k, v in current.to_dict().items()}, indent=2), language="json")
    chart_df = events.copy()
    chart_df["stage"] = chart_df.event_type.str.replace("_", " ").str.title()
    fig = px.scatter(chart_df, x="timestamp", y="stage", color="stage",
                     hover_data=["username", "details"], title="Event timeline")
    fig.add_vline(x=current.timestamp.timestamp()*1000, line_dash="dash", line_color="white")
    fig.update_layout(showlegend=False, height=350)
    st.plotly_chart(fig, use_container_width=True)
    st.caption("Move the slider to replay individual log records in timestamp order.")
with investigation:
    if findings:
        st.dataframe(pd.DataFrame(findings), use_container_width=True, hide_index=True)
    else:
        st.success("No rules triggered for this dataset.")
    report = {"generated_at": datetime.utcnow().isoformat() + "Z", "event_count": len(df),
              "findings": [{**f, "timestamp": str(f["timestamp"])} for f in findings]}
    st.download_button("Download incident findings (JSON)", json.dumps(report, indent=2),
                       file_name="attackrewind_findings.json", mime="application/json")
with raw:
    st.dataframe(df, use_container_width=True, hide_index=True)
    st.download_button("Download loaded logs (CSV)", df.to_csv(index=False),
                       file_name="attackrewind_export.csv", mime="text/csv")
