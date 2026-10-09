# AttackRewind
Interactive cybersecurity event replay using Streamlit and optional ClickHouse Cloud.

## Windows PowerShell
```powershell
py -m venv .venv
.\.venv\Scripts\Activate.ps1
pip install -r requirements.txt
streamlit run app.py
```

Local demo loads `sample_logs.csv` automatically. To use ClickHouse, copy `.env.example` to `.env`, edit your real credentials, restart Streamlit, switch to ClickHouse Cloud, and click **Import bundled sample logs into ClickHouse**.

**CSV columns:** timestamp,src_ip,username,event_type,details,session_id,status,bytes_transferred.

**Notes:** Synthetic data; imports append and can create duplicates; time-series rule detection is a prototype. Do not upload private logs without authorization.
