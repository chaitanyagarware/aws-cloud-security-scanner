"""Streamlit dashboard for AWS Cloud Security Scanner.

Run after generating reports/demo_report.json:
    pip install -e .[dashboard]
    streamlit run dashboard/app.py
"""
from __future__ import annotations

import json
from pathlib import Path

import pandas as pd
import streamlit as st

REPORT = Path("reports/demo_report.json")
st.set_page_config(page_title="AWS Cloud Security Scanner", layout="wide")
st.title("AWS Cloud Security Scanner Findings Explorer")
st.caption("Portfolio dashboard for IAM blast radius, CloudTrail behavior, GuardDuty triage, MITRE mapping, and remediation review.")

if not REPORT.exists():
    st.warning("Run scripts/run_demo.sh first to generate reports/demo_report.json")
    st.stop()

data = json.loads(REPORT.read_text(encoding="utf-8"))
summary = data["summary"]
metrics = data.get("impact_metrics", {})

c1, c2, c3, c4 = st.columns(4)
c1.metric("Total Findings", summary["total_findings"])
c2.metric("High + Critical", summary["high"] + summary["critical"])
c3.metric("Least-Privilege Drafts", metrics.get("principals_with_least_privilege_drafts", 0))
c4.metric("New Findings", metrics.get("new_findings", 0))

findings = pd.DataFrame(data["findings"])
if findings.empty:
    st.success("No findings found.")
    st.stop()

left, right = st.columns(2)
with left:
    st.subheader("Severity distribution")
    st.bar_chart(findings["severity"].value_counts())
with right:
    st.subheader("Top principals")
    st.bar_chart(findings["principal"].fillna("unknown").value_counts().head(10))

severity = st.multiselect("Severity", sorted(findings["severity"].unique()), default=sorted(findings["severity"].unique()))
source = st.multiselect("Source", sorted(findings["source"].unique()), default=sorted(findings["source"].unique()))
all_mitre = sorted({tag for tags in findings.get("mitre_attack", []) for tag in (tags or [])})
mitre = st.multiselect("MITRE ATT&CK", all_mitre, default=all_mitre) if all_mitre else []
text_query = st.text_input("Search title, principal, resource, remediation")
view = findings[findings["severity"].isin(severity) & findings["source"].isin(source)]
if mitre:
    view = view[view["mitre_attack"].apply(lambda tags: bool(set(tags or []) & set(mitre)))]
if text_query:
    q = text_query.lower()
    view = view[view.apply(lambda row: q in " ".join(str(row.get(col, "")) for col in ["title", "principal", "resource", "remediation"]).lower(), axis=1)]

st.subheader("Findings")
cols = ["severity", "source", "rule_id", "title", "principal", "resource", "mitre_attack", "remediation"]
st.dataframe(view[cols], use_container_width=True)

st.download_button("Download filtered findings JSON", view.to_json(orient="records", indent=2), file_name="filtered_findings.json")
