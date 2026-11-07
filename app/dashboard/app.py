import json
import os
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen

import pandas as pd
import streamlit as st


API_URL = os.getenv(
    "DFIR_API_URL",
    "http://127.0.0.1:8000",
)


st.set_page_config(
    page_title="DFIR Investigation Dashboard",
    page_icon="DFIR",
    layout="wide",
)


def fetch_json(path: str) -> list[dict]:
    """
    Fetch a JSON list from the FastAPI backend.
    """

    request = Request(
        f"{API_URL}{path}",
        headers={"Accept": "application/json"},
        method="GET",
    )

    with urlopen(request, timeout=10) as response:
        return json.loads(response.read().decode("utf-8"))


def fetch_events() -> list[dict]:
    """
    Fetch events from the FastAPI backend.
    """

    return fetch_json("/events")


st.title("DFIR Investigation Dashboard")
st.caption("Windows & Linux Host Investigation Tool")

st.sidebar.header("System Information")
st.sidebar.write(f"API URL: `{API_URL}`")

try:
    events = fetch_events()

    st.success("Connected to FastAPI successfully.")

    total_events = len(events)
    windows_events = sum(
        event.get("platform") == "windows"
        for event in events
    )
    linux_events = sum(
        event.get("platform") == "linux"
        for event in events
    )
    high_severity = sum(
        event.get("severity") in {"high", "critical"}
        for event in events
    )

    col1, col2, col3, col4 = st.columns(4)

    col1.metric("Total Events", total_events)
    col2.metric("Windows Events", windows_events)
    col3.metric("Linux Events", linux_events)
    col4.metric("High/Critical", high_severity)

    st.divider()

    st.subheader("Events")

    if events:
        dataframe = pd.DataFrame(events)

        visible_columns = [
            "event_id",
            "case_id",
            "host_id",
            "platform",
            "event_type",
            "timestamp",
            "severity",
            "source",
            "evidence_reference",
            "message",
        ]

        existing_columns = [
            column
            for column in visible_columns
            if column in dataframe.columns
        ]

        st.dataframe(
            dataframe[existing_columns],
            use_container_width=True,
            hide_index=True,
        )

        st.subheader("Event Details")

        selected_event_id = st.selectbox(
            "Choose an Event",
            options=[
                event["event_id"]
                for event in events
            ],
        )

        selected_event = next(
            event
            for event in events
            if event["event_id"] == selected_event_id
        )

        st.json(selected_event)

    else:
        st.info(
            "No events found. Send an event through POST /events first."
        )

except HTTPError as error:
    st.error(
        f"FastAPI returned an HTTP error: {error.code}"
    )

except URLError:
    st.error(
        "Could not connect to FastAPI. "
        "Start the API first and verify the API URL."
    )

except Exception as error:
    st.error(f"Unexpected error: {error}")

# ---------------------------------------------------------------
# Findings section (detection output, analyst review required)
# ---------------------------------------------------------------

st.subheader("Potential Findings")
st.caption(
    "All findings are produced by detection rules with status "
    "'unverified' and require analyst review. They are not a final "
    "compromise verdict."
)

try:
    findings = fetch_json("/findings")

    if findings:
        col5, col6, col7 = st.columns(3)
        col5.metric("Total Findings", len(findings))
        col6.metric(
            "Unverified",
            sum(f.get("status") == "unverified" for f in findings),
        )
        col7.metric(
            "High/Critical",
            sum(f.get("severity") in {"high", "critical"} for f in findings),
        )

        findings_frame = pd.DataFrame(findings)

        finding_columns = [
            "finding_id",
            "rule_id",
            "severity",
            "status",
            "host_id",
            "title",
            "evidence_reference",
            "mitre_technique",
        ]

        existing_finding_columns = [
            column
            for column in finding_columns
            if column in findings_frame.columns
        ]

        st.dataframe(
            findings_frame[existing_finding_columns],
            use_container_width=True,
            hide_index=True,
        )

        st.subheader("Finding Details")

        selected_finding_id = st.selectbox(
            "Choose a Finding",
            options=[
                finding["finding_id"]
                for finding in findings
            ],
        )

        selected_finding = next(
            finding
            for finding in findings
            if finding["finding_id"] == selected_finding_id
        )

        st.json(selected_finding)

    else:
        st.info(
            "No findings found. Detection output appears here after "
            "POST /findings."
        )

except Exception as error:
    st.warning(f"Findings unavailable: {error}")
