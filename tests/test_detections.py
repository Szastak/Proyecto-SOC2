"""Nordic Shadow Hunter - SIEM Correlation Engine Tests.

This test suite verifies the correctness, precision, and ground truth alignment
of the correlation rules (R1 to R14), MITRE ATT&CK taxonomy enrichment,
incident clustering, and IoC extraction implemented in detections.py.
"""

import os
from pathlib import Path
import pytest
import pandas as pd

from detections import load_dataset, file_sha256, run_detections

# Expected constants
EXPECTED_SHA256 = "f645d76800097c09f3102d7d4f1cb5c1b2bb286d6cd054ab3daabe62c69d85f0"
EXPECTED_TOTAL_ROWS = 715
EXPECTED_MALICIOUS_COUNT = 121
EXPECTED_INCIDENT_COUNT = 6

# Ground Truth Log_IDs per incident
GROUND_TRUTH_LOG_IDS = {
    "INC-01": {
        f"EVT-00{s.zfill(3)}"
        for s in (
            "057,058,060,061,063,065,066,068,069,071,073,074,075,077,078,079,"
            "081,084,085,086,088,092,094,096,099,100,101,104,105,107,108,110,"
            "111,123,126"
        ).split(",")
    },
    "INC-02": {
        f"EVT-00{s.zfill(3)}"
        for s in (
            "174,175,178,180,188,193,198,207,214,222,225,227,231,232,235"
        ).split(",")
    },
    "INC-03": {
        f"EVT-00{s.zfill(3)}"
        for s in (
            "280,284,286,289,290,291,293,296,298,300,302,303,305,306,307,308,"
            "309,314"
        ).split(",")
    },
    "INC-04": {
        f"EVT-00{s.zfill(3)}"
        for s in (
            "419,428,430,431,432,435,436,438,439,440,441,443,444,445,448,450,"
            "451,453,455,456,457,458,460,461"
        ).split(",")
    },
    "INC-05": {
        f"EVT-00{s.zfill(3)}"
        for s in ("523,524,528,542,548,559,564").split(",")
    },
    "INC-06": {
        f"EVT-00{s.zfill(3)}"
        for s in (
            "571,572,573,574,576,577,579,581,582,583,584,585,586,588,589,590,"
            "591,592,593,595,596,599"
        ).split(",")
    },
}

EXPECTED_ANCHOR_ALTO = [
    "EVT-00123",
    "EVT-00188",
    "EVT-00198",
    "EVT-00235",
    "EVT-00280",
    "EVT-00314",
    "EVT-00428",
    "EVT-00523",
    "EVT-00524",
    "EVT-00599",
]

EXPECTED_HOSTS = {
    "DC-01",
    "WS-031",
    "APP-SRV01",
    "FS-SRV01",
    "WS-023",
    "WS-018",
    "WEB-01",
}

EXPECTED_EXTERNAL_IPS = {
    "203.0.113.74",
    "198.51.100.77",
    "192.0.2.91",
    "203.0.113.88",
    "198.51.100.88",
}


def get_dataset_path():
    """Retrieve dataset path from env or repository default."""
    env_path = os.getenv("DATASET_PATH")
    if env_path and os.path.isfile(env_path):
        return Path(env_path)
    default_path = (
        Path(__file__).resolve().parent.parent
        / "data"
        / "SOC_L2_Logs_Ampliados_Multiples_Incidentes.xlsx"
    )
    if default_path.is_file():
        return default_path
    pytest.skip("Dataset file not found; skipping telemetry tests.")


@pytest.fixture(scope="module")
def dataset_df():
    """Load dataset once for module tests."""
    path = get_dataset_path()
    return load_dataset(path)


@pytest.fixture(scope="module")
def detection_results(dataset_df):
    """Run detections once on dataset for module tests."""
    return run_detections(dataset_df)


def test_load_dataset_integrity():
    """Verify row count, SHA-256 digest, and column extractions."""
    path = get_dataset_path()
    computed_sha = file_sha256(path)
    assert computed_sha == EXPECTED_SHA256, (
        f"Dataset SHA-256 mismatch: {computed_sha} != {EXPECTED_SHA256}"
    )

    df = load_dataset(path)
    assert len(df) == EXPECTED_TOTAL_ROWS, (
        f"Row count mismatch: {len(df)} != {EXPECTED_TOTAL_ROWS}"
    )
    for col in ("is_external_ip", "LogonType", "bytes_out"):
        assert col in df.columns, f"Expected engineered column '{col}' missing."


def test_incidents_count_and_members(detection_results):
    """Verify exactly 6 incidents and exact Log_ID sets per incident."""
    df_enriquecido, incidents, _ = detection_results
    assert len(incidents) == EXPECTED_INCIDENT_COUNT, (
        f"Incident count mismatch: {len(incidents)} != {EXPECTED_INCIDENT_COUNT}"
    )

    incident_ids = [inc["id"] for inc in incidents]
    assert incident_ids == ["INC-01", "INC-02", "INC-03", "INC-04", "INC-05", "INC-06"]

    for inc in incidents:
        inc_id = inc["id"]
        expected_set = GROUND_TRUTH_LOG_IDS[inc_id]
        actual_set = set(inc["log_ids"])
        diff_missing = expected_set - actual_set
        diff_extra = actual_set - expected_set
        assert actual_set == expected_set, (
            f"Incident {inc_id} membership mismatch! Missing: {diff_missing}, Extra: {diff_extra}"
        )


def test_malicious_events_precision(detection_results):
    """Verify exactly 121 malicious events and 100% precision."""
    df_enriquecido, _, _ = detection_results
    malicious_df = df_enriquecido[df_enriquecido["Severidad_SOC"].isin(["Alto", "Medio"])]
    actual_malicious_ids = set(malicious_df["Log_ID"])

    all_expected_ids = set().union(*GROUND_TRUTH_LOG_IDS.values())
    assert len(all_expected_ids) == EXPECTED_MALICIOUS_COUNT

    missing = all_expected_ids - actual_malicious_ids
    false_positives = actual_malicious_ids - all_expected_ids

    assert len(actual_malicious_ids) == EXPECTED_MALICIOUS_COUNT, (
        f"Total malicious count mismatch: {len(actual_malicious_ids)} != {EXPECTED_MALICIOUS_COUNT}"
    )
    assert not missing, f"Expected malicious events missed by engine: {missing}"
    assert not false_positives, f"False positives detected outside ground truth: {false_positives}"


def test_anchor_events_severity_alto(detection_results):
    """Verify all 10 anchor events are assigned Severidad_SOC == 'Alto'."""
    df_enriquecido, _, _ = detection_results
    anchor_rows = df_enriquecido[df_enriquecido["Log_ID"].isin(EXPECTED_ANCHOR_ALTO)]
    assert len(anchor_rows) == len(EXPECTED_ANCHOR_ALTO)
    non_alto = anchor_rows[anchor_rows["Severidad_SOC"] != "Alto"]
    assert len(non_alto) == 0, (
        f"Anchor events not marked as 'Alto': {non_alto[['Log_ID', 'Severidad_SOC', 'Regla']].to_dict(orient='records')}"
    )


def test_affected_hosts_and_external_ips(detection_results):
    """Verify 7 affected hosts and 5 external IPs in IoCs."""
    df_enriquecido, incidents, iocs = detection_results

    # Affected hosts across incidents
    actual_hosts = set()
    for inc in incidents:
        actual_hosts.update(inc["hosts"])
    assert actual_hosts == EXPECTED_HOSTS, (
        f"Affected hosts mismatch: {actual_hosts} != {EXPECTED_HOSTS}"
    )

    # External IPs extracted in IoCs
    ip_iocs = iocs[iocs["tipo"] == "IP Externa"]
    actual_ips = set(ip_iocs["valor"].unique())
    assert actual_ips == EXPECTED_EXTERNAL_IPS, (
        f"External IPs in IoCs mismatch: {actual_ips} != {EXPECTED_EXTERNAL_IPS}"
    )


def test_r14_data_quality_anomalies(detection_results):
    """Verify R14 flags DC01 and CORP\\svc_backup as anomalies with Bajo severity and no incident."""
    df_enriquecido, _, _ = detection_results

    # Check DC01 events
    dc01_events = df_enriquecido[df_enriquecido["Hostname"] == "DC01"]
    assert len(dc01_events) > 0, "No DC01 events found in dataframe."
    assert (dc01_events["Anomalia_Dato"] != "").all(), "Not all DC01 events flagged in Anomalia_Dato."
    assert (dc01_events["Severidad_SOC"] == "Bajo").all(), "DC01 event has severity != Bajo."
    assert (dc01_events["Incidente"] == "").all(), "DC01 event erroneously assigned to an incident."

    # Check CORP\\svc_backup events
    svc_backup_events = df_enriquecido[df_enriquecido["User"] == r"CORP\svc_backup"]
    assert len(svc_backup_events) > 0, r"No CORP\svc_backup events found in dataframe."
    assert (svc_backup_events["Anomalia_Dato"] != "").all(), r"Not all CORP\svc_backup events flagged in Anomalia_Dato."
    assert (svc_backup_events["Severidad_SOC"] == "Bajo").all(), r"CORP\svc_backup event has severity != Bajo."
    assert (svc_backup_events["Incidente"] == "").all(), r"CORP\svc_backup event erroneously assigned to an incident."


def test_anti_hardcode_detections_source():
    """Verify detections.py contains NO hardcoded entities or identifiers."""
    source_file = Path(__file__).resolve().parent.parent / "detections.py"
    content = source_file.read_text(encoding="utf-8")

    forbidden_patterns = [
        "EVT-",
        "203.0.113",
        "198.51.100",
        "192.0.2",
        "mgarcia",
        "backupsvc",
        "rrojas",
    ]

    found = []
    for pat in forbidden_patterns:
        if pat.lower() in content.lower():
            found.append(pat)

    assert not found, f"Hardcoded entity forbidden patterns found in detections.py: {found}"
