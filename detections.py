"""Nordic Shadow Hunter - SIEM Correlation Engine and Detection Rules.

This module provides generic detection rules (R1 to R14), MITRE ATT&CK taxonomy
enrichment, incident clustering algorithms, IoC extraction, and data quality anomaly
identification for SOC Level 2 forensic investigations without hardcoded entity filters.
"""


def load_dataset(file_or_path):
    """Load and normalize SIEM export logs from Excel or path.

    Args:
        file_or_path: File path or uploaded file buffer.

    Returns:
        pd.DataFrame: Normalized logs dataframe.
    """
    raise NotImplementedError("Engine implementation will be loaded in Subfase F1.")


def run_detections(df):
    """Run correlation rules R1-R14, group into incidents, and extract IoCs.

    Args:
        df (pd.DataFrame): Normalized logs dataframe.

    Returns:
        tuple[pd.DataFrame, list[dict], pd.DataFrame]: Enriched dataframe, incident list, IoCs dataframe.
    """
    raise NotImplementedError("Detection rules will be implemented in Subfase F1.")
