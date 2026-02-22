from datetime import datetime, timedelta

from audit_flags import calculate_flag_age


def test_calculate_flag_age_handles_iso_datetime():
    recent = (datetime.now() - timedelta(days=5)).strftime("%Y-%m-%dT%H:%M:%SZ")
    assert calculate_flag_age(recent) >= 4


def test_calculate_flag_age_bad_input_defaults_zero():
    assert calculate_flag_age("not-a-date") == 0
