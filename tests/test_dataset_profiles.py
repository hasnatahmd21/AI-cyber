from ai_cyber_os.dataset_profiles import TARGET_DATASETS, profile, validate_profile_metadata

def test_target_dataset_families_are_explicit():
    assert len(TARGET_DATASETS) == 9
    for name in TARGET_DATASETS:
        metadata = profile(name)
        validate_profile_metadata(metadata)
        assert metadata["dataset"] == name

def test_profile_requires_explicit_operator_metadata():
    metadata = profile("nvd_cve", version="2026", source="NVD", source_uri="local://artifact", license="operator-supplied")
    validate_profile_metadata(metadata)
    assert metadata["version"] == "2026"

def test_unknown_profile_fails():
    try:
        profile("unknown")
    except ValueError as exc:
        assert "unsupported dataset family" in str(exc)
    else:
        raise AssertionError("unknown profile accepted")
