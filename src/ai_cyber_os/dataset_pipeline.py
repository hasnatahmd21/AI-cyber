    manifest = load_manifest(manifest_path)
    inspection = inspect_dataset(manifest_path)

    # Report deterministic integrity failures before the aggregate readiness
    # check so callers/tests can distinguish checksum failures from record-count
    # failures.  A bad checksum must never be hidden behind the generic
    # "integrity/count" error.
    if "artifacts" not in manifest:
        if require_checksum and not inspection["sha256_matches"]:
            raise ValueError("dataset SHA-256 does not match manifest")
        if not inspection["record_count_matches"]:
            raise ValueError("dataset record count does not match manifest")
    else:
        for artifact in inspection["artifacts"]:
            if require_checksum and not artifact["sha256_matches"]:
                raise ValueError("dataset SHA-256 does not match manifest")
            if not artifact["record_count_matches"]:
                raise ValueError("dataset record count does not match manifest")

    if not inspection["ready"]:
        raise ValueError("dataset manifest integrity/count validation failed")
    if "artifacts" in manifest: