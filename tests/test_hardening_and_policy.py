from __future__ import annotations

import json
from pathlib import Path

import pytest

from cloudsec_aws_lab.config import load_config
from cloudsec_aws_lab.exceptions import InputValidationError
from cloudsec_aws_lab.io_utils import load_json
from cloudsec_aws_lab.least_privilege import normalize_cloudtrail_action, recommend_from_cloudtrail


def test_cloudtrail_action_normalization_removes_amazonaws_domain():
    assert normalize_cloudtrail_action("iam.amazonaws.com:CreateAccessKey") == "iam:CreateAccessKey"
    assert normalize_cloudtrail_action("s3.amazonaws.com:PutBucketPolicy") == "s3:PutBucketPolicy"
    assert normalize_cloudtrail_action("sts:AssumeRole") == "sts:AssumeRole"
    assert normalize_cloudtrail_action("signin.amazonaws.com:ConsoleLogin") is None
    assert normalize_cloudtrail_action("not a valid action") is None


def test_least_privilege_policy_draft_contains_valid_iam_actions():
    recs = recommend_from_cloudtrail({
        "actions_by_principal": {
            "arn:aws:iam::111122223333:user/alice": {
                "iam.amazonaws.com:CreateAccessKey": 1,
                "signin.amazonaws.com:ConsoleLogin": 2,
            }
        }
    })
    actions = recs[0]["draft_policy"]["Statement"][0]["Action"]
    assert "iam:CreateAccessKey" in actions
    assert "signin:ConsoleLogin" not in actions
    assert all("amazonaws.com" not in action for action in actions)


def test_load_json_rejects_malformed_json(tmp_path: Path):
    bad = tmp_path / "bad.json"
    bad.write_text('{"Records": [', encoding="utf-8")
    with pytest.raises(InputValidationError):
        load_json(bad)


def test_load_json_rejects_large_file(tmp_path: Path):
    large = tmp_path / "large.json"
    large.write_text(json.dumps({"x": "a" * 100}), encoding="utf-8")
    with pytest.raises(InputValidationError):
        load_json(large, max_bytes=10)


def test_config_rejects_unknown_keys(tmp_path: Path):
    cfg = tmp_path / "bad.yml"
    cfg.write_text("unexpected_key: true\n", encoding="utf-8")
    with pytest.raises(InputValidationError):
        load_config(str(cfg))
