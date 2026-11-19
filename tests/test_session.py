import boto3
import pytest
from moto import mock_aws

from cspm_collector.core.config import AccountSettings
from cspm_collector.core.session import AccountSession


@mock_aws
def test_assume_role_with_external_id_and_clients_cached(monkeypatch):
    monkeypatch.setenv("CSPM_EXT", "secret-ext")
    iam = boto3.client("iam", region_name="us-east-1")
    role = iam.create_role(RoleName="r", AssumeRolePolicyDocument="{}")["Role"]["Arn"]
    s = AccountSession(AccountSettings(account_id="123456789012", role_arn=role, external_id_env="CSPM_EXT"))
    assert s.client("ec2", "us-east-1") is s.client("ec2", "us-east-1")
    assert s.client("ec2", "us-west-2") is not s.client("ec2", "us-east-1")
    assert s.client("sts").get_caller_identity()["Arn"].startswith("arn:aws:sts::")


def test_missing_external_id_env_fails_clearly(monkeypatch):
    monkeypatch.delenv("CSPM_EXT", raising=False)
    with pytest.raises(RuntimeError, match="CSPM_EXT"):
        AccountSession(AccountSettings(account_id="1", role_arn="arn:aws:iam::1:role/r", external_id_env="CSPM_EXT"))


@mock_aws
def test_regions_from_config_or_discovery():
    fixed = AccountSession(AccountSettings(account_id="1", regions=["ap-northeast-2"]))
    assert fixed.target_regions() == ["ap-northeast-2"]
    regions = AccountSession(AccountSettings(account_id="1")).target_regions()
    assert "us-east-1" in regions and "ap-northeast-2" in regions


@mock_aws
def test_s3_in_us_east_1_uses_the_regional_endpoint():
    """The global s3.amazonaws.com endpoint is re-signed by TLS-inspecting proxies and fails certificate checks."""
    s = AccountSession(AccountSettings(account_id="1"))
    assert s.client("s3", "us-east-1").meta.endpoint_url == "https://s3.us-east-1.amazonaws.com"
    assert s.client("s3", "ap-northeast-2").meta.endpoint_url == "https://s3.ap-northeast-2.amazonaws.com"
    assert s.client("iam", "us-east-1").meta.endpoint_url == "https://iam.amazonaws.com"  # other services unchanged
