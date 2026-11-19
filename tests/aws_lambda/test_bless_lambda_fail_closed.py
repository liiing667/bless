import logging
import os

import pytest

from bless.aws_lambda.bless_lambda_user import lambda_handler_user
from bless.aws_lambda.bless_lambda_host import lambda_handler_host
from tests.ssh.vectors import EXAMPLE_RSA_PUBLIC_KEY, RSA_CA_PRIVATE_KEY_PASSWORD

CONFIG = os.path.join(os.path.dirname(__file__), 'bless-test.cfg')


class Context(object):
    aws_request_id = 'bogus aws_request_id'
    invoked_function_arn = 'bogus invoked_function_arn'


VALID_TEST_REQUEST = {
    "remote_usernames": "user",
    "public_key_to_sign": EXAMPLE_RSA_PUBLIC_KEY,
    "command": "ssh user@server",
    "bastion_ips": "127.0.0.1",
    "bastion_user": "user",
    "bastion_user_ip": "127.0.0.1"
}


def run_user(mocker, request=None):
    return lambda_handler_user(
        request or VALID_TEST_REQUEST,
        context=Context,
        ca_private_key_password=RSA_CA_PRIVATE_KEY_PASSWORD,
        entropy_check=False,
        config_file=CONFIG)


def test_ca_signing_failure_returns_error_and_no_certificate(mocker):
    mocker.patch(
        'bless.aws_lambda.bless_lambda_user.get_ssh_certificate_authority') \
        .return_value.sign.side_effect = RuntimeError('CA signing failed.')

    output = run_user(mocker)

    assert 'certificate' not in output
    assert output['errorType'] == 'CertificateIssuanceError'


def test_certificate_builder_failure_returns_error_and_no_certificate(mocker):
    builder_mock = mocker.MagicMock()
    builder_mock.get_cert_file.side_effect = RuntimeError('extension boom')
    mocker.patch(
        'bless.aws_lambda.bless_lambda_user.get_ssh_certificate_builder',
        return_value=builder_mock)

    output = run_user(mocker)

    assert 'certificate' not in output
    assert output['errorType'] == 'CertificateIssuanceError'


def test_failed_issuance_does_not_write_issued_audit_log(mocker, caplog):
    mocker.patch(
        'bless.aws_lambda.bless_lambda_user.get_ssh_certificate_authority') \
        .return_value.sign.side_effect = RuntimeError('CA signing failed.')

    with caplog.at_level(logging.INFO):
        output = run_user(mocker)

    assert output['errorType'] == 'CertificateIssuanceError'
    assert not any('Issued a cert' in record.message for record in caplog.records)


def test_successful_issuance_still_returns_certificate_and_audit(mocker, caplog):
    with caplog.at_level(logging.INFO):
        output = run_user(mocker)

    assert output['certificate'].startswith('ssh-rsa-cert-v01@openssh.com ')
    assert any('Issued a cert' in record.message for record in caplog.records)


@pytest.mark.parametrize("field,value", [
    ("bastion_ips", ""),
    ("bastion_user_ip", ""),
    ("bastion_ips", "127.0.0.1,"),
    ("bastion_user_ip", ",127.0.0.1"),
    ("remote_usernames", ""),
    ("remote_usernames", "user,"),
])
def test_entrypoint_rejects_empty_principals_and_addresses(mocker, field, value):
    request = dict(VALID_TEST_REQUEST)
    request[field] = value

    output = run_user(mocker, request)

    assert 'certificate' not in output
    assert output['errorType'] == 'InputValidationError'


@pytest.mark.parametrize("ips", [
    "127.0.0.1",
    "10.0.0.0/8",
    "::1",
    "fe80::/10",
    "127.0.0.1,10.0.0.0/8,::1",
])
def test_legitimate_ipv4_ipv6_and_cidr_inputs_remain_compatible(mocker, ips):
    request = dict(VALID_TEST_REQUEST)
    request["bastion_ips"] = ips
    request["bastion_user_ip"] = ips.split(',')[0]

    output = run_user(mocker, request)

    assert output['certificate'].startswith('ssh-rsa-cert-v01@openssh.com ')


def test_host_ca_signing_failure_fails_closed(mocker):
    mocker.patch(
        'bless.aws_lambda.bless_lambda_host.get_ssh_certificate_authority') \
        .return_value.sign.side_effect = RuntimeError('CA signing failed.')

    output = lambda_handler_host(
        {"public_key_to_sign": EXAMPLE_RSA_PUBLIC_KEY, "hostnames": "thisthat.com"},
        context=Context,
        ca_private_key_password=RSA_CA_PRIVATE_KEY_PASSWORD,
        entropy_check=False,
        config_file=CONFIG)

    assert 'certificate' not in output
    assert output['errorType'] == 'CertificateIssuanceError'


def test_host_empty_hostname_rejected_at_entrypoint(mocker):
    output = lambda_handler_host(
        {"public_key_to_sign": EXAMPLE_RSA_PUBLIC_KEY, "hostnames": "good.com,"},
        context=Context,
        ca_private_key_password=RSA_CA_PRIVATE_KEY_PASSWORD,
        entropy_check=False,
        config_file=CONFIG)

    assert 'certificate' not in output
    assert output['errorType'] == 'InputValidationError'
