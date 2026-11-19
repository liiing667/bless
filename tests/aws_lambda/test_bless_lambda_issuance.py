import base64
import os
import struct
from concurrent.futures import ThreadPoolExecutor

from cryptography.hazmat.primitives.serialization.ssh import _ssh_read_next_string

from bless.audit.audit_ledger import AuditLedger
from bless.aws_lambda.bless_lambda_host import lambda_handler_host
from bless.aws_lambda.bless_lambda_user import lambda_handler_user
from tests.ssh.vectors import EXAMPLE_RSA_PUBLIC_KEY, RSA_CA_PRIVATE_KEY_PASSWORD

os.environ['AWS_REGION'] = 'us-west-2'


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

VALID_TEST_REQUEST_IPV6_CIDR = {
    "remote_usernames": "user",
    "public_key_to_sign": EXAMPLE_RSA_PUBLIC_KEY,
    "command": "ssh user@server",
    "bastion_ips": "10.0.0.0/8,2001:db8::/32",
    "bastion_user": "user",
    "bastion_user_ip": "2001:db8::1"
}

VALID_HOST_REQUEST = {
    "public_key_to_sign": EXAMPLE_RSA_PUBLIC_KEY,
    "hostnames": "thisthat.com",
}

INVALID_TEST_REQUEST = {
    "remote_usernames": "user",
    "public_key_to_sign": EXAMPLE_RSA_PUBLIC_KEY,
    "command": "ssh user@server",
    "bastion_ips": "invalid_ip",
    "bastion_user": "user",
    "bastion_user_ip": "invalid_ip"
}

CONFIG_TEMPLATE = """
[Bless CA]
ca_private_key_file = tests/aws_lambda/only-use-for-unit-tests.pem
us-east-1_password = bogus-password-for-unit-test
us-west-2_password = bogus-password-for-unit-tests

[Bless Options]
audit_ledger_file = {ledger}
{extra_options}
"""


def make_config(tmp_path, extra_options=''):
    ledger = tmp_path / 'ledger.jsonl'
    config_file = tmp_path / 'bless-test.cfg'
    config_file.write_text(CONFIG_TEMPLATE.format(ledger=ledger, extra_options=extra_options))
    return str(config_file), str(ledger)


def cert_serial(cert_file_contents):
    remainder = base64.b64decode(cert_file_contents.split(' ')[1])
    _, remainder = _ssh_read_next_string(remainder)  # cert key type
    _, remainder = _ssh_read_next_string(remainder)  # nonce
    _, remainder = _ssh_read_next_string(remainder)  # rsa e
    _, remainder = _ssh_read_next_string(remainder)  # rsa n
    return struct.unpack('>Q', remainder[:8])[0]


def issue_user(config_file, request=None):
    return lambda_handler_user(request or VALID_TEST_REQUEST, context=Context,
                               ca_private_key_password=RSA_CA_PRIVATE_KEY_PASSWORD,
                               entropy_check=False, config_file=config_file)


def test_issued_certificate_has_unique_audit_record(tmp_path):
    config_file, ledger_path = make_config(tmp_path)
    output = issue_user(config_file)
    assert output['certificate'].startswith('ssh-rsa-cert-v01@openssh.com ')

    serial = cert_serial(output['certificate'])
    assert serial != 0

    records = AuditLedger(ledger_path).read_all()
    matching = [r for r in records if r['serial'] == serial]
    assert len(matching) == 1

    record = matching[0]
    assert 'serial[{}]'.format(serial) in record['key_id']
    assert record['principals'] == ['user']
    assert record['bastion_user'] == 'user'
    assert record['remote_usernames'] == 'user'
    assert record['certificate_type'] == 'user'


def test_serials_are_unique_across_issuances(tmp_path):
    config_file, ledger_path = make_config(tmp_path)
    serials = {cert_serial(issue_user(config_file)['certificate']) for _ in range(4)}
    assert len(serials) == 4
    assert {r['serial'] for r in AuditLedger(ledger_path).read_all()} == serials


def test_audit_failure_returns_no_certificate(tmp_path):
    config_file, _ = make_config(tmp_path)
    config_file_bad = str(tmp_path / 'bad.cfg')
    with open(config_file) as f:
        contents = f.read().replace(str(tmp_path / 'ledger.jsonl'),
                                    str(tmp_path / 'missing-dir' / 'ledger.jsonl'))
    with open(config_file_bad, 'w') as f:
        f.write(contents)

    output = issue_user(config_file_bad)
    assert 'certificate' not in output
    assert output['errorType'] == 'AuditError'


def test_failed_issuance_writes_no_audit_record(tmp_path):
    config_file, ledger_path = make_config(tmp_path)
    output = issue_user(config_file, INVALID_TEST_REQUEST)
    assert 'certificate' not in output
    assert not os.path.exists(ledger_path)


def test_concurrent_issuances_are_all_audited(tmp_path):
    config_file, ledger_path = make_config(tmp_path)
    with ThreadPoolExecutor(max_workers=8) as pool:
        outputs = list(pool.map(issue_user, [config_file] * 16))

    assert all('certificate' in o for o in outputs)
    serials = [cert_serial(o['certificate']) for o in outputs]
    assert len(set(serials)) == len(serials)

    committed = {r['serial'] for r in AuditLedger(ledger_path).read_all()}
    assert committed == set(serials)


def test_ipv6_and_cidr_request_is_issued_and_audited(tmp_path):
    config_file, ledger_path = make_config(tmp_path)
    output = issue_user(config_file, VALID_TEST_REQUEST_IPV6_CIDR)
    assert output['certificate'].startswith('ssh-rsa-cert-v01@openssh.com ')

    serial = cert_serial(output['certificate'])
    records = [r for r in AuditLedger(ledger_path).read_all() if r['serial'] == serial]
    assert len(records) == 1
    assert records[0]['bastion_ips'] == '10.0.0.0/8,2001:db8::/32'


def test_test_user_issuance_is_still_audited(tmp_path):
    config_file, ledger_path = make_config(tmp_path, extra_options='test_user = user')
    output = issue_user(config_file)
    assert output['certificate'].startswith('ssh-rsa-cert-v01@openssh.com ')

    serial = cert_serial(output['certificate'])
    assert serial in {r['serial'] for r in AuditLedger(ledger_path).read_all()}


def test_host_certificate_is_audited(tmp_path):
    config_file, ledger_path = make_config(tmp_path)
    output = lambda_handler_host(VALID_HOST_REQUEST, context=Context,
                                 ca_private_key_password=RSA_CA_PRIVATE_KEY_PASSWORD,
                                 entropy_check=False, config_file=config_file)
    assert output['certificate'].startswith('ssh-rsa-cert-v01@openssh.com ')

    serial = cert_serial(output['certificate'])
    records = [r for r in AuditLedger(ledger_path).read_all() if r['serial'] == serial]
    assert len(records) == 1
    assert records[0]['principals'] == ['thisthat.com']
    assert records[0]['certificate_type'] == 'host'


def test_host_audit_failure_returns_no_certificate(tmp_path):
    config_file, _ = make_config(tmp_path)
    config_file_bad = str(tmp_path / 'bad.cfg')
    with open(config_file) as f:
        contents = f.read().replace(str(tmp_path / 'ledger.jsonl'),
                                    str(tmp_path / 'missing-dir' / 'ledger.jsonl'))
    with open(config_file_bad, 'w') as f:
        f.write(contents)

    output = lambda_handler_host(VALID_HOST_REQUEST, context=Context,
                                 ca_private_key_password=RSA_CA_PRIVATE_KEY_PASSWORD,
                                 entropy_check=False, config_file=config_file_bad)
    assert 'certificate' not in output
    assert output['errorType'] == 'AuditError'
