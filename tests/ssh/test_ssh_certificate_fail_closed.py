import pytest

from bless.ssh.certificates.rsa_certificate_builder import RSACertificateBuilder
from bless.ssh.certificates.ssh_certificate_builder import SSHCertificateType
from bless.ssh.public_keys.rsa_public_key import RSAPublicKey
from tests.ssh.vectors import RSA_CA_PRIVATE_KEY, RSA_CA_PRIVATE_KEY_PASSWORD, \
    EXAMPLE_RSA_PUBLIC_KEY


class FailingCA(object):
    def __init__(self, wrapped_ca):
        self._wrapped_ca = wrapped_ca
        self.fail_signing = False
        self.sign_calls = 0

    def get_signature_key(self):
        return self._wrapped_ca.get_signature_key()

    def sign(self, body):
        self.sign_calls += 1
        if self.fail_signing:
            raise RuntimeError('CA signing failed.')
        return self._wrapped_ca.sign(body)


def get_builder_with_failing_ca():
    from bless.ssh.certificate_authorities.rsa_certificate_authority import \
        RSACertificateAuthority
    real_ca = RSACertificateAuthority(RSA_CA_PRIVATE_KEY, RSA_CA_PRIVATE_KEY_PASSWORD)
    ca = FailingCA(real_ca)
    pub_key = RSAPublicKey(EXAMPLE_RSA_PUBLIC_KEY)
    return ca, RSACertificateBuilder(ca, SSHCertificateType.USER, pub_key)


def test_signing_failure_does_not_cache_a_partial_certificate():
    ca, cert_builder = get_builder_with_failing_ca()

    cert_builder.add_valid_principal('user1')
    cert_builder.set_valid_before(2000000000)
    cert_builder.set_valid_after(1000000000)

    ca.fail_signing = True
    with pytest.raises(RuntimeError):
        cert_builder._sign_cert()

    # No partially issued certificate state survives the failure.
    assert cert_builder.signed_cert is None

    # Once the CA recovers, signing succeeds and produces a complete cert.
    ca.fail_signing = False
    signed_cert = cert_builder._sign_cert()
    assert signed_cert is not None
    assert ca.sign_calls == 2


def test_get_cert_file_fails_closed_when_signing_fails():
    ca, cert_builder = get_builder_with_failing_ca()

    cert_builder.add_valid_principal('user1')
    cert_builder.set_valid_before(2000000000)
    cert_builder.set_valid_after(1000000000)

    ca.fail_signing = True
    with pytest.raises(RuntimeError):
        cert_builder.get_cert_file()

    assert cert_builder.signed_cert is None


def test_successful_cert_is_all_or_nothing_and_complete():
    ca, cert_builder = get_builder_with_failing_ca()

    cert_builder.add_valid_principal('user1')
    cert_builder.set_valid_before(2000000000)
    cert_builder.set_valid_after(1000000000)

    cert_file = cert_builder.get_cert_file()

    assert cert_file.startswith('ssh-rsa-cert-v01@openssh.com ')
    # Re-using the cached, fully-issued cert must not trigger another signing.
    assert cert_builder.get_cert_file() == cert_file
    assert ca.sign_calls == 1
