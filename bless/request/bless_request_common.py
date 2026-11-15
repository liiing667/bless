"""
.. module: bless.request.bless_request_common
    :copyright: (c) 2016 by Netflix Inc., see AUTHORS for more
    :license: Apache, see LICENSE for more details.
"""
import ipaddress
import re

from marshmallow import ValidationError

VALID_SSH_RSA_PUBLIC_KEY_HEADER = "ssh-rsa AAAAB3NzaC1yc2"
VALID_SSH_ED25519_PUBLIC_KEY_HEADER = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5"

# It appears that most printable ascii is valid, excluding whitespace, #, and commas.
# There doesn't seem to be any practical size limits of an SSH Certificate Principal (> 4096B allowed).
PRINCIPAL_PATTERN = re.compile(r'[\d\w!"$%&\'()*+\-./:;<=>?@\[\\\]\^`{|}~]+\Z')


def validate_ssh_public_key(public_key):
    if public_key.startswith(VALID_SSH_RSA_PUBLIC_KEY_HEADER) or public_key.startswith(
            VALID_SSH_ED25519_PUBLIC_KEY_HEADER):
        pass
    # todo other key types
    else:
        raise ValidationError('Invalid SSH Public Key.')


def validate_ip_list(ips):
    """
    Canonical validation of a comma-separated list of IPs or CIDRs.  Both the request
    schemas and the SSH Certificate Builder use this so that a validated request can
    never be serialized into a certificate with a different source-address scope.
    :param ips: String of one or more comma-separated IPs or CIDRs.
    """
    try:
        for ip in ips.split(','):
            ipaddress.ip_network(ip, strict=True)
    except ValueError:
        raise ValidationError('Invalid IP address.')


def validate_principal(principal):
    """
    Canonical validation of a single SSH Certificate Principal.  Principals must be
    non-empty and cannot contain the list delimiter (','), whitespace, or '#'.
    :param principal: String with the username or hostname.
    """
    if PRINCIPAL_PATTERN.match(principal) is None:
        raise ValidationError('Principal contains invalid characters.')
