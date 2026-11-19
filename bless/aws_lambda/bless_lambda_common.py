"""
.. module: bless.aws_lambda.bless_lambda_common
    :copyright: (c) 2016 by Netflix Inc., see AUTHORS for more
    :license: Apache, see LICENSE for more details.
"""
import logging
import os
import time

import boto3
from bless.audit.audit_ledger import AuditLedger, generate_serial
from bless.cache.bless_lambda_cache import BlessLambdaCache
from bless.config.bless_config import BLESS_OPTIONS_SECTION, LOGGING_LEVEL_OPTION, ENTROPY_MINIMUM_BITS_OPTION, \
    RANDOM_SEED_BYTES_OPTION, AUDIT_LEDGER_FILE_OPTION

global_bless_cache = None


def success_response(cert):
    return {
        'certificate': cert
    }


def error_response(error_type, error_message):
    return {
        'errorType': error_type,
        'errorMessage': error_message
    }


def issue_certificate_transaction(config, cert_builder, audit_fields=None,
                                  bypass_time_validity_check=False):
    """
    Atomically issue an SSH Certificate and its audit record.

    A unique serial number is embedded into the signed certificate body (and its key_id) and
    committed to the append-only audit ledger before the certificate is returned.  The serial
    is the shared revocation identity binding the certificate to its ledger record, so the two
    can never diverge: a certificate is only ever returned to the caller after its unique audit
    record has been durably committed.

    :param config: The BlessConfig for this deployment.
    :param cert_builder: A fully populated SSHCertificateBuilder (principals, validity, key_id).
    :param audit_fields: Optional dict of request-specific attributes to include in the audit
    record.
    :param bypass_time_validity_check: Passed through to the certificate builder.
    :return: Tuple of (certificate file contents, serial number).
    :raises bless.audit.audit_ledger.AuditLedgerError: If the audit record cannot be committed.
    The certificate must not be returned to the caller in that case.
    """
    serial = generate_serial()
    cert_builder.set_serial(serial)

    base_key_id = cert_builder.key_id if cert_builder.key_id else ''
    key_id = 'serial[{}] {}'.format(serial, base_key_id).strip()
    cert_builder.set_key_id(key_id)

    cert = cert_builder.get_cert_file(bypass_time_validity_check)

    record = dict(audit_fields) if audit_fields else {}
    record.update({
        'serial': serial,
        'key_id': key_id,
        'fingerprint': cert_builder.ssh_public_key.fingerprint,
        'principals': list(cert_builder.valid_principals),
        'valid_after': cert_builder.valid_after,
        'valid_before': cert_builder.valid_before,
        'issued_at': int(time.time()),
    })

    ledger = AuditLedger(config.get(BLESS_OPTIONS_SECTION, AUDIT_LEDGER_FILE_OPTION))
    ledger.commit_issuance(record)

    return cert, serial


def set_logger(config):
    logging_level = config.get(BLESS_OPTIONS_SECTION, LOGGING_LEVEL_OPTION)
    numeric_level = getattr(logging, logging_level.upper(), None)
    if not isinstance(numeric_level, int):
        raise ValueError('Invalid log level: {}'.format(logging_level))

    logger = logging.getLogger()
    logger.setLevel(numeric_level)
    return logger


def check_entropy(config, logger):
    """
    Check the entropy pool and seed it with KMS if desired
    """
    region = os.environ['AWS_REGION']
    kms_client = boto3.client('kms', region_name=region)
    entropy_minimum_bits = config.getint(BLESS_OPTIONS_SECTION, ENTROPY_MINIMUM_BITS_OPTION)
    random_seed_bytes = config.getint(BLESS_OPTIONS_SECTION, RANDOM_SEED_BYTES_OPTION)

    with open('/proc/sys/kernel/random/entropy_avail', 'r') as f:
        entropy = int(f.read())
        logger.debug(entropy)
        if entropy < entropy_minimum_bits:
            logger.info(
                'System entropy was {}, which is lower than the entropy_'
                'minimum {}.  Using KMS to seed /dev/urandom'.format(
                    entropy, entropy_minimum_bits))
            response = kms_client.generate_random(
                NumberOfBytes=random_seed_bytes)
            random_seed = response['Plaintext']
            with open('/dev/urandom', 'w') as urandom:
                urandom.write(random_seed)


def setup_lambda_cache(ca_private_key_password, config_file):
    # For testing, ignore the static bless_cache, otherwise fill the cache one time.
    global global_bless_cache
    if ca_private_key_password is not None or config_file is not None:
        bless_cache = BlessLambdaCache(ca_private_key_password, config_file)
    elif global_bless_cache is None:
        global_bless_cache = BlessLambdaCache(config_file=os.path.join(os.getcwd(), 'bless_deploy.cfg'))
        bless_cache = global_bless_cache
    else:
        bless_cache = global_bless_cache
    return bless_cache
