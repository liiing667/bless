"""
.. module: bless.aws_lambda.bless_lambda_host
    :copyright: (c) 2016 by Netflix Inc., see AUTHORS for more
    :license: Apache, see LICENSE for more details.
"""
import time

from bless.audit.audit_ledger import AuditLedgerError
from bless.aws_lambda.bless_lambda_common import success_response, error_response, set_logger, check_entropy, \
    setup_lambda_cache, issue_certificate_transaction
from bless.config.bless_config import BLESS_OPTIONS_SECTION, SERVER_CERTIFICATE_VALIDITY_BEFORE_SEC_OPTION, \
    SERVER_CERTIFICATE_VALIDITY_AFTER_SEC_OPTION, HOSTNAME_VALIDATION_OPTION
from bless.request.bless_request_host import BlessHostSchema
from bless.ssh.certificate_authorities.ssh_certificate_authority_factory import get_ssh_certificate_authority
from bless.ssh.certificates.ssh_certificate_builder import SSHCertificateType
from bless.ssh.certificates.ssh_certificate_builder_factory import get_ssh_certificate_builder
from marshmallow import ValidationError


def lambda_handler_host(
        event, context=None, ca_private_key_password=None,
        entropy_check=True,
        config_file=None):
    """
    This is the function that will be called when the lambda function starts.
    :param event: Dictionary of the json request.
    :param context: AWS LambdaContext Object
    http://docs.aws.amazon.com/lambda/latest/dg/python-context-object.html
    :param ca_private_key_password: For local testing, if the password is provided, skip the KMS
    decrypt.
    :param entropy_check: For local testing, if set to false, it will skip checking entropy and
    won't try to fetch additional random from KMS.
    :param config_file: The config file to load the SSH CA private key from, and additional settings.
    :return: the SSH Certificate that can be written to id_rsa-cert.pub or similar file.
    """
    bless_cache = setup_lambda_cache(ca_private_key_password, config_file)

    # Load the deployment config values
    config = bless_cache.config

    logger = set_logger(config)

    certificate_validity_before_seconds = config.getint(BLESS_OPTIONS_SECTION,
                                                        SERVER_CERTIFICATE_VALIDITY_BEFORE_SEC_OPTION)
    certificate_validity_after_seconds = config.getint(BLESS_OPTIONS_SECTION,
                                                       SERVER_CERTIFICATE_VALIDITY_AFTER_SEC_OPTION)

    ca_private_key = config.getprivatekey()

    # Process cert request
    schema = BlessHostSchema(strict=True)
    schema.context[HOSTNAME_VALIDATION_OPTION] = config.get(BLESS_OPTIONS_SECTION, HOSTNAME_VALIDATION_OPTION)

    try:
        request = schema.load(event).data
    except ValidationError as e:
        return error_response('InputValidationError', str(e))

    # todo: You'll want to bring your own hostnames validation.
    logger.info('Bless lambda invoked by [public_key: {}] for hostnames[{}]'.format(request.public_key_to_sign,
                                                                                    request.hostnames))

    # Make sure we have the ca private key password
    if bless_cache.ca_private_key_password is None:
        return error_response('ClientError', bless_cache.ca_private_key_password_error)
    else:
        ca_private_key_password = bless_cache.ca_private_key_password

    # if running as a Lambda, we can check the entropy pool and seed it with KMS if desired
    if entropy_check:
        check_entropy(config, logger)

    # cert values determined only by lambda and its configs
    current_time = int(time.time())
    valid_before = current_time + certificate_validity_after_seconds
    valid_after = current_time - certificate_validity_before_seconds

    # Build the cert
    ca = get_ssh_certificate_authority(ca_private_key, ca_private_key_password)
    cert_builder = get_ssh_certificate_builder(ca, SSHCertificateType.HOST,
                                               request.public_key_to_sign)

    for hostname in request.hostnames.split(','):
        cert_builder.add_valid_principal(hostname)

    cert_builder.set_valid_before(valid_before)
    cert_builder.set_valid_after(valid_after)

    # cert_builder is needed to obtain the SSH public key's fingerprint
    key_id = 'request[{}] ssh_key[{}] ca[{}] valid_to[{}]'.format(
        context.aws_request_id, cert_builder.ssh_public_key.fingerprint, context.invoked_function_arn,
        time.strftime("%Y/%m/%d %H:%M:%S", time.gmtime(valid_before))
    )

    cert_builder.set_key_id(key_id)

    # Commit the unique audit record before the certificate is returned to the caller.  The
    # serial embedded in the signed certificate is the revocation identity recorded in the
    # audit ledger, so a returned certificate is always traceable and revocable.
    try:
        cert, serial = issue_certificate_transaction(
            config, cert_builder,
            audit_fields={
                'certificate_type': 'host',
                'request_id': context.aws_request_id,
                'hostnames': request.hostnames,
            })
    except AuditLedgerError as e:
        logger.error('Refusing to return certificate without a committed audit record: {}'.format(e))
        return error_response('AuditError',
                              'Certificate issuance could not be audited; no certificate was issued')

    logger.info(
        'Issued a server cert to hostnames[{}] with serial[{}] key_id[{}] and '
        'valid_from[{}])'.format(
            request.hostnames, serial, cert_builder.key_id,
            time.strftime("%Y/%m/%d %H:%M:%S", time.gmtime(valid_after))))
    return success_response(cert)
