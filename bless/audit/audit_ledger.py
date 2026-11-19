"""
.. module: bless.audit.audit_ledger
    :copyright: (c) 2016 by Netflix Inc., see AUTHORS for more
    :license: Apache, see LICENSE for more details.
"""
import json
import os
import threading

try:
    import fcntl
except ImportError:  # pragma: no cover - non-POSIX platforms
    fcntl = None

UINT64_MAX = 0xFFFFFFFFFFFFFFFF


class AuditLedgerError(Exception):
    """
    Raised when an issuance cannot be committed to the audit ledger.  Callers must treat this
    as a failed issuance: the certificate must never be returned to the caller.
    """
    pass


def generate_serial():
    """
    Generate a random, non-zero uint64 serial number for a new SSH Certificate.
    Uniqueness is enforced by the AuditLedger at commit time.
    :return: int in [1, 2^64 - 1]
    """
    while True:
        serial = int.from_bytes(os.urandom(8), byteorder='big')
        if serial != 0:
            return serial


class AuditLedger(object):
    """
    Append-only audit ledger for certificate issuance.  Every certificate returned to a caller
    must first be committed here, keyed by the same serial number that is embedded in the
    signed certificate body.  That shared serial is the revocation identity: it cannot diverge
    between the certificate and the ledger, and it can be used to revoke the certificate
    (e.g. via an ssh-keygen KRL, or the key_id logged by sshd).

    Commits are serialized with an in-process lock and an advisory file lock, and are fsync'd
    before returning, so concurrent issuances cannot lose or duplicate audit records.
    """

    _locks = {}
    _locks_guard = threading.Lock()

    def __init__(self, path):
        """
        :param path: Filesystem path of the append-only ledger file (JSON Lines).
        """
        if not path:
            raise AuditLedgerError('An audit ledger file path is required.')
        self.path = path
        with AuditLedger._locks_guard:
            self._lock = AuditLedger._locks.setdefault(os.path.abspath(path), threading.Lock())

    def commit_issuance(self, record):
        """
        Atomically verify the serial is unique and append the issuance record to the ledger,
        fsync'ing before returning.  Raises AuditLedgerError on any failure.
        :param record: dict of issuance attributes.  Must contain a 'serial' entry.
        """
        if 'serial' not in record:
            raise AuditLedgerError('Audit record is missing its serial number.')
        serial = record['serial']

        line = json.dumps(record, sort_keys=True)

        with self._lock:
            try:
                fd = os.open(self.path, os.O_CREAT | os.O_RDWR | os.O_APPEND, 0o600)
            except OSError as e:
                raise AuditLedgerError('Unable to open audit ledger: {}'.format(e))
            try:
                if fcntl is not None:
                    fcntl.flock(fd, fcntl.LOCK_EX)
                if serial in self._read_serials(fd):
                    raise AuditLedgerError(
                        'Serial {} is already present in the audit ledger.'.format(serial))
                os.write(fd, (line + '\n').encode('utf-8'))
                os.fsync(fd)
            except OSError as e:
                raise AuditLedgerError('Unable to commit audit record: {}'.format(e))
            finally:
                if fcntl is not None:
                    try:
                        fcntl.flock(fd, fcntl.LOCK_UN)
                    except OSError:
                        pass
                os.close(fd)

    def read_all(self):
        """
        Read every committed issuance record.
        :return: list of dicts, in commit order.
        """
        records = []
        try:
            with open(self.path, 'r') as f:
                for line in f:
                    line = line.strip()
                    if line:
                        records.append(json.loads(line))
        except IOError as e:
            raise AuditLedgerError('Unable to read audit ledger: {}'.format(e))
        return records

    @staticmethod
    def _read_serials(fd):
        serials = set()
        os.lseek(fd, 0, os.SEEK_SET)
        data = b''
        while True:
            chunk = os.read(fd, 1 << 16)
            if not chunk:
                break
            data += chunk
        for line in data.decode('utf-8').splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                record = json.loads(line)
            except ValueError:
                continue
            if 'serial' in record:
                serials.add(record['serial'])
        return serials
