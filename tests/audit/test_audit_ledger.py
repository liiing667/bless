import threading

import pytest

from bless.audit.audit_ledger import AuditLedger, AuditLedgerError, generate_serial, UINT64_MAX


def test_generate_serial_is_nonzero_uint64():
    serials = {generate_serial() for _ in range(1000)}
    assert all(0 < s <= UINT64_MAX for s in serials)
    assert len(serials) == 1000


def test_commit_and_read_back(tmp_path):
    ledger = AuditLedger(str(tmp_path / 'ledger.jsonl'))
    ledger.commit_issuance({'serial': 42, 'key_id': 'serial[42] test'})
    ledger.commit_issuance({'serial': 43, 'key_id': 'serial[43] test'})

    records = ledger.read_all()
    assert [r['serial'] for r in records] == [42, 43]
    assert records[0]['key_id'] == 'serial[42] test'


def test_commit_rejects_duplicate_serial(tmp_path):
    ledger = AuditLedger(str(tmp_path / 'ledger.jsonl'))
    ledger.commit_issuance({'serial': 7})
    with pytest.raises(AuditLedgerError):
        ledger.commit_issuance({'serial': 7})

    assert len(ledger.read_all()) == 1


def test_commit_requires_serial(tmp_path):
    ledger = AuditLedger(str(tmp_path / 'ledger.jsonl'))
    with pytest.raises(AuditLedgerError):
        ledger.commit_issuance({'key_id': 'no serial'})


def test_commit_requires_path():
    with pytest.raises(AuditLedgerError):
        AuditLedger('')


def test_commit_fails_closed_on_unwritable_path(tmp_path):
    ledger = AuditLedger(str(tmp_path / 'missing-dir' / 'ledger.jsonl'))
    with pytest.raises(AuditLedgerError):
        ledger.commit_issuance({'serial': 1})


def test_concurrent_commits_are_all_recorded(tmp_path):
    ledger = AuditLedger(str(tmp_path / 'ledger.jsonl'))
    serials = [generate_serial() for _ in range(64)]
    errors = []

    def commit(serial):
        try:
            ledger.commit_issuance({'serial': serial})
        except AuditLedgerError as e:
            errors.append(e)

    threads = [threading.Thread(target=commit, args=(s,)) for s in serials]
    for t in threads:
        t.start()
    for t in threads:
        t.join()

    assert not errors
    committed = {r['serial'] for r in ledger.read_all()}
    assert committed == set(serials)


def test_concurrent_duplicate_serial_committed_once(tmp_path):
    ledger = AuditLedger(str(tmp_path / 'ledger.jsonl'))
    results = []

    def commit():
        try:
            ledger.commit_issuance({'serial': 99})
            results.append('ok')
        except AuditLedgerError:
            results.append('rejected')

    threads = [threading.Thread(target=commit) for _ in range(16)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()

    assert results.count('ok') == 1
    assert len(ledger.read_all()) == 1
