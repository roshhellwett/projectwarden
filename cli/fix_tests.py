import os

audit = 'tests/audit_test.py'
with open(audit, 'r', encoding='utf-8') as f:
    c = f.read()
c = c.replace('def test(name, fn):', 'def run_audit_test(name, fn):')
c = c.replace('\ntest(\"', '\nrun_audit_test(\"')
with open(audit, 'w', encoding='utf-8') as f:
    f.write(c)

test_cmds = 'tests/test_commands.py'
with open(test_cmds, 'r', encoding='utf-8') as f:
    c2 = f.read()
if 'import mock' not in c2 and 'unittest.mock' not in c2:
    c2 = 'from unittest.mock import patch\n' + c2
c2 = c2.replace('def test_list_no_vault():', '@patch(\"zenith_passkeys.core.vault.VaultManager.exists\", return_value=False)\ndef test_list_no_vault(mock_exists):')
with open(test_cmds, 'w', encoding='utf-8') as f:
    f.write(c2)

test_host = 'tests/test_native_host.py'
with open(test_host, 'r', encoding='utf-8') as f:
    c3 = f.read()
if 'unittest.mock' not in c3:
    c3 = 'from unittest.mock import patch\n' + c3
c3 = c3.replace('def test_host_no_vault():', '@patch(\"zenith_passkeys.core.vault.VaultManager.exists\", return_value=False)\ndef test_host_no_vault(mock_exists):')
with open(test_host, 'w', encoding='utf-8') as f:
    f.write(c3)
