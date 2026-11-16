#!/usr/bin/env python3
"""Build SEC89 UFS PERF5 PROD1 TRACE1 offline using the local Windows VM and an owned Mac RAM share.

Separate task-key test signing, no installation or VM trust/boot-policy mutation.
This is a single-milestone wrapper around the existing managed RAM allocator.
"""
import argparse
import base64
import json
from pathlib import Path
import shutil
import subprocess
import sys
import time
import uuid

ROOT = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(ROOT / 'tools'))
from ram_scratch import RamScratch


def guest_command(vm, script):
    return ['prlctl', 'exec', vm, 'powershell.exe', '-NoProfile',
            '-NonInteractive', '-EncodedCommand',
            base64.b64encode(script.encode('utf-16le')).decode('ascii')]


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--vm', default='Windows 11')
    parser.add_argument('--evidence', required=True, type=Path)
    args = parser.parse_args()
    evidence = args.evidence.resolve()
    evidence.mkdir(parents=True, exist_ok=False)
    source = Path(__file__).resolve().parent
    token = 'n976n-s89p5ufs-' + uuid.uuid4().hex[:10]
    scratch = RamScratch(512)
    share_attempted = False
    guest_retired = True
    outputs_exported = True
    process = None
    start = time.monotonic()
    result = {'scope': 'SEC89_UFS_PERF5', 'vm': args.vm,
              'phone_access': False, 'driver_installed': False,
              'security_policy_changed': False, 'share': token}
    try:
        scratch.__enter__()
        staged = scratch.path / 'source'
        shutil.copytree(source, staged, ignore=shutil.ignore_patterns(
            '__pycache__', '*.pyc', 'evidence', 'build-*'))
        signing = scratch.path / 'signing'
        signing.mkdir(mode=0o700)
        # New certificate for this candidate. The private key never leaves RAM.
        from datetime import datetime, timedelta, timezone
        from cryptography import x509
        from cryptography.x509.oid import NameOID, ExtendedKeyUsageOID
        from cryptography.hazmat.primitives import hashes, serialization
        from cryptography.hazmat.primitives.asymmetric import rsa
        from cryptography.hazmat.primitives.serialization import pkcs12
        now = datetime.now(timezone.utc)
        key = rsa.generate_private_key(public_exponent=65537, key_size=3072)
        name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, 'N976N SEC89 UFS PERF5 PROD1 TRACE1 Bounded Read Completion')])
        cert = (x509.CertificateBuilder().subject_name(name).issuer_name(name)
                .public_key(key.public_key()).serial_number(x509.random_serial_number())
                .not_valid_before(datetime(2026, 1, 1, tzinfo=timezone.utc)).not_valid_after(now+timedelta(days=365))
                .add_extension(x509.BasicConstraints(ca=False,path_length=None),critical=True)
                .add_extension(x509.KeyUsage(digital_signature=True,content_commitment=False,
                    key_encipherment=False,data_encipherment=False,key_agreement=False,
                    key_cert_sign=False,crl_sign=False,encipher_only=None,decipher_only=None),critical=True)
                .add_extension(x509.ExtendedKeyUsage([ExtendedKeyUsageOID.CODE_SIGNING]),critical=False)
                .sign(key, hashes.SHA256()))
        (signing/'N976nUfsTest.pem').write_bytes(cert.public_bytes(serialization.Encoding.PEM))
        (signing/'N976nUfsTest.cer').write_bytes(cert.public_bytes(serialization.Encoding.DER))
        (signing/'N976nUfsTest.pfx').write_bytes(pkcs12.serialize_key_and_certificates(
            b'N976N SEC89 UFS PERF5 PROD1 TRACE1',key,cert,None,serialization.NoEncryption()))
        (signing/'N976nUfsTest.pfx').chmod(0o600)
        result['certificate'] = {'generated_utc':now.isoformat(),
            'not_before':cert.not_valid_before_utc.isoformat(),
            'not_after':cert.not_valid_after_utc.isoformat(),
            'reason':'fixed development start date for uncertain phone RTC; private key RAM-only'}
        share_attempted = True
        subprocess.run(['prlctl', 'set', args.vm, '--shf-host-add', token,
                        '--path', str(scratch.path), '--mode', 'rw'],
                       check=True, capture_output=True, timeout=30)
        guest = '\\\\Mac\\' + token
        # ScriptBlock invocation is process-local; do not change ExecutionPolicy.
        ps = f"""$ErrorActionPreference='Stop'; $ProgressPreference='SilentlyContinue'
$lease='{guest}'
$global:Sec89Perf5NativeRetired=$true
[IO.File]::WriteAllText((Join-Path $lease 'guest-pid.txt'), [string]$PID)
try {{
  $build=Join-Path $lease 'source\\Build-Trace1.ps1'
  & ([ScriptBlock]::Create([IO.File]::ReadAllText($build))) -SourceDirectory (Join-Path $lease 'source') -OutputDirectory (Join-Path $lease 'output') -SigningDirectory (Join-Path $lease 'signing')
  if (-not $global:Sec89Perf5NativeRetired) {{ throw 'Native child retirement is unconfirmed' }}
  [IO.File]::WriteAllText((Join-Path $lease 'guest-retired.txt'),'success')
  exit 0
}} catch {{
  [IO.File]::WriteAllText((Join-Path $lease 'guest-error.txt'), ($_ | Out-String))
  if ($global:Sec89Perf5NativeRetired) {{
    [IO.File]::WriteAllText((Join-Path $lease 'guest-retired.txt'),'failed')
  }}
  Write-Error $_ -ErrorAction Continue
  exit 1
}}
"""
        with (evidence / 'guest-console.log').open('wb') as log:
            process = subprocess.Popen(guest_command(args.vm, ps), stdout=log,
                                       stderr=subprocess.STDOUT)
            guest_retired = False
            while process.poll() is None:
                try:
                    process.wait(timeout=10)
                except subprocess.TimeoutExpired:
                    scratch.check()
                    if time.monotonic() - start > 900:
                        raise TimeoutError('SEC89 UFS PERF5 PROD1 TRACE1 guest build exceeded 900 seconds')
            result['guest_exit_code'] = process.returncode
            guest_retired = (scratch.path / 'guest-retired.txt').is_file()
            if not guest_retired:
                raise RuntimeError('Guest did not confirm completion; retain RAM for inspection')
        scratch.check()
        result['result'] = 'PASS' if process.returncode == 0 else 'FAIL'
    except Exception as exc:
        result['result'] = 'FAIL'
        result['error'] = str(exc)
        # An unexpected guest/transport failure does not authorize deleting
        # storage still accessible by a compiler. Retain and report it.
        if not guest_retired:
            result['retained_ram_path'] = str(scratch.path)
            result['guest_pid_file'] = str(scratch.path / 'guest-pid.txt')
    finally:
        try:
            if scratch.path and scratch.path.exists():
                out = scratch.path / 'output'
                if out.exists():
                    # Persist small outputs/evidence, not temporary compiler objects.
                    shutil.copytree(out, evidence / 'output',
                                    ignore=shutil.ignore_patterns('obj', 'temp', 'tmp', '*.tlog', '*.ipch'))
                for name in ('guest-error.txt', 'guest-pid.txt', 'guest-retired.txt'):
                    if (scratch.path / name).exists():
                        shutil.copy2(scratch.path / name, evidence / name)
        except Exception as exc:
            outputs_exported = False
            result['result'] = 'FAIL'
            result['evidence_export_error'] = str(exc)
            result['retained_ram_path'] = str(scratch.path)
        if share_attempted and guest_retired:
            try:
                removed = subprocess.run(['prlctl', 'set', args.vm, '--shf-host-del', token],
                                         capture_output=True, timeout=30)
                if removed.returncode:
                    # Share creation may have failed before applying anything.
                    info = subprocess.run(['prlctl', 'list', args.vm, '-i'],
                                          check=True, capture_output=True, timeout=30)
                    if token.encode() in info.stdout:
                        raise RuntimeError('Owned RAM share remains configured')
                result['share_removed'] = True
            except Exception as exc:
                result['share_cleanup_error'] = str(exc)
                result['result'] = 'FAIL'
                guest_retired = False
        if guest_retired and outputs_exported:
            try:
                scratch.__exit__(None, None, None)
            except Exception as exc:
                result['ram_cleanup_error'] = str(exc)
                result['result'] = 'FAIL'
        else:
            scratch.info['cleanup'] = 'retained: export or guest/share retirement unconfirmed'
        result['ram'] = scratch.info
        result['elapsed_seconds'] = round(time.monotonic() - start, 3)
        (evidence / 'local-build.json').write_text(json.dumps(result, indent=2)+'\n')
    print(json.dumps({k: result.get(k) for k in ('result','elapsed_seconds','error','share_removed')}))
    return 0 if result.get('result') == 'PASS' else 1


if __name__ == '__main__':
    raise SystemExit(main())
