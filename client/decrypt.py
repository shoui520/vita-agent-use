# SPDX-License-Identifier: GPL-3.0-or-later
"""Native SELF job orchestration; the PC never receives license keys."""
import hashlib
import math
from pathlib import Path
import re
import time
import uuid
from vita_client import ClientError, VitaClient


def decrypt(client, path, output=None, operation_id=None, timeout=1800, no_wait=False, progress=None):
    if not math.isfinite(timeout) or timeout <= 0:
        raise ClientError('Decryption timeout must be positive and finite.')
    operation_id = operation_id or uuid.uuid4().hex
    args = {'operation_id': operation_id, 'path': path}
    VitaClient._command('decrypt.start', args)
    output = Path(output) if output is not None else Path(path.rsplit('/', 1)[-1].split(':')[-1]).with_suffix('.elf')
    if not no_wait and (output.exists() or output.is_symlink()):
        raise ClientError('Decryption output already exists; choose a new host output path.')
    if progress is not None:
        progress({'status': 'progress', 'result': {'phase': 'starting', 'operation_id': operation_id, 'source': path}})
    deadline = time.monotonic() + timeout
    reply = client.call('decrypt.start', args)
    while reply.get('status') == 'ok':
        result = reply.get('result', {})
        if result.get('operation_id') != operation_id or result.get('path') != path:
            raise ClientError('Native decryption job does not match the requested source/ID.')
        if progress is not None:
            progress({'status': 'progress', 'result': {'phase': 'decrypt', 'operation_id': operation_id, 'native': result}})
        if no_wait or not result.get('running'):
            break
        if time.monotonic() >= deadline:
            return {**reply, 'status': 'unconfirmed', 'message': 'Decryption continues on the Vita. Reuse this operation_id or query call decrypt.status.'}
        time.sleep(1)
        reply = client.call('decrypt.status', {'operation_id': operation_id})
    if reply.get('status') != 'ok' or no_wait:
        return reply
    result = reply['result']
    if result.get('state') == 'uncertain':
        return {**reply, 'status': 'unconfirmed', 'message': 'Native job was interrupted before completion was journaled; keep its operation_id and inspect its output/audit.'}
    if result.get('state') != 'complete' or result.get('native_result') != 0 or result.get('running') is not False:
        return {**reply, 'status': 'error', 'message': 'Native decryption failed; inspect phase and native_result.'}
    remote = 'ux0:data/vita-agent-use-decrypt/' + operation_id + '.elf'
    digest = result.get('sha256')
    size = result.get('bytes')
    if result.get('output_path') != remote or not isinstance(digest, str) or not re.fullmatch('[0-9a-f]{64}', digest) or not isinstance(size, str) or not re.fullmatch('[1-9][0-9]*', size) or not 52 <= int(size) <= 256 * 1024 * 1024:
        raise ClientError('Invalid native decrypted-file metadata.')
    download = client.download(remote, output, progress=progress)
    actual = hashlib.sha256()
    with output.open('rb') as stream:
        elf = stream.read(52)
        actual.update(elf)
        for block in iter(lambda: stream.read(65536), b''):
            actual.update(block)
    if len(elf) != 52 or not elf.startswith(b'\x7fELF\x01\x01\x01') or output.stat().st_size != int(size) or actual.hexdigest() != digest:
        output.unlink()
        raise ClientError('Decrypted ELF download failed size/magic/SHA256 verification; native output remains available with the same operation_id.')
    return {'status': 'ok', 'operation_id': operation_id, 'source': path, 'file': str(output), 'format': 'elf', 'bytes': download['bytes'], 'sha256': digest, 'verified': True, 'native_output_path': remote}
