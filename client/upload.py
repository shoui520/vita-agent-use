# SPDX-License-Identifier: GPL-3.0-or-later
"""Resumable sequential binary upload through the native write coordinator."""
import argparse
import fcntl
import hashlib
import json
import os
import re
from pathlib import Path
import stat
import time
import uuid
from vita_client import VitaClient, ClientError, UploadError, private_json, durable_json


def checked(result, allow_readback=False):
    if result['code']:
        raise ClientError('Vita upload returned %d; retain the transfer state and operation ID.' % result['code'])
    if result['readback_required'] and not allow_readback:
        raise ClientError('Config readback is required; this ordinary-file workflow cannot acknowledge it.')
    return result


def upload(client, source, destination, transfer_state, overwrite=False, expected_sha256='', yes=False, *, config_readback=None, progress=None):
    VitaClient._command('fs.mkdir', {'operation_id':'0'*32,'path':destination,'yes':yes})
    if type(overwrite) is not bool or not isinstance(expected_sha256, str) or not re.fullmatch('(?:[0-9a-f]{64})?' if overwrite else '', expected_sha256):
        raise ClientError('Invalid optional original SHA256.')
    if overwrite and not yes:raise ClientError('Overwrite requires --yes.')
    is_config = destination.lower() in ('ur0:tai/config.txt', 'ux0:tai/config.txt', 'uma0:tai/config.txt')
    if is_config and overwrite and not expected_sha256:
        raise ClientError('Guarded config overwrite requires the original SHA256.')
    if is_config and config_readback is None:
        raise ClientError('Use the guarded config workflow for tai/config.txt.')
    if config_readback is not None and not is_config:
        raise ClientError('Config readback callback is only valid for tai/config.txt.')
    def check(result):return checked(result, allow_readback=config_readback is not None)
    def complete(result):
        if config_readback is not None:
            if not result['readback_required']:raise ClientError('Vita did not require config readback.')
            info['phase']='readback';report(force=True)
            return {**result, 'readback': config_readback()}
        return result
    source = Path(source).absolute()
    transfer_state = Path(transfer_state).absolute()
    info={'type':'upload','path':destination,'transfer_state':str(transfer_state),
          'phase':'prepare','action':None,'received':None,'bytes':None,'operation_id':None}
    last_report=0
    def report(force=False):
        nonlocal last_report
        now=time.monotonic()
        if progress is not None and (force or now-last_report>=1):
            progress({'status':'progress','result':dict(info)});last_report=now
    def step(request, action, offset=0, data=b''):
        phase='transfer' if action in ('begin','chunk') else action
        changed=info['phase']!=phase
        info.update(phase=phase,action=action)
        if changed:report(force=True)
        started=time.monotonic()
        result=client.upload_step(request,action,offset,data)
        info['last_step_ms']=round((time.monotonic()-started)*1000,3)
        if 'timings_us' in result:info['last_step_native_us']=dict(result['timings_us'])
        if result['code']==0:info['received']=result['received']
        report()
        return result
    lock_fd = os.open(str(transfer_state) + '.lock', os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW, 0o600)
    try:
        lock_info = os.fstat(lock_fd)
        if not stat.S_ISREG(lock_info.st_mode) or lock_info.st_uid != os.getuid() or lock_info.st_mode & 0o077:
            raise ClientError('Transfer lock must be a private user-owned regular file.')
        fcntl.flock(lock_fd, fcntl.LOCK_EX)
        fd = os.open(source, os.O_RDONLY | os.O_NOFOLLOW)
        with os.fdopen(fd, 'rb') as stream:
            before = os.fstat(stream.fileno())
            if not stat.S_ISREG(before.st_mode):raise ClientError('Upload source must be a regular file.')
            info['bytes']=str(before.st_size);info['phase']='hash';report(force=True)
            digest = hashlib.sha256()
            while block := stream.read(65536):
                digest.update(block);report()
            signature = (before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns, before.st_ctime_ns)
            def unchanged():
                now = os.fstat(stream.fileno())
                if (now.st_dev, now.st_ino, now.st_size, now.st_mtime_ns, now.st_ctime_ns) != signature:
                    raise ClientError('Upload source changed; commit was withheld.')
            unchanged()
            base = {'path': destination, 'bytes': str(before.st_size), 'sha256': digest.hexdigest(),
                    'overwrite': overwrite, 'expected_sha256': expected_sha256, 'yes': yes}
            if transfer_state.exists():
                saved = private_json(transfer_state)
                if not isinstance(saved, dict) or set(saved) != {'v', 'source', 'device', 'request', 'phase'} or type(saved['v']) is not int or saved['v'] != 1 or saved['source'] != str(source) or saved['device'] != client.pin or not isinstance(saved['request'], dict) or saved['phase'] not in ('transfer', 'commit', 'done') or {k: v for k, v in saved['request'].items() if k != 'operation_id'} != base:
                    raise ClientError('Transfer state does not match this source, device and operation.')
            else:
                saved = {'v': 1, 'source': str(source), 'device': client.pin,
                         'request': {**base, 'operation_id': uuid.uuid4().hex}, 'phase': 'transfer'}
                durable_json(transfer_state, saved)
            request = saved['request']
            info.update(operation_id=request['operation_id'],phase=saved['phase']);report(force=True)
            if saved['phase'] in ('commit', 'done'):
                # Query the bound completion first after a lost commit reply.
                result = step(request, 'recover')
                if result['code'] == 0 and result['complete']:
                    check(result);result = complete(result);saved['phase'] = 'done';durable_json(transfer_state, saved)
                    return result
                if result['code'] != -5: # STALE can also mean no commit INTENT existed.
                    check(result)
                if result['complete']:
                    check(result) # A recovered original is a failed operation, never a new upload.
                # No commit intent was recorded: verify/commit the staged bytes
                # with the same operation identity; never generate another ID.
                unchanged();verified = check(step(request, 'verify'))
                if not verified['verified']:raise ClientError('Vita did not verify the upload.')
            else:
                result = check(step(request, 'begin'))
                if result['complete']:
                    result = complete(result);saved['phase'] = 'done';durable_json(transfer_state, saved);return result
                chunk_bytes=client.upload_chunk_size() if hasattr(client,'upload_chunk_size') else 12288
                if type(chunk_bytes) is not int or not 1<=chunk_bytes<=122880:raise ClientError('Invalid upload chunk limit.')
                offset = int(result['received']);stream.seek(offset)
                while offset < before.st_size:
                    unchanged();block = stream.read(min(chunk_bytes, before.st_size-offset))
                    if not block:raise ClientError('Upload source truncated; commit was withheld.')
                    result = check(step(request, 'chunk', offset, block))
                    next_offset = int(result['received'])
                    if next_offset != offset + len(block):raise ClientError('Unexpected upload offset; resume from the saved operation.')
                    offset = next_offset
                unchanged();result = check(step(request, 'verify'))
                if not result['verified']:raise ClientError('Vita did not verify the upload.')
                saved['phase'] = 'commit';durable_json(transfer_state, saved)
            unchanged();result = check(step(request, 'commit'))
            if not result['complete']:raise ClientError('Vita has not confirmed durable upload completion.')
            result = complete(result)
            saved['phase'] = 'done';durable_json(transfer_state, saved)
            return result
    except (ClientError,OSError) as exc:
        if info['operation_id'] is None:raise
        raise UploadError(str(exc),info) from exc
    finally:
        os.close(lock_fd)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--credentials', type=Path, required=True)
    parser.add_argument('--state', type=Path, required=True)
    parser.add_argument('--transfer-state', type=Path, required=True)
    parser.add_argument('--overwrite', action='store_true')
    parser.add_argument('--expected-sha256', default='', help='Optional original-content precondition for ordinary overwrites.')
    parser.add_argument('--yes', action='store_true')
    parser.add_argument('source', type=Path)
    parser.add_argument('destination')
    args = parser.parse_args()
    client = VitaClient(private_json(args.credentials), args.state)
    try:
        print(json.dumps(upload(client, args.source, args.destination, args.transfer_state,
                                args.overwrite, args.expected_sha256, args.yes)))
    finally:
        client.close()


if __name__ == '__main__':main()
