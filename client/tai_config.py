# SPDX-License-Identifier: GPL-3.0-or-later
"""Review protected tai config changes and require exact native readback."""
import argparse
import base64
import ctypes
import difflib
import hashlib
import json
import os
import stat
from pathlib import Path
from upload import upload
from vita_client import VitaClient, ClientError, private_json, durable_json

MAX_BYTES = 16384
CONFIG_PATHS = {'ur0:tai/config.txt', 'ux0:tai/config.txt', 'uma0:tai/config.txt'}


def guard(before, after):
    if not isinstance(before, bytes) or not isinstance(after, bytes) or max(len(before), len(after)) > MAX_BYTES:
        raise ClientError('Config must be at most 16 KiB.')
    library = Path(__file__).resolve().parents[1] / 'agent/build-host/agent/tests/libtai_config_guard_host.so'
    try:
        native = ctypes.CDLL(str(library)).vau_tai_config_check
    except OSError:
        raise ClientError('Build the host tai config guard before editing config.') from None
    native.argtypes = [ctypes.c_void_p, ctypes.c_size_t, ctypes.c_void_p, ctypes.c_size_t, ctypes.c_int, ctypes.c_int]
    native.restype = ctypes.c_int
    # This checks syntax and protected plugin behavior. Recovery eligibility
    # is independently enforced on-device; no PC assertion can grant it.
    code = native(before, len(before), after, len(after), 0, 0)
    if code:
        raise ClientError('Config syntax or protected plugin behavior rejected (code %d).' % code)


def snapshot(client, path):
    if path not in CONFIG_PATHS:
        raise ClientError('Expected a canonical tai/config.txt path.')
    data, meta = client.file_chunk(path, 0, MAX_BYTES)
    if meta['file_bytes'] > MAX_BYTES or len(data) != meta['file_bytes']:
        raise ClientError('Config snapshot is incomplete or too large.')
    return data


def prepare(client, path, candidate, plan_path):
    before = snapshot(client, path)
    fd = os.open(candidate, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    with os.fdopen(fd, 'rb') as stream:
        if not stat.S_ISREG(os.fstat(stream.fileno()).st_mode):
            raise ClientError('Config candidate must be a regular file.')
        after = stream.read(MAX_BYTES + 1)
    guard(before, after)
    if before == after:
        raise ClientError('Config has no changes.')
    plan = {'v': 1, 'device': client.pin, 'path': path,
            'before_base64': base64.b64encode(before).decode('ascii'), 'after_base64': base64.b64encode(after).decode('ascii'),
            'before_sha256': hashlib.sha256(before).hexdigest(),
            'after_sha256': hashlib.sha256(after).hexdigest()}
    durable_json(Path(plan_path).absolute(), plan)
    return {'path': path, 'before_sha256': plan['before_sha256'], 'after_sha256': plan['after_sha256'],
            'diff': ''.join(difflib.unified_diff(before.decode('utf-8').splitlines(True),
                                               after.decode('utf-8').splitlines(True),
                                               fromfile=path + ' (before)', tofile=path + ' (after)')),
            'applied': False}


def apply(client, plan_path, transfer_state, yes=False):
    if yes is not True:
        raise ClientError('Config apply requires explicit --yes intent and a device ACL.')
    plan_path = Path(plan_path).absolute()
    plan = private_json(plan_path)
    fields = {'v','device','path','before_base64','after_base64','before_sha256','after_sha256'}
    if not isinstance(plan, dict) or set(plan) != fields or type(plan['v']) is not int or plan['v'] != 1 or plan['device'] != client.pin or plan['path'] not in CONFIG_PATHS:
        raise ClientError('Config plan does not match this device.')
    try:
        before, after = base64.b64decode(plan['before_base64'], validate=True), base64.b64decode(plan['after_base64'], validate=True)
    except (ValueError, TypeError):
        raise ClientError('Invalid config plan bytes.') from None
    guard(before, after)
    if hashlib.sha256(before).hexdigest() != plan['before_sha256'] or hashlib.sha256(after).hexdigest() != plan['after_sha256']:
        raise ClientError('Config plan digest mismatch.')
    current = snapshot(client, plan['path'])
    transfer_state = Path(transfer_state).absolute()
    if current != before:
        if current != after or not transfer_state.exists():
            raise ClientError('Config changed since review; prepare a new plan.')
        saved = private_json(transfer_state)
        expected = {'path':plan['path'], 'bytes':str(len(after)), 'sha256':plan['after_sha256'],
                    'overwrite':True, 'expected_sha256':plan['before_sha256'], 'yes':True}
        if not isinstance(saved, dict) or saved.get('device') != client.pin or saved.get('phase') not in ('commit','done') or not isinstance(saved.get('request'), dict) or {k:v for k,v in saved['request'].items() if k != 'operation_id'} != expected:
            raise ClientError('Config differs without a matching pending commit.')
    source = Path(str(plan_path) + '.candidate')
    try:
        fd = os.open(source, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    except FileExistsError:
        fd = os.open(source, os.O_RDONLY | os.O_NOFOLLOW)
        with os.fdopen(fd, 'rb') as stream:
            if stream.read(MAX_BYTES + 1) != after:
                raise ClientError('Saved candidate differs from the reviewed plan.')
    else:
        with os.fdopen(fd, 'wb') as stream:
            stream.write(after);stream.flush();os.fsync(stream.fileno())
    def readback():
        observed = snapshot(client, plan['path'])
        if observed != after:
            raise ClientError('Config readback mismatch; completion remains unacknowledged. Retain plan and transfer state.')
        guard(before, observed)
        result = {'path':plan['path'], 'verified':True, 'sha256':hashlib.sha256(observed).hexdigest(),
                  'bytes':str(len(observed)), 'text':observed.decode('utf-8')}
        durable_json(Path(str(plan_path) + '.readback.json'), result)
        return result
    return upload(client, source, plan['path'], transfer_state, True,
                  plan['before_sha256'], True, config_readback=readback)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--credentials', type=Path, required=True)
    parser.add_argument('--state', type=Path, required=True)
    sub = parser.add_subparsers(dest='action', required=True)
    review = sub.add_parser('plan')
    review.add_argument('path', choices=sorted(CONFIG_PATHS));review.add_argument('candidate', type=Path)
    review.add_argument('--plan', type=Path, required=True)
    commit = sub.add_parser('apply');commit.add_argument('--plan', type=Path, required=True)
    commit.add_argument('--transfer-state', type=Path, required=True);commit.add_argument('--yes', action='store_true')
    args = parser.parse_args();client = VitaClient(private_json(args.credentials), args.state)
    try:
        result = prepare(client, args.path, args.candidate, args.plan) if args.action == 'plan' else apply(client, args.plan, args.transfer_state, args.yes)
        print(json.dumps(result, ensure_ascii=False))
    finally:client.close()


if __name__ == '__main__':main()
