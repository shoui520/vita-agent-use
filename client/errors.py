# SPDX-License-Identifier: GPL-3.0-or-later
"""Plain explanations for native error codes, so a refusal says why and what to do."""

NAMES = {-1: 'invalid', -2: 'busy', -3: 'expired', -4: 'denied', -5: 'stale', -6: 'unsupported',
         -7: 'device_error', -8: 'late', -9: 'recovery_required'}
GENERAL = {
    -1: 'The Vita rejected the arguments.',
    -2: 'The Vita is busy with other work (an install, content job, decrypt, input or an approval prompt). Try again once it finishes.',
    -3: 'The session or lease expired. Commands renew the session by themselves; repeat the command.',
    -4: 'The Vita refused the request.',
    -5: 'The state changed since it was read (a newer request, a different foreground app or a changed file). Read it again and retry.',
    -6: 'The plugin installed on the Vita does not support this. Update the plugin.',
    -7: 'A system call failed on the Vita.',
    -8: 'The input ran later than max_lateness_us allowed, so it was stopped instead of shifting the timing.',
    -9: 'Interrupted earlier work has to be recovered first. Repeat the original command with the same IDs and state files.',
}
INPUT_DENIED = ('Input refused: another controller holds input, the agent was stopped with PS+SELECT '
                '(the user must allow it again), or the system has the buttons right now (screen off or a system dialog).')
READ_ONLY = ('os0', 'pd0', 'sa0', 'tm0', 'ud0', 'vd0', 'vs0')
CORE_PLUGINS = ('henkaku', 'yamt', 'yamt_helper', 'storagemgr')


def path_reason(path, write=True):
    """The policy rule that most likely refused PATH, with the next step."""
    p = str(path).replace('\\', '/').lower()
    mount, _, rest = p.partition(':')
    rest = rest.strip('/')
    base = rest.rsplit('/', 1)[-1]
    if mount in READ_ONLY and write:
        return '%s: is always read-only.' % mount
    if mount == 'ur0' and (rest == 'data/vita-agent-use' or rest.startswith('data/vita-agent-use/')):
        return ("This is the plugin's private storage (identity, approvals, journals). Only "
                'ur0:data/vita-agent-use/runtime.log and loader.log can be read.')
    if rest.startswith('data/vita-agent-use/') and mount == 'ux0':
        return "This is the plugin's journal and trash storage; use the fs trash/purge commands instead."
    if write and base.rsplit('.', 1)[0] in CORE_PLUGINS and base.endswith(('.suprx', '.skprx')):
        return 'Core plugins (henkaku, yamt, storagemgr) can never be changed, moved or deleted.'
    if rest == 'tai' or (rest.startswith('tai/') and mount in ('ur0', 'ux0', 'uma0')):
        if base == 'config.txt' and write:
            return 'tai/config.txt changes only through `config plan` then `config apply`.'
        if rest == 'tai':
            return 'The tai folder itself can never be changed.'
        return ('Guarded path: run `acl request %s`, have the user approve it on the Vita, then repeat with --yes. '
                'Only the active tai folder is allowed.' % path)
    if mount == 'ur0' and (rest == 'shell' or rest.startswith('shell/')):
        return 'Guarded path: run `acl request %s`, have the user approve it on the Vita, then repeat with --yes.' % path
    return 'An ACL deny rule, or a path that needs an ACL. Check `acl audit`, or run `acl request %s`.' % path


def describe(code, op=None, path=None, write=True):
    """Return (name, message) for a native code in the context of OP."""
    if type(code) is not int:
        return 'unknown', 'The Vita returned an error without a code.'
    if code < -9 or code > 0:
        unsigned = code & 0xffffffff
        return 'system_error', 'System error 0x%08X from the Vita firmware.' % unsigned
    name = NAMES.get(code, 'unknown')
    if code == -4 and op and op.split('.')[0] in ('input', 'macro', 'touch'):
        return name, INPUT_DENIED
    if code == -4 and path:
        return name, 'Denied by file policy. ' + path_reason(path, write)
    return name, GENERAL.get(code, 'The Vita returned error %d.' % code)


def annotate(op, args, reply):
    """Add name and message to a native error reply in place, keeping its code."""
    if not isinstance(reply, dict) or reply.get('status') != 'error':
        return reply
    error = reply.get('error')
    result = reply.get('result')
    if error is None and isinstance(result, dict) and type(result.get('code')) is int:
        # File mutations report their native code inside result.
        error = reply['error'] = {'source': 'native', 'code': result['code']}
    if not isinstance(error, dict) or 'message' in error:
        return reply
    path = args.get('path') if isinstance(args, dict) else None
    name, message = describe(error.get('code'), op, path, write=op not in ('fs.stat', 'fs.list'))
    error.setdefault('name', name)
    error['message'] = message
    return reply
