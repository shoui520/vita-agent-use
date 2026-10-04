# SPDX-License-Identifier: GPL-3.0-or-later
"""Per-title authored macros compiled to Vita's bounded native input timeline.

This module does not execute JavaScript or time individual inputs over a network.
Compiled submissions still require a live process-bound lease on the Vita.
Cycles can last one hour, with up to 1024 coalesced states and native loops.
"""
from __future__ import annotations
import argparse
import json
import os
from pathlib import Path
import re
import stat

from vita_client import ClientError, VitaClient, durable_json, private_json, strict_json

BUTTONS = {
    'select': 0x0001, 'start': 0x0008,
    'up': 0x0010, 'right': 0x0020, 'down': 0x0040, 'left': 0x0080,
    'l': 0x0100, 'r': 0x0200,
    'triangle': 0x1000, 'circle': 0x2000, 'cross': 0x4000, 'square': 0x8000,
}
MACRO_FILE_BYTES=16*1024*1024
MACRO_STEPS=65536
MACRO_CYCLE_US=7*24*3600*1000000

def compile_segments(macro, *, max_lateness_us=100000):
    """Validate a long saved macro into bounded native continuation segments.

    Only two native segments are resident at once. Long holds are split at an
    hour without releasing the held state; segment boundaries use device time.
    """
    if not isinstance(macro,dict) or set(macro)!={'v','name','title_id','steps'} or not isinstance(macro['steps'],list) or not 1<=len(macro['steps'])<=MACRO_STEPS:
        raise ClientError('Saved macro requires v, name, title_id and 1..65536 steps.')
    # Reuse the same strict identity and held-state validation as ordinary input.
    header={key:value for key,value in macro.items() if key!='steps'}
    compile_macro({**header,'steps':[{'duration_us':1,'buttons':[]}]},start_us='0',max_lateness_us=max_lateness_us)
    enabled=0;has_touch=False
    for step in macro['steps']:
        if isinstance(step,dict) and 'touch' in step:
            has_touch=True;touch=step['touch']
            if not isinstance(touch,list) or len(touch)!=3 or type(touch[0]) is not int or not 0<=touch[0]<=3:
                raise ClientError('Touch state is [enabled, front_contacts, back_contacts].')
            enabled|=touch[0]
    held=[];total=0;previous=None
    for step in macro['steps']:
        if not isinstance(step,dict) or type(step.get('duration_us')) is not int or not 1<=step['duration_us']<=MACRO_CYCLE_US:
            raise ClientError('Saved macro holds must be positive and fit a seven-day cycle.')
        total+=step['duration_us']
        if total>MACRO_CYCLE_US:raise ClientError('Saved macro cycle exceeds seven days.')
        item={**step,'duration_us':min(step['duration_us'],3600000000)}
        if has_touch and 'touch' not in item:item['touch']=[enabled,[],[]]
        checked=compile_macro({**header,'steps':[item]},start_us='0',max_lateness_us=max_lateness_us)
        state=(checked['events'][0][1:],checked.get('touch'))
        if state==previous:held[-1]['duration_us']+=step['duration_us']
        else:held.append({**item,'duration_us':step['duration_us']})
        previous=state
    expanded=[]
    for step in held:
        count=(step['duration_us']+3599999999)//3600000000
        remaining=step['duration_us']
        for i in range(count):
            part=(remaining+count-i-1)//(count-i)
            expanded.append({**step,'duration_us':part});remaining-=part
    segments=[];steps=[];duration=0
    # Balance event counts so a 1025-state cycle does not end in an unprefetchable
    # single-state tail at its repeat boundary.
    parts=(len(expanded)+1023)//1024;target=(len(expanded)+parts-1)//parts
    def append(part):
        try:segments.append(compile_macro({**header,'steps':part},start_us='0',max_lateness_us=max_lateness_us))
        except ClientError as exc:
            if len(part)<2 or not str(exc).startswith('Compiled macro exceeds'):raise
            mid=len(part)//2;append(part[:mid]);append(part[mid:])
    def flush():
        nonlocal steps,duration
        if steps:append(steps);steps=[];duration=0
    for step in expanded:
        remaining=step['duration_us']
        while remaining:
            if len(steps)==target or duration==3600000000:flush()
            part=min(remaining,3600000000-duration)
            steps.append({**step,'duration_us':part});duration+=part;remaining-=part
    flush()
    return segments


def compile_macro(macro, *, start_us, repeats=1, max_lateness_us=100000):
    """Convert full held states to input.submit args; never send a command.

    Each step holds its button/analog/touch state for duration_us. Absent analog
    axes center both sticks. If any step uses touch, absent touch in other steps
    releases the same panels instead of accidentally retaining a contact.
    """
    if not isinstance(macro, dict) or set(macro) != {'v', 'name', 'title_id', 'steps'}:
        raise ClientError('Macro requires v, name, title_id and steps.')
    if type(macro['v']) is not int or macro['v'] != 1:
        raise ClientError('Unsupported macro version.')
    if not isinstance(macro['name'], str) or not re.fullmatch('[a-zA-Z0-9][a-zA-Z0-9_-]{0,63}', macro['name']):
        raise ClientError('Macro name must be a simple name of at most 64 characters.')
    if not isinstance(macro['title_id'], str) or not re.fullmatch('[A-Z0-9]{9}', macro['title_id']):
        raise ClientError('Macro requires a nine-character title_id.')
    steps = macro['steps']
    if not isinstance(steps, list) or not 1 <= len(steps) <= 1024:
        raise ClientError('Macro requires between 1 and 1024 held-state steps.')
    # Determine which panels to release in steps that omit touch. All touch
    # payload details are also checked by the shared command validator below.
    enabled = 0
    for step in steps:
        if not isinstance(step, dict) or set(step) - {'duration_us', 'buttons', 'axes', 'touch'} or not {'duration_us', 'buttons'} <= set(step):
            raise ClientError('Each step requires duration_us and buttons; axes/touch are optional.')
        if 'touch' in step:
            touch = step['touch']
            if not isinstance(touch, list) or len(touch) != 3 or type(touch[0]) is not int or not 0 <= touch[0] <= 3:
                raise ClientError('Touch state is [enabled, front_contacts, back_contacts].')
            enabled |= touch[0]
    events, touches = [], []
    elapsed = 0
    previous = None
    for step in steps:
        duration = step['duration_us']
        if type(duration) is not int or not 1 <= duration <= 3600000000 or elapsed + duration > 3600000000:
            raise ClientError('Macro cycle must be between 1 us and one hour.')
        buttons = step['buttons']
        if not isinstance(buttons, list) or any(not isinstance(b, str) or b not in BUTTONS for b in buttons) or len(set(buttons)) != len(buttons):
            raise ClientError('Buttons must be unique names from the supported controller buttons.')
        mask = 0
        for button in buttons:
            mask |= BUTTONS[button]
        axes = step.get('axes', [128, 128, 128, 128])
        if not isinstance(axes, list) or len(axes) != 4 or any(type(v) is not int or not 0 <= v <= 255 for v in axes):
            raise ClientError('Axes must be [lx, ly, rx, ry], each from 0 to 255.')
        touch = step.get('touch', [enabled, [], []])
        # Validate even a step whose state is later coalesced. Copy validation
        # also prevents callers mutating the macro after compilation.
        check = {'start_us': '0', 'duration_us': duration, 'repeats': 1,
                 'max_lateness_us': 1, 'events': [[0, mask, *axes]]}
        if enabled or any('touch' in s for s in steps):
            check['touch'] = [touch]
        checked = VitaClient._command('input.submit', check)['args']
        state = (checked['events'][0][1:], checked.get('touch', [None])[0])
        if state != previous:
            events.append([elapsed, *state[0]])
            if 'touch' in checked:
                touches.append(state[1])
            previous = state
        elapsed += duration
    args = {'start_us': start_us, 'duration_us': elapsed, 'repeats': repeats,
            'max_lateness_us': max_lateness_us, 'events': events}
    if touches:
        args['touch'] = touches
    args = VitaClient._command('input.submit', args)['args']
    envelope = {'v': 1, 'id': str(2**64-1), 'op': 'input.submit', 'args': args}
    if len(json.dumps(envelope, separators=(',', ':')).encode()) > 131072:
        raise ClientError('Compiled macro exceeds the native request limit; split it at an observation checkpoint.')
    return args


def macro_from_sequence(name, title_id, args):
    """Save an authored/submitted timeline as reusable held states.

    This is a record of commanded inputs, not proof of game sampling, and not
    physical-controller recording. Device timestamps and repeat count are not
    baked into the reusable cycle.
    """
    checked = VitaClient._command('input.submit', args)['args']
    events = checked['events']
    steps = []
    for i, event in enumerate(events):
        end = events[i+1][0] if i+1 < len(events) else checked['duration_us']
        step = {'duration_us': end-event[0], 'buttons': [name for name, mask in BUTTONS.items() if event[1] & mask]}
        if event[2:] != [128]*4:
            step['axes'] = event[2:]
        if 'touch' in checked:
            step['touch'] = checked['touch'][i]
        steps.append(step)
    macro = {'v': 1, 'name': name, 'title_id': title_id, 'steps': steps}
    compile_macro(macro, start_us='0')
    return macro


class MacroStore:
    """Private host storage, scoped by native title ID and macro name."""
    def __init__(self, root):
        self.root = Path(root)
        self._directory(self.root)

    @staticmethod
    def _directory(path):
        path.mkdir(mode=0o700, parents=True, exist_ok=True)
        info = path.lstat()
        if not stat.S_ISDIR(info.st_mode) or info.st_mode & 0o077 or info.st_uid != os.getuid():
            raise ClientError('Macro directory must be private and owned by this user.')

    def save(self, macro):
        compile_segments(macro)
        folder = self.root / macro['title_id']
        self._directory(folder)
        path = folder / (macro['name'] + '.json')
        durable_json(path, macro, max_bytes=MACRO_FILE_BYTES)
        return path

    def load(self, title_id, name):
        # Validate keys before constructing a filesystem path.
        compile_macro({'v': 1, 'name': name, 'title_id': title_id,
                       'steps': [{'duration_us': 1, 'buttons': []}]}, start_us='0')
        folder = self.root / title_id
        self._directory(folder)
        macro = private_json(folder / (name + '.json'), max_bytes=MACRO_FILE_BYTES)
        compile_segments(macro)
        if macro['title_id'] != title_id or macro['name'] != name:
            raise ClientError('Stored macro identity does not match the requested title/name.')
        return macro


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--store', type=Path, required=True)
    sub = parser.add_subparsers(dest='action', required=True)
    save = sub.add_parser('save'); save.add_argument('input', type=Path)
    load = sub.add_parser('load'); load.add_argument('title_id'); load.add_argument('name')
    compile_cmd = sub.add_parser('compile'); compile_cmd.add_argument('title_id'); compile_cmd.add_argument('name')
    compile_cmd.add_argument('--start-us', required=True); compile_cmd.add_argument('--repeats', type=int, default=1)
    compile_cmd.add_argument('--max-lateness-us', type=int, default=100000)
    args = parser.parse_args()
    try:
        store = MacroStore(args.store)
        if args.action == 'save':
            data = args.input.read_bytes()
            if len(data) > MACRO_FILE_BYTES:
                raise ClientError('Macro file exceeds its size limit.')
            macro = strict_json(data)
            result = {'status': 'ok', 'file': str(store.save(macro))}
        else:
            macro = store.load(args.title_id, args.name)
            if args.action=='load':result=macro
            else:
                segments=compile_segments(macro,max_lateness_us=args.max_lateness_us)
                checked=VitaClient._command('input.submit',{**segments[0],'start_us':args.start_us,'repeats':args.repeats})['args']
                if len(segments)==1:result={'acquire':{'op':'macro.acquire','args':{'title_id':macro['title_id']}},'op':'input.submit','args':checked}
                else:result={'status':'ok','result':{'title_id':macro['title_id'],'name':macro['name'],'segments':segments,'repeats':args.repeats,'execute_with':'macro.run','resident_segments':2}}
        print(json.dumps(result, separators=(',', ':')))
        return 0
    except (ClientError, OSError, ValueError, TypeError) as error:
        print(json.dumps({'status': 'client_error', 'message': str(error) if isinstance(error, ClientError) else 'Invalid local macro file.'}))
        return 1


if __name__ == '__main__':
    raise SystemExit(main())
