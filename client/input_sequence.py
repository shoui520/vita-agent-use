# SPDX-License-Identifier: GPL-3.0-or-later
"""Validate readable timed state changes without silently changing semantics."""
from copy import deepcopy
BUTTONS = {'SELECT', 'START', 'UP', 'RIGHT', 'DOWN', 'LEFT', 'L', 'R',
           'TRIANGLE', 'CIRCLE', 'CROSS', 'SQUARE'}
CHANNELS = {'buttons', 'left_stick', 'right_stick', 'front', 'back'}


def validate(events, duration):
    if not isinstance(events, list) or not events:
        raise ValueError('Input events must be a nonempty list.')
    previous = -1
    grouped = set()
    states = 0
    for event in events:
        if not isinstance(event, dict) or set(event) - (CHANNELS | {'at_us'}) or 'at_us' not in event or len(event) == 1:
            raise ValueError('Readable events need at_us and at least one input channel.')
        at = event['at_us']
        if type(at) is not int or not 0 <= at < duration or at < previous or (previous == -1 and at != 0):
            raise ValueError('Events start at zero and use nondecreasing microsecond timestamps.')
        channels = set(event) - {'at_us'}
        if at == previous:
            if channels & grouped:
                raise ValueError('Same-timestamp events cannot both change the same channel.')
            grouped |= channels
        else:
            states += 1
            grouped = channels
        if states > 1024:
            raise ValueError('Input sequences support at most 1024 distinct timed states.')
        previous = at
        if 'buttons' in event:
            buttons = event['buttons']
            if not isinstance(buttons, list) or any(not isinstance(b, str) or b not in BUTTONS for b in buttons) or len(set(buttons)) != len(buttons):
                raise ValueError('Buttons must be a list of unique supported names.')
        for key in ('left_stick', 'right_stick'):
            if key in event and (not isinstance(event[key], list) or len(event[key]) != 2 or any(type(v) is not int or not 0 <= v <= 255 for v in event[key])):
                raise ValueError('Stick state is [x,y], each 0..255; neutral is [128,128].')
        for key, maximum in (('front', 6), ('back', 4)):
            if key not in event:
                continue
            contacts = event[key]
            if not isinstance(contacts, list) or len(contacts) > maximum:
                raise ValueError('Too many touch contacts for ' + key + '.')
            ids = set()
            for contact in contacts:
                if not isinstance(contact, dict) or not {'id', 'x', 'y'} <= set(contact) or set(contact) - {'id', 'x', 'y', 'force'}:
                    raise ValueError('Touch contacts require id, x, y and optional force (default 128).')
                for field, limit in (('id', 127), ('x', 32767), ('y', 32767), ('force', 255)):
                    value = contact.get(field, 128)
                    if type(value) is not int or not 0 <= value <= limit:
                        raise ValueError('Invalid touch ' + field + '.')
                if contact['id'] in ids:
                    raise ValueError('Duplicate finger id within a panel.')
                ids.add(contact['id'])
    return deepcopy(events)
