# SPDX-License-Identifier: GPL-3.0-or-later
"""Validate readable timed state changes, merging events that share a timestamp."""
from copy import deepcopy
BUTTONS = {'SELECT', 'START', 'UP', 'RIGHT', 'DOWN', 'LEFT', 'L', 'R',
           'TRIANGLE', 'CIRCLE', 'CROSS', 'SQUARE'}
CHANNELS = {'buttons', 'left_stick', 'right_stick', 'front', 'back'}


def validate(events, duration):
    if not isinstance(events, list) or not events:
        raise ValueError('Input events must be a nonempty list.')
    previous = -1
    for event in events:
        if not isinstance(event, dict) or set(event) - (CHANNELS | {'at_us'}) or 'at_us' not in event:
            raise ValueError('Readable events need at_us plus any of: ' + ', '.join(sorted(CHANNELS)) + '.')
        at = event['at_us']
        if type(at) is not int or not 0 <= at < duration:
            raise ValueError('at_us must be a microsecond offset from 0 to below duration_us (%d).' % duration)
        if at < previous:
            raise ValueError('at_us must not decrease: %d comes after %d.' % (at, previous))
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
    return merge(deepcopy(events))


def merge(events):
    """One state per timestamp: events at the same at_us combine, events naming
    no channel are dropped, and a sequence that starts after 0 begins from the
    neutral state the pad already has. Two different values for one channel at
    the same moment would hide one of them (a press and release at once is no
    tap), so that is refused."""
    merged = []
    for event in events:
        if len(event) == 1:
            continue
        if merged and merged[-1]['at_us'] == event['at_us']:
            for key in set(event) & set(merged[-1]) - {'at_us'}:
                if merged[-1][key] != event[key]:
                    raise ValueError('%s is set to %s and %s at the same at_us %d, so one would never happen. '
                                     'Put the second change at a later at_us (a tap needs its release about 50000 us after the press).'
                                     % (key, merged[-1][key], event[key], event['at_us']))
            merged[-1].update(event)
        else:
            merged.append(event)
    if not merged or merged[0]['at_us'] != 0:
        merged.insert(0, {'at_us': 0, 'buttons': []})
    if len(merged) > 1024:
        raise ValueError('Input sequences support at most 1024 distinct timed states; this one has %d.' % len(merged))
    return merged
