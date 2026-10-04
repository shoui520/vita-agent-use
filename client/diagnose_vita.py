# SPDX-License-Identifier: GPL-3.0-or-later
"""Read startup/stop diagnostics once; never retry or perform control/file operations."""
import argparse
import json
import socket
from vita_client import strict_json

PHASES = ('starting', 'input bridge', 'identity files', 'notification worker',
          'pairing listening', 'pairing start', 'pairing rejected',
          'native pairing accepted', 'commands listening',
          'service returning to pairing', 'crypto worker stopped', 'network cleanup stopped', 'trusted session accepted', 'trusted session rejected', 'saved peer invalid')


def decode(data):
    if not 0 < len(data) < 256:
        raise ValueError('Invalid diagnostic response length.')
    result = strict_json(data)
    required = {'v', 'phase', 'result', 'log_result', 'stop_query', 'stop'}
    if not isinstance(result, dict) or set(result) != required or type(result['v']) is not int or result['v'] != 1:
        raise ValueError('Invalid diagnostic response fields.')
    if type(result['phase']) is not int or not 0 <= result['phase'] < 2**32:
        raise ValueError('Invalid diagnostic phase.')
    stop = result['stop']
    if not isinstance(stop, dict) or set(stop) != {'size', 'abi', 'ready', 'held', 'stopped', 'error'}:
        raise ValueError('Invalid stop diagnostic fields.')
    for key in ('result', 'log_result', 'stop_query'):
        if type(result[key]) is not int or not -(2**31) <= result[key] < 2**31:
            raise ValueError('Invalid native diagnostic result.')
    if type(stop['error']) is not int or not -(2**31) <= stop['error'] < 2**31:
        raise ValueError('Invalid stop result.')
    for key in ('size', 'abi'):
        if type(stop[key]) is not int or not 0 <= stop[key] < 2**32:
            raise ValueError('Invalid stop ABI fields.')
    for key in ('ready', 'held', 'stopped'):
        if type(stop[key]) is not int or stop[key] not in (0, 1):
            raise ValueError('Invalid stop state.')
    phase = result['phase']
    result['phase_name'] = PHASES[phase] if phase < len(PHASES) else 'unknown'
    for key in ('result', 'log_result', 'stop_query'):
        if result[key] < 0:
            result[key + '_hex'] = '0x%08X' % (result[key] & 0xffffffff)
    if stop['error'] < 0:
        stop['error_hex'] = '0x%08X' % (stop['error'] & 0xffffffff)
    return result


INPUT_REASONS = ('healthy', 'native_call_failed', 'unexpected_sample_count',
                 'stop_buttons_masked', 'zero_timestamp', 'timestamp_regressed',
                 'clock_regressed', 'timestamp_frozen')


def decode_input(data):
    if not 0 < len(data) < 512:
        raise ValueError('Invalid input diagnostic length.')
    result = strict_json(data)
    fields = {'v', 'query', 'size', 'abi', 'stamp', 'previous_stamp', 'observed_us',
              'changed_us', 'result', 'error', 'mask', 'buttons', 'reason', 'sampled'}
    if not isinstance(result, dict) or set(result) != fields:
        raise ValueError('Invalid input diagnostic fields.')
    for key, value in result.items():
        if type(value) is not int:
            raise ValueError('Invalid input diagnostic number.')
        if key in ('query', 'result', 'error'):
            valid = -(2**31) <= value < 2**31
        elif key in ('stamp', 'previous_stamp', 'observed_us', 'changed_us'):
            valid = 0 <= value < 2**64
        else:
            valid = 0 <= value < 2**32
        if not valid:
            raise ValueError('Input diagnostic number out of range.')
    if result['v'] != 1 or result['sampled'] not in (0, 1):
        raise ValueError('Invalid input diagnostic version/state.')
    reason = result['reason']
    result['reason_name'] = INPUT_REASONS[reason] if reason < len(INPUT_REASONS) else 'unknown'
    return result


def decode_log(data):
    if not 0 < len(data) < 128:
        raise ValueError('Invalid log diagnostic length.')
    result = strict_json(data)
    if not isinstance(result, dict) or set(result) != {'v', 'open', 'write', 'close'}:
        raise ValueError('Invalid log diagnostic fields.')
    if type(result['v']) is not int or result['v'] != 1:
        raise ValueError('Invalid log diagnostic version.')
    for key in ('open', 'write', 'close'):
        if type(result[key]) is not int or not -(2**31) <= result[key] < 2**31:
            raise ValueError('Invalid log native result.')
        if result[key] < 0:
            result[key + '_hex'] = '0x%08X' % (result[key] & 0xffffffff)
    return result


def query(host, timeout=3, input_sample=False, logging=False):
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
        sock.settimeout(timeout)
        sock.connect((host, 8846))
        sock.send(b'log\n' if logging else b'input\n' if input_sample else b'status\n')
        return (decode_log if logging else decode_input if input_sample else decode)(sock.recv(1024))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--host', required=True)
    mode = parser.add_mutually_exclusive_group()
    mode.add_argument('--logging', action='store_true', help='Read native log open/write/close results.')
    mode.add_argument('--input-sample', action='store_true', help='Read raw controller evidence instead of startup status.')
    args = parser.parse_args()
    try:
        result = query(args.host, input_sample=args.input_sample, logging=args.logging)
    except ConnectionRefusedError:
        result = {'status': 'unreachable', 'error': 'connection_refused'}
    except TimeoutError:
        result = {'status': 'unreachable', 'error': 'timeout'}
    except OSError:
        result = {'status': 'unreachable', 'error': 'network_error'}
    except (ValueError, UnicodeError):
        result = {'status': 'invalid_response', 'error': 'malformed_diagnostics'}
    print(json.dumps(result, indent=2))
    return int(result.get('status') in ('unreachable', 'invalid_response'))


if __name__ == '__main__':
    raise SystemExit(main())
