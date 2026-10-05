# SPDX-License-Identifier: GPL-3.0-or-later
"""Human terminal setup; the Vita is inspected using read-only FTP operations."""
from __future__ import annotations
import contextlib
import curses
import ftplib
import io
import ipaddress
import os
import shlex
from pathlib import Path
import subprocess
import textwrap
from vita_client import ClientError, durable_json, validate_agent_name

AGENT_NAMES = ('Codex', 'Claude', 'Gemini', 'Grok', 'Muse', 'DeepSeek', 'Qwen',
               'Kimi', 'GLM', 'MiMo', 'Custom')
PLUGIN_PATTERNS = ('vitacompanion', 'bgftp', 'catlog', 'kvdb', 'psp2shell_', 'vdbtcp')
MAX_CONFIG_BYTES = 256 * 1024


def inspect_plugins(text):
    """Only active paths count; names match variants, case-insensitively."""
    findings = []
    nolockscreen = False
    section = None
    for line in text.splitlines():
        line = line.split('#', 1)[0].strip()
        if not line:
            continue
        if line.startswith('*'):
            section = line
            continue
        if not section or ':' not in line:
            continue
        name = line.replace('\\', '/').rsplit('/', 1)[-1].casefold()
        nolockscreen |= 'nolockscreen' in name
        for pattern in PLUGIN_PATTERNS:
            if pattern in name:
                findings.append({'plugin': pattern, 'path': line, 'section': section,
                                 'severity': 'incompatible' if pattern == 'vitacompanion' else 'not_recommended'})
                break
    return {'findings': findings, 'nolockscreen_enabled': nolockscreen}


def read_vita_config(host, port=1337):
    data = bytearray()
    def append(chunk):
        if len(data) + len(chunk) > MAX_CONFIG_BYTES:
            raise ClientError('tai/config.txt is larger than 256 KiB.')
        data.extend(chunk)
    # No STOR, DELE, rename, mkdir or other device write operations.
    with ftplib.FTP() as ftp:
        ftp.connect(host, port, timeout=15)
        ftp.login()
        ftp.retrbinary('RETR ur0:/tai/config.txt', append, blocksize=16384)
    return data.decode('utf-8-sig', errors='strict')


def _exclude_private_directory(folder, is_directory=True):
    """Keep generated identity/configuration out of a containing Git repository."""
    try:
        result = subprocess.run(['git', '-C', str(folder.parent), 'rev-parse', '--show-toplevel'],
                                capture_output=True, text=True)
    except FileNotFoundError:
        return
    if result.returncode:
        return
    root = Path(result.stdout.strip()).resolve()
    try:
        relative = folder.resolve().relative_to(root)
    except ValueError:
        return
    if not relative.parts:
        raise ClientError('Choose a configuration subdirectory, not the repository root.')
    tracked = subprocess.run(['git', '-C', str(root), 'ls-files', '--', str(relative)],
                             capture_output=True, text=True, check=True)
    if tracked.stdout.strip():
        raise ClientError('Private configuration must not overwrite tracked Git files.')
    result = subprocess.run(['git', '-C', str(root), 'rev-parse', '--git-path', 'info/exclude'],
                            capture_output=True, text=True, check=True)
    path = Path(result.stdout.strip())
    if not path.is_absolute():
        path = root / path
    path.parent.mkdir(parents=True, exist_ok=True)
    # Escape gitignore metacharacters in a user-selected directory name.
    pattern = '/' + ''.join('\\' + c if c in '\\*?[]#! ' else c for c in relative.as_posix()) + ('/' if is_directory else '')
    text = path.read_text() if path.exists() else ''
    if pattern not in text.splitlines():
        path.write_text(text.rstrip('\n') + '\n' + pattern + '\n')


def save_setup(folder, host, name):
    import pair_vita
    folder = folder.expanduser().resolve()
    if folder.exists() and not folder.is_dir():
        raise ClientError('Configuration directory is not a directory.')
    folder.parent.mkdir(parents=True, exist_ok=True)
    _exclude_private_directory(folder)
    folder.mkdir(mode=0o700, exist_ok=True)
    previous_base = pair_vita.BASE
    try:
        pair_vita.BASE = folder
        with contextlib.redirect_stdout(io.StringIO()):
            pair_vita.provision(host, name)
    finally:
        pair_vita.BASE = previous_base
    config = folder / 'config.json'
    durable_json(config, {'device_dir': '.', 'vita_ip': host, 'agent_name': name,
                          'screen_off_when_done': True})
    return config


class Terminal:
    def __init__(self, screen):
        self.screen = screen
        curses.noecho()
        screen.keypad(True)
    def draw(self, title, lines, footer='Enter: continue   Esc: cancel', offset=0):
        self.screen.erase()
        height, width = self.screen.getmaxyx()
        if height < 18 or width < 50:
            raise ClientError('Bootstrap needs a terminal at least 50 columns by 18 rows.')
        self.screen.addnstr(1, 2, 'vita-agent-use / ' + title, width-4, curses.A_BOLD)
        body = [part for line in lines for part in (textwrap.wrap(line, width-4) or [''])]
        capacity = height-9
        offset = min(offset, max(0, len(body)-capacity))
        y = 3
        for part in body[offset:offset+capacity]:
            self.screen.addnstr(y, 2, part, width-4)
            y += 1
        if len(body)>capacity:
            self.screen.addnstr(height-3, 2, 'PgUp/PgDn: scroll text (%d-%d of %d)' %
                                (offset+1, min(offset+capacity,len(body)),len(body)), width-4, curses.A_DIM)
        self.screen.addnstr(height-2, 2, footer, width-4, curses.A_DIM)
        self.screen.refresh()
        return min(y+1, height-4), width
    def ask(self, title, lines, default='', validate=None):
        value = default
        error = ''
        while True:
            y, width = self.draw(title, lines + ([error] if error else []))
            curses.curs_set(1)
            shown = value[-(width-7):]
            self.screen.addnstr(y, 2, '> ' + shown, width-4)
            self.screen.move(y, 4+len(shown))
            self.screen.refresh()
            key = self.screen.get_wch()
            if key == '\x1b':
                raise KeyboardInterrupt
            if key in ('\n', '\r', curses.KEY_ENTER):
                try:
                    if validate:
                        validate(value)
                    curses.curs_set(0)
                    return value
                except (ValueError, ClientError) as exc:
                    error = str(exc)
            elif key in ('\b', '\x7f', curses.KEY_BACKSPACE):
                value = value[:-1]
            elif key == '\x15':
                value = ''
            elif isinstance(key, str) and key.isprintable():
                value += key
    def choose(self, title, lines, options):
        selected = 0
        offset = 0
        while True:
            y, width = self.draw(title, lines, 'Up/Down: choose   Enter: select   Esc: cancel', offset=offset)
            curses.curs_set(0)
            height = self.screen.getmaxyx()[0]
            count = max(1, height-3-y)
            start = max(0, selected-count+1)
            for index in range(start, min(len(options), start+count)):
                self.screen.addnstr(y+index-start, 2, ('> ' if index == selected else '  ') + options[index],
                                    width-4, curses.A_REVERSE if index == selected else 0)
            self.screen.refresh()
            key = self.screen.get_wch()
            if key == '\x1b':
                raise KeyboardInterrupt
            if key in ('\n', '\r', curses.KEY_ENTER):
                return selected
            if key == curses.KEY_NPAGE:
                offset += max(1,height-9)
            if key == curses.KEY_PPAGE:
                offset = max(0,offset-max(1,height-9))
            if key == curses.KEY_UP:
                selected = (selected-1) % len(options)
            if key == curses.KEY_DOWN:
                selected = (selected+1) % len(options)


def run():
    if not os.isatty(0) or not os.isatty(1):
        raise ClientError('bootstrap is for humans and requires an interactive terminal.')
    def wizard(screen):
        ui = Terminal(screen)
        default = Path(os.environ['VITA_AGENT_CONFIG_DIR']).expanduser() if os.environ.get('VITA_AGENT_CONFIG_DIR') else Path.cwd() / 'agent' / 'vita-agent-use'
        def check_folder(value):
            if not value.strip():
                raise ClientError('Enter a configuration directory.')
        folder = Path(ui.ask('Configuration directory', [
            'Choose where to save config.json and the private PC identity.',
            'Default: the selected environment directory, or a folder beneath the current directory.',
            'Ctrl+U clears the field. Existing PC identities are retained.'], str(default), check_folder)).expanduser().resolve()
        def check_ip(value):
            ipaddress.IPv4Address(value)
        host = ui.ask('Vita IP address', ['Enter the Wi-Fi IPv4 address shown on your Vita.'], validate=check_ip)
        while True:
            ui.choose('Read Vita configuration', [
                'Open VitaShell and press SELECT to start its FTP server.',
                'The server must be at ' + host + ':1337.',
                'Bootstrap reads ur0:tai/config.txt. It never writes to the Vita.'], ['FTP is running; read configuration'])
            try:
                text = read_vita_config(host)
                assessment = inspect_plugins(text)
            except (OSError, ftplib.Error, ValueError) as exc:
                ui.choose('Could not read configuration', [str(exc), 'Check the address and FTP server.'], ['Retry'])
                continue
            findings = assessment['findings']
            if findings:
                blocked = any(item['severity'] == 'incompatible' for item in findings)
                lines = ['Enabled plugins to disable before using agent-use:'] + [
                    item['section'] + ' ' + item['path'] for item in findings]
                lines += ['VitaCompanion variants are incompatible. Other listed plugins are potentially incompatible or not recommended concurrently.',
                          'Edit the config yourself; bootstrap will not change it. Reboot after disabling plugins.']
                options = ['Re-read after editing'] + ([] if blocked else ['Continue with these warnings'])
                if ui.choose('Plugin compatibility', lines, options) == 0:
                    continue
            if not assessment['nolockscreen_enabled']:
                ui.choose('Recommended plugin', [
                    'NoLockScreen is not enabled in ur0:tai/config.txt.',
                    'Installing and enabling nolockscreen.suprx is recommended.',
                    'Bootstrap does not install plugins or change tai/config.txt.'], ['Continue'])
            break
        index = ui.choose('Agent name', ['Choose the name shown in Vita notifications and approval dialogs.'], list(AGENT_NAMES))
        name = AGENT_NAMES[index]
        if name == 'Custom':
            name = ui.ask('Custom agent name', ['Enter the agent name.'], validate=validate_agent_name)
        ui.choose('Save configuration', ['Directory: ' + str(folder), 'Vita: ' + host, 'Agent: ' + name,
                  'This creates or retains the PC identity in this directory.',
                  'An existing config.json in this directory will be updated.'], ['Save'])
        config = save_setup(folder, host, name)
        ui.choose('Setup complete', ['Saved: ' + str(config), 'The PC identity is ready. No Vita files were changed.',
                  'Set this in your shell or agent launch environment:',
                  'export VITA_AGENT_CONFIG_DIR=' + shlex.quote(str(folder)),
                  'First connection: python3 client/vita_agent.py session pair (tap OK on the Vita).',
                  'Then start the PC event server: python3 client/vita_agent.py serve'], ['Finish'])
        return config
    try:
        config = curses.wrapper(wizard)
        print('export VITA_AGENT_CONFIG_DIR=' + shlex.quote(str(config.parent)))
        return config
    except curses.error as exc:
        raise ClientError("Could not initialize or draw the terminal UI: " + str(exc)) from exc
