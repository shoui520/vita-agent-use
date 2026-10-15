# SPDX-License-Identifier: GPL-3.0-or-later
"""Saved-pairing session renewal shared by direct CLI commands and serve.

Renewal happens only when the Vita no longer holds this PC's grant: a 401,
a refused command port, or a passed expiry. A dropped connection alone is
reconnected with the same token, which keeps exact-ID replay possible.
"""
import sys
import time
from pathlib import Path
from vita_client import ClientError, GrantExpiredError, NotSentError

# The Vita issues the token before its command listener is up.
COMMAND_READY_WAIT = 15


def stderr_log(*parts):
    print(*parts, file=sys.stderr, flush=True)


class SessionRenewer:
    def __init__(self, device_dir, *, host=None, agent_name=None, credentials_path=None,
                 state_path=None, timeout=60, log=stderr_log):
        self.device_dir = Path(device_dir).resolve()
        self.host, self.agent_name, self.timeout, self.log = host, agent_name, timeout, log
        pc = self.device_dir / 'pc'
        self.credentials_path = Path(credentials_path) if credentials_path else pc / 'credentials.json'
        self.state_path = Path(state_path) if state_path else pc / 'state.json'
        self.renewals = 0
        self.last_renewed = None

    @staticmethod
    def needs_renewal(client, exc):
        if isinstance(exc, GrantExpiredError):
            return True
        if isinstance(exc, NotSentError) and exc.refused:
            # The command port only closes when the Vita has no command
            # session for this PC (reboot, expiry or another admission).
            return True
        return client.session_expired()

    def __call__(self, client, exc):
        if self.needs_renewal(client, exc):
            self.renew_now(client)

    def renew_now(self, client, *, pair=False, log=None):
        import pair_vita
        pair_vita.BASE = self.device_dir
        # Admission waits for the current controller to disconnect, and that
        # may be this client's own command connection.
        close = getattr(client, '_close_transport', None)
        if close is not None:
            close()
        archived = []
        credentials = pair_vita.pair(
            resume=not pair, host=self.host, agent_name=self.agent_name,
            timeout=max(self.timeout, 75) if pair else self.timeout,
            state_lock=getattr(client, '_state_lock', None), on_archived=archived.append,
            credentials_path=self.credentials_path, state_path=self.state_path,
            log=log or self.log)
        client.rebind(credentials)
        client.command_ready_until = time.monotonic() + COMMAND_READY_WAIT
        self.renewals += 1
        self.last_renewed = time.time()
        for record in archived:
            client._emit_notice({'type': 'command.unresolved', **record})
        client._emit_notice({'type': 'session.renewed', 'paired': pair})
        return credentials


def attach(client, options):
    """Give a direct-mode client automatic renewal when device_dir is known."""
    client.credentials_path = getattr(options, 'credentials', None)
    device_dir = getattr(options, 'device_dir', None)
    if device_dir:
        client.session_hook = SessionRenewer(
            device_dir, host=getattr(options, 'vita_ip', None), agent_name=getattr(options, 'agent_name', None),
            credentials_path=getattr(options, 'credentials', None), state_path=getattr(options, 'state', None))
    return client


__all__ = ['SessionRenewer', 'attach', 'ClientError']
