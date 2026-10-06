# SPDX-License-Identifier: GPL-3.0-or-later
"""Provision a private device identity or pair with the native Vita OK prompt."""
import argparse
import datetime
import hashlib
import http.client
import json
import os
from pathlib import Path
import ssl
import time
import tempfile
import fcntl
import stat
from contextlib import contextmanager
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID, ExtendedKeyUsageOID
from vita_client import durable_json, private_json, ClientError, VitaClient, validate_host, validate_agent_name

BASE=Path.home()/'.local/share/vita-agent-use'

def create_identity(folder,name,usage):
    key=ec.generate_private_key(ec.SECP256R1())
    subject=x509.Name([x509.NameAttribute(NameOID.COMMON_NAME,name)])
    now=datetime.datetime.now(datetime.timezone.utc)
    cert=(x509.CertificateBuilder().subject_name(subject).issuer_name(subject)
          .public_key(key.public_key()).serial_number(x509.random_serial_number())
          .not_valid_before(now-datetime.timedelta(days=1)).not_valid_after(now+datetime.timedelta(days=3650))
          .add_extension(x509.BasicConstraints(ca=True,path_length=0),critical=True)
          .add_extension(x509.KeyUsage(True,False,False,False,False,True,False,False,False),critical=True)
          .add_extension(x509.ExtendedKeyUsage([usage]),critical=False).sign(key,hashes.SHA256()))
    for suffix,data in {
        '.der':cert.public_bytes(serialization.Encoding.DER),
        '.pem':cert.public_bytes(serialization.Encoding.PEM),
        '-key.der':key.private_bytes(serialization.Encoding.DER,serialization.PrivateFormat.PKCS8,serialization.NoEncryption()),
        '-key.pem':key.private_bytes(serialization.Encoding.PEM,serialization.PrivateFormat.PKCS8,serialization.NoEncryption())}.items():
        path=folder/(name+suffix)
        fd=os.open(path,os.O_WRONLY|os.O_CREAT|os.O_EXCL,0o600)
        with os.fdopen(fd,'wb') as stream: stream.write(data)
    return hashlib.sha256(cert.public_bytes(serialization.Encoding.DER)).hexdigest()

def provision(host,name):
    BASE.mkdir(mode=0o700,exist_ok=True)
    local=BASE/'pc'
    local.mkdir(mode=0o700,exist_ok=True)
    config=local/'pairing.json'
    if config.exists():
        print('Existing identity retained:',config); return
    client_pin=create_identity(local,'client',ExtendedKeyUsageOID.CLIENT_AUTH)
    durable_json(config,dict(host=host,port=8847,agent_name=name,certificate_sha256=None,
        client_certificate=str(local/'client.pem'),client_key=str(local/'client-key.pem'),
        client_fingerprint=client_pin))
    print('PC identity prepared. The Vita generates and stores its own identity on first boot.')
    print('Client fingerprint for native prompt:',client_pin.upper())

@contextmanager
def pairing_state_lock():
    path=BASE/'pc/state.json.lock'
    fd=os.open(path,os.O_RDWR|os.O_CREAT|os.O_NOFOLLOW,0o600)
    try:
        info=os.fstat(fd)
        if not stat.S_ISREG(info.st_mode) or info.st_mode & 0o077 or info.st_uid!=os.getuid():
            raise ClientError('State lock must be a private regular file.')
        try: fcntl.flock(fd,fcntl.LOCK_EX|fcntl.LOCK_NB)
        except BlockingIOError: raise ClientError('An existing command is using this session; retry pairing after it finishes.') from None
        yield
    finally: os.close(fd)


def pair(resume=False, *, host=None, agent_name=None, timeout=75):
    with pairing_state_lock():
        return pair_locked(resume, host=host, agent_name=agent_name, timeout=timeout)


def pair_locked(resume=False, *, host=None, agent_name=None, timeout=75):
    config=dict(private_json(BASE/'pc/pairing.json'))
    if host is not None:config['host']=host
    if agent_name is not None:config['agent_name']=agent_name
    validate_host(config['host'])
    validate_agent_name(config['agent_name'])
    context=ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    context.check_hostname=False; context.verify_mode=ssl.CERT_NONE
    context.minimum_version=context.maximum_version=ssl.TLSVersion.TLSv1_2
    context.set_ciphers('ECDHE-ECDSA-CHACHA20-POLY1305:ECDHE-ECDSA-AES128-GCM-SHA256')
    context.load_cert_chain(config['client_certificate'],config['client_key'])
    connection=http.client.HTTPSConnection(config['host'],config['port'],context=context,timeout=timeout)
    started_at=time.time()
    try:
        connection.connect()
        pin=hashlib.sha256(connection.sock.getpeercert(binary_form=True)).hexdigest()
        expected_pin=config.get('certificate_sha256')
        if expected_pin is None and resume:
            raise ClientError('Pair this Vita once before reconnecting.')
        if expected_pin is not None and pin!=expected_pin:
            raise ClientError('Vita certificate pin mismatch.')
        if not resume:
            print('Compare this client fingerprint with the Vita prompt:',config['client_fingerprint'].upper(),flush=True)
        body=json.dumps(dict(v=1,agent_name=config['agent_name']),separators=(',',':')).encode()
        connection.request('POST','/v1/session' if resume else '/v1/pair',body=body,headers={'Content-Type':'application/json','Connection':'close'})
        response=connection.getresponse(); data=response.read(1025)
        if response.status!=200 or len(data)>1024:
            if response.status==403 and len(data)<=1024:
                try:
                    failure=json.loads(data)
                except (ValueError,UnicodeError):
                    failure={}
                if isinstance(failure,dict) and failure.get('error')=='identity_not_paired':
                    raise ClientError('This PC identity is not paired. Run session pair and tap OK on the Vita once. Other approved identities are retained.')
            raise ClientError('Saved-peer session rejected.' if resume else 'Pairing rejected.')
        result=json.loads(data)
        token=result.get('token','')
        if len(token)!=64 or any(c not in '0123456789abcdef' for c in token): raise ClientError('Invalid grant response.')
        if type(result.get('v')) is not int or result['v']!=1 or type(result.get('command_port')) is not int or not 1<=result['command_port']<=65535: raise ClientError('Invalid service response.')
        if expected_pin is None:
            config['certificate_sha256']=pin
            durable_json(BASE/'pc/pairing.json',config)
        credentials={k:config[k] for k in ('host','agent_name','certificate_sha256','client_certificate','client_key')}
        # Start before the exchange so the host deadline is conservative.
        credentials.update(port=result['command_port'],token=token,session_expires_at=started_at+3600)
        durable_json(BASE/'pc/credentials.json',credentials)
        state=BASE/'pc/state.json'
        if state.exists():
            old=private_json(state)
            new_identity=VitaClient(credentials,state).identity
            if not isinstance(old,dict) or old.get('identity')!=new_identity:
                # Preserve uncertain old operations; their grants are distinct
                # from the newly approved token and must not share request IDs.
                fd,backup=tempfile.mkstemp(prefix='previous-state-',suffix='.json',dir=state.parent)
                os.close(fd); os.replace(state,backup)
        print('Session accepted.' if resume else 'Pairing accepted.', 'Credentials saved privately; command endpoint port',result['command_port'])
        return credentials
    except ssl.SSLError as exc:
        if getattr(exc,'reason',None)=='TLSV1_ALERT_UNKNOWN_CA' or 'TLSV1_ALERT_UNKNOWN_CA' in str(exc):
            raise ClientError(
                'Vita rejected this PC certificate (TLS unknown CA). The installed plugin may predate multi-identity pairing. '
                'Update the Shell plugin, then use session pair to approve this identity; other approvals are retained. '
                'The trusted peer name/fingerprint is unavailable from this rejected handshake.'
            ) from exc
        raise
    except TimeoutError as exc:
        raise ClientError(
            'Pairing/session connection timed out. Another PC server may still own the command connection; '
            'finish its work and stop that serve process, then retry. The Vita keeps every approved identity. '
            'If no server is active, check the Vita IP and connectivity. Do not delete pairing files.'
        ) from exc
    finally: connection.close()

def wait_for_commands(credentials,timeout=15,*,screen_off_when_done=True):
    client=VitaClient(credentials,BASE/'pc/state.json',timeout=5,screen_off_when_done=screen_off_when_done)
    deadline=time.monotonic()+timeout
    try:
        while True:
            try:
                result=client.call('capabilities',{})
                if result.get('status')!='ok': raise ClientError('Command service rejected its capabilities request.')
                return client
            except ClientError as exc:
                if not isinstance(exc.__cause__,ConnectionRefusedError) or time.monotonic()>=deadline:
                    raise
                time.sleep(1)
    except BaseException:
        client.close(); raise


if __name__=='__main__':
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('action',choices=('provision','pair','connect'))
    parser.add_argument('--host'); parser.add_argument('--name',default='Agent')
    args=parser.parse_args()
    if args.action=='provision':
        if not args.host:parser.error('provision requires --host')
        provision(args.host,args.name)
    else:
        credentials=pair(resume=args.action=='connect')
        client=wait_for_commands(credentials)
        client.close()
        print('Authenticated command service verified with capabilities.')
