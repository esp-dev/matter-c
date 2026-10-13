"""Create a private CSA01 TH project from the frozen, observed x86 profile.

No network writes. Input/output project files contain lab configuration and must
remain outside Git. Presence is a capability declaration, never a PASS result.
"""
import argparse
import json
from pathlib import Path

CLUSTERS = {0x1d: 'DESC', 0x28: 'BINFO', 0x30: 'CGEN', 0x31: 'CNET',
            0x3e: 'OPCREDS', 0x1f: 'ACL', 0x3f: 'GRPKEY', 0x33: 'DGGEN',
            0x36: 'DGWIFI', 0x3c: 'CADMIN', 0x38: 'TIMESYNC', 0x2a: 'OTAR',
            3: 'I', 0xb06: 'MTRID', 0x9c: 'PWRTL', 0x90: 'EPM', 0x91: 'EEM'}
EVENTS = {'BINFO': (0,), 'ACL': (0,), 'DGGEN': (3,), 'TIMESYNC': (3,),
          'OTAR': (0, 1, 2), 'EEM': (0,)}
CORE = {
    'MCORE.ROLE.COMMISSIONEE': True, 'MCORE.ROLE.COMMISSIONER': False,
    'MCORE.SC.S.TCP': False, 'MCORE.COM.WIFI': True,
    'MCORE.COM.THREAD': False, 'MCORE.COM.BLE': False,
    'MCORE.DD.NFC': False, 'MCORE.DD.QR': True, 'MCORE.DD.MANUAL_PC': True,
    'MCORE.OTA.Requestor': True, 'MCORE.OTA.Provider': False,
    'MCORE.BDX.Receiver': True, 'MCORE.BDX.Initiator': True,
    'MCORE.BDX.SynchronousReceiver': True, 'MCORE.BDX.Driver': True,
    'MCORE.BDX.Sender': False, 'MCORE.BDX.Responder': False,
    'MCORE.BDX.SynchronousSender': False, 'MCORE.BDX.AsynchronousSender': False,
    'MCORE.BDX.AsynchronousReceiver': False,
    # The OTA client initiates authorized commands to another node. Its limited
    # controller role does not imply commissioning or a general Read client.
    'MCORE.ROLE.CONTROLLER': True, 'MCORE.ACL.Administrator': False,
    'MCORE.IDM.S': True, 'MCORE.IDM.C': True,
    'MCORE.IDM.C.InvokeRequest': True, 'MCORE.IDM.C.InvokeRequest.BatchCommands': False,
    'MCORE.IDM.C.ReadRequest': False, 'MCORE.IDM.C.WriteRequest': False,
    'MCORE.IDM.C.SubscribeRequest': False, 'MCORE.IDM.S.PersistentSubscription': False,
    'MCORE.DD.COMM_DISCOVERY': True, 'MCORE.DD.UI': False,
    'MCORE.DD.CUSTOM_COMM_FLOW': False, 'MCORE.SC.LWIP': False,
    'CNET.C.F00': False, 'CNET.C.F01': False,
}


def flags_for(profile, endpoint):
    # Server PICS are endpoint-local, including negative declarations for root
    # clusters on application endpoints (checked by official IDM 10.4).
    selected = {row['cluster']: row for row in profile if row['endpoint'] == endpoint}
    flags = dict(CORE)
    for cluster, name in CLUSTERS.items():
        row = selected.get(cluster)
        flags[name + '.S'] = row is not None
        flags[name + '.C'] = False
        for bit in range(8):
            flags[f'{name}.S.F{bit:02x}'] = bool(row and row['FeatureMap'] & (1 << bit))
        for attr in range(0x20):
            flags[f'{name}.S.A{attr:04x}'] = bool(row and attr in row['AttributeList'])
        for command in (*range(0x20), 0x40):
            for suffix, field in [('Rsp', 'AcceptedCommandList'), ('Tx', 'GeneratedCommandList')]:
                flags[f'{name}.S.C{command:02x}.{suffix}'] = bool(row and command in row[field])
        for event in range(8):
            flags[f'{name}.S.E{event:02x}'] = bool(row and event in EVENTS.get(name, ()))
    flags.update({'G.S': False, 'BINFO.C.A0002': False,
                  'BINFO.S.M.DeviceConfigurationChange': False,
                  'PICS_SDK_CI_ONLY': False, 'PICS_USER_PROMPT': True})
    # Descriptor.ClientList contains 0x0029 on EP0. The runtime's OTA client
    # issues QueryImage, ApplyUpdateRequest and NotifyUpdateApplied; it is not
    # an OTA Provider server (MCORE.OTA.Provider stays false).
    flags.update({'OTAP.C': endpoint == 0, 'OTAP.S': False})
    for command in (0, 2, 4):
        flags[f'OTAP.C.C{command:02x}.Tx'] = endpoint == 0
    for command in (1, 3):
        flags[f'OTAP.C.C{command:02x}.Rsp'] = endpoint == 0
    return flags


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--base', type=Path, required=True)
    p.add_argument('--profile', type=Path, required=True)
    p.add_argument('--output', type=Path, required=True)
    p.add_argument('--endpoint', type=int, choices=(0, 1, 3, 4, 5), required=True)
    p.add_argument('--discriminator', type=int, required=True)
    a = p.parse_args()
    if not 0 <= a.discriminator <= 4095:
        p.error('discriminator must be 0..4095')
    project = json.loads(a.base.read_text(encoding='utf-8'))
    profile = json.loads(a.profile.read_text(encoding='utf-8'))
    project['name'] = f'Matter C CSA01 endpoint {a.endpoint}'
    project['config']['dut_config']['discriminator'] = str(a.discriminator)
    params = project['config']['test_parameters']
    params['endpoint'] = str(a.endpoint)
    # Whole-test watchdog only: several published cases deliberately wait for
    # 180-second commissioning windows or long reporting intervals.
    params['timeout'] = '1500'
    # Explicitly disable certification-disallowed bypasses, including the
    # upstream 10.2 default that otherwise ignores work-in-progress conformance.
    params['bool-arg'] = ('ignore_in_progress_test_event_only_disallowed_for_certification:False '
                          'allow_provisional_test_event_only_disallowed_for_certification:False '
                          'allow_unsupported_described_conformance:False')
    profiles = {}
    for key, enabled in flags_for(profile, a.endpoint).items():
        group = key.split('.')[0]
        profiles.setdefault(group, {'name': group, 'items': {}})['items'][key] = {
            'number': key, 'enabled': enabled}
    project['pics']['clusters'] = profiles
    with a.output.open('x', encoding='utf-8') as f:
        json.dump(project, f, indent=2)
        f.write('\n')
    print(f'Prepared CSA01 endpoint {a.endpoint}; no TH mutation.')


if __name__ == '__main__':
    main()
