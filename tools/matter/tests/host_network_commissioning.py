"""Complete host Wi-Fi simulation over CASE; local regression, NOT a CSA test.

Default mode runs errors, configuration, connect and rollback. mode:prepare
leaves the primary network committed for TH; mode:arm additionally arms the
fail-safe required by Core 1.6.1 11.9.7.1 before the unchanged scan test.
The two APs are simulated by matter_server.c; IPv6 transport remains real.
"""
import asyncio
import logging

from mobly import asserts
import matter.clusters as C
from matter.clusters.Types import NullValue
from matter.interaction_model import InteractionModelError, Status
from matter.testing.decorators import async_test_body
from matter.testing.matter_testing import MatterBaseTest
from matter.testing.runner import default_matter_test_main


class NetworkCommissioning(MatterBaseTest):
    @async_test_body
    async def test_network(self):
        nc, gc = C.NetworkCommissioning, C.GeneralCommissioning
        primary, secondary, password = b'testharness', b'testharness-2', b'wifi-password'
        mode = self.user_params.get('mode', 'run')
        asserts.assert_in(mode, ('run', 'prepare', 'arm'))

        async def send(cmd):
            return await self.send_single_cmd(cmd=cmd, endpoint=0)

        async def read(attr, cluster=nc):
            return await self.read_single_attribute_check_success(cluster=cluster, attribute=attr, endpoint=0)

        async def arm(seconds):
            response = await send(gc.Commands.ArmFailSafe(expiryLengthSeconds=seconds))
            asserts.assert_equal(response.errorCode, gc.Enums.CommissioningErrorEnum.kOk)
            if seconds == 0:
                await asyncio.sleep(0.3)

        async def network(cmd, status=0):
            response = await send(cmd)
            asserts.assert_equal(response.networkingStatus, status)
            return response

        async def rejected(cmd, expected):
            try:
                await send(cmd)
            except InteractionModelError as error:
                asserts.assert_equal(error.status, expected)
            else:
                asserts.fail(f'Expected {expected}')

        async def connected(ssid):
            entries = await read(nc.Attributes.Networks)
            asserts.assert_equal([e.networkID for e in entries if e.connected], [ssid])
            return entries

        await arm(0)
        if mode == 'run':
            await rejected(nc.Commands.ScanNetworks(), Status.FailsafeRequired)
            await rejected(nc.Commands.AddOrUpdateWiFiNetwork(ssid=primary, credentials=password), Status.FailsafeRequired)
        await arm(60)
        await network(nc.Commands.AddOrUpdateWiFiNetwork(ssid=primary, credentials=password))
        await network(nc.Commands.ConnectNetwork(networkID=primary))
        await connected(primary)
        response = await send(gc.Commands.CommissioningComplete())
        asserts.assert_equal(response.errorCode, gc.Enums.CommissioningErrorEnum.kOk)
        baseline = await read(nc.Attributes.Networks)
        if mode == 'prepare':
            logging.info('PASS TH precondition: primary network committed and connected')
            return
        await arm(600 if mode == 'arm' else 60)
        if mode == 'arm':
            logging.info('PASS TH scan precondition: primary connected, fail-safe armed for 600 s')
            return
        try:
            scan = await network(nc.Commands.ScanNetworks(ssid=NullValue, breadcrumb=11))
            asserts.assert_equal({ap.ssid for ap in scan.wiFiScanResults}, {primary, secondary})
            scan = await network(nc.Commands.ScanNetworks(ssid=secondary, breadcrumb=12))
            asserts.assert_equal([ap.ssid for ap in scan.wiFiScanResults], [secondary])
            await network(nc.Commands.ScanNetworks(ssid=b'absent', breadcrumb=99), 5)
            asserts.assert_equal(await read(gc.Attributes.Breadcrumb, gc), 12)
            await network(nc.Commands.AddOrUpdateWiFiNetwork(ssid=secondary, credentials=b'wrong-password', breadcrumb=13))
            await network(nc.Commands.ConnectNetwork(networkID=secondary, breadcrumb=99), 7)
            asserts.assert_equal(await read(nc.Attributes.LastConnectErrorValue), 13)
            asserts.assert_equal(await read(gc.Attributes.Breadcrumb, gc), 13)
            await network(nc.Commands.AddOrUpdateWiFiNetwork(ssid=secondary, credentials=password))
            await network(nc.Commands.ConnectNetwork(networkID=secondary, breadcrumb=14))
            await connected(secondary)
            await network(nc.Commands.ReorderNetwork(networkID=secondary, networkIndex=0))
            asserts.assert_equal((await read(nc.Attributes.Networks))[0].networkID, secondary)
            await network(nc.Commands.RemoveNetwork(networkID=b'absent'), 3)
            await network(nc.Commands.ConnectNetwork(networkID=b'absent'), 3)
            await network(nc.Commands.RemoveNetwork(networkID=primary))
            await arm(0)
            asserts.assert_equal(await read(nc.Attributes.Networks), baseline)
            await connected(primary)
            await arm(60)
            await network(nc.Commands.AddOrUpdateWiFiNetwork(ssid=secondary, credentials=password))
            await network(nc.Commands.ConnectNetwork(networkID=secondary))
            await arm(1)
            await asyncio.sleep(2)
            asserts.assert_equal(await read(nc.Attributes.Networks), baseline)
            await connected(primary)
            asserts.assert_equal(await read(nc.Attributes.LastNetworkID), primary)
            asserts.assert_equal(await read(nc.Attributes.LastNetworkingStatus), 0)
            asserts.assert_equal(await read(nc.Attributes.LastConnectErrorValue), NullValue)
            asserts.assert_equal(await read(gc.Attributes.Breadcrumb, gc), 0)
            logging.info('PASS CASE scan/add/update/connect/reorder/remove, authentication errors, Breadcrumb, zero/natural rollback')
        finally:
            await arm(0)


if __name__ == '__main__':
    default_matter_test_main()
