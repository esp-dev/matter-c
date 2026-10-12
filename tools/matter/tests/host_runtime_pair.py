"""OSS04: two native runtimes in one process/thread; local SDK acceptance, not CSA certification."""
import asyncio
import logging
from mobly import asserts
from matter import ChipDeviceCtrl
import matter.clusters as C
from matter.testing.decorators import async_test_body
from matter.testing.matter_testing import MatterBaseTest
from matter.testing.runner import default_matter_test_main


class RuntimePair(MatterBaseTest):
    @async_test_body
    async def test_runtime_pair(self):
        ctrl, a, b = self.default_controller, self.dut_node_id, self.dut_node_id + 1
        await ctrl.CommissionOnNetwork(nodeId=b, setupPinCode=20202021,
                                      filterType=ChipDeviceCtrl.DiscoveryFilterType.LONG_DISCRIMINATOR,
                                      filter=1234)
        oc, sw, epm, eem = C.OperationalCredentials, C.OnOff, C.ElectricalPowerMeasurement, C.ElectricalEnergyMeasurement

        async def read(node, endpoint, cluster, attribute):
            result = await ctrl.ReadAttribute(node, [(endpoint, attribute)])
            return result[endpoint][cluster][attribute]

        for node, label in ((a, 'runtime-A'), (b, 'runtime-B')):
            reply = await ctrl.SendCommand(node, 0, oc.Commands.UpdateFabricLabel(label=label))
            asserts.assert_equal(reply.statusCode, 0)
        for node, label in ((a, 'runtime-A'), (b, 'runtime-B')):
            fabrics = await read(node, 0, oc, oc.Attributes.Fabrics)
            asserts.assert_equal(len(fabrics), 1)
            asserts.assert_equal(fabrics[0].nodeID, node)
            asserts.assert_equal(fabrics[0].label, label)
        logging.info('PASS independent fabrics, operational credentials and persistent labels')

        subscriptions = []
        try:
            for node in (a, b):
                sub = await ctrl.ReadAttribute(node, [(2, sw.Attributes.OnOff)],
                                               reportInterval=(0, 2), keepSubscriptions=False, autoResubscribe=False)
                subscriptions.append(sub)
            await ctrl.SendCommand(a, 2, sw.Commands.On())
            asserts.assert_true(await read(a, 2, sw, sw.Attributes.OnOff), 'A must turn on')
            asserts.assert_false(await read(b, 2, sw, sw.Attributes.OnOff), 'A command must not turn B on')
            for _ in range(30):
                if subscriptions[0].GetAttributes()[2][sw][sw.Attributes.OnOff]:
                    break
                await asyncio.sleep(0.1)
            asserts.assert_true(subscriptions[0].GetAttributes()[2][sw][sw.Attributes.OnOff], 'A report missing')
            asserts.assert_false(subscriptions[1].GetAttributes()[2][sw][sw.Attributes.OnOff], 'A report leaked to B')
            before = await read(b, 1, eem, eem.Attributes.CumulativeEnergyImported)
            power = await read(b, 1, epm, epm.Attributes.ActivePower)
            asserts.assert_true(power in (3600000, -1800000), 'Missing simulated instantaneous power')
            logging.info('PASS simultaneous CASE subscriptions and isolated On/Off command')

            own = await read(a, 0, oc, oc.Attributes.CurrentFabricIndex)
            reply = await ctrl.SendCommand(a, 0, oc.Commands.RemoveFabric(fabricIndex=own))
            asserts.assert_equal(reply.statusCode, 0)
            subscriptions[0].Shutdown()
            # A has a bounded reply drain. B is pumped throughout teardown.
            await asyncio.sleep(3)
            await ctrl.SendCommand(b, 2, sw.Commands.On())
            for _ in range(30):
                if subscriptions[1].GetAttributes()[2][sw][sw.Attributes.OnOff]:
                    break
                await asyncio.sleep(0.1)
            asserts.assert_true(subscriptions[1].GetAttributes()[2][sw][sw.Attributes.OnOff], 'B subscription must survive A deletion')
            after = await read(b, 1, eem, eem.Attributes.CumulativeEnergyImported)
            asserts.assert_greater(after.energy, before.energy, 'B energy source must keep running')
            subscriptions[1].Shutdown()
            ctrl.ExpireSessions(b)
            asserts.assert_true(await read(b, 2, sw, sw.Attributes.OnOff), 'B fresh CASE read failed')
            fabrics = await read(b, 0, oc, oc.Attributes.Fabrics)
            asserts.assert_equal(fabrics[0].label, 'runtime-B')
            logging.info('PASS B subscription, increasing EEM and fresh CASE after A removal/deletion')
        finally:
            for sub in subscriptions:
                sub.Shutdown()
        own = await read(b, 0, oc, oc.Attributes.CurrentFabricIndex)
        reply = await ctrl.SendCommand(b, 0, oc.Commands.RemoveFabric(fabricIndex=own))
        asserts.assert_equal(reply.statusCode, 0)
        logging.info('PASS both last-fabric responses; verify PAIR_DELETED twice and clean process exit')


if __name__ == '__main__':
    default_matter_test_main()
