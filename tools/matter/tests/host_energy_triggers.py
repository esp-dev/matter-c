"""Full SDK error/direction/stop/restart regression; not an official CSA test.

--string-arg mode:disabled checks the default; mode:run records a baseline;
mode:restart checks discarded laboratory energy and disabled triggers.
Optional --int-arg remove:1 removes the sole laboratory fabric at the end.
"""
import asyncio
import json
import logging
from pathlib import Path

from mobly import asserts
import matter.clusters as C
from matter.interaction_model import InteractionModelError, Status
from matter.testing.decorators import async_test_body
from matter.testing.matter_testing import MatterBaseTest
from matter.testing.runner import default_matter_test_main


class EnergyTriggers(MatterBaseTest):
    @async_test_body
    async def test_energy_triggers(self):
        gd, epm, eem = C.GeneralDiagnostics, C.ElectricalPowerMeasurement, C.ElectricalEnergyMeasurement
        mode = self.user_params.get('mode', 'run')
        asserts.assert_in(mode, ('run', 'disabled', 'restart'))
        key = bytes.fromhex('000102030405060708090a0b0c0d0e0f')  # Laboratory fixture only.
        stop = 0x0091000100000000  # SDK target endpoint1 in bits32..47.
        baseline = Path(self.matter_test_config.storage_path).parent / 'energy-baseline.json'

        async def read(cluster, attr, endpoint=1):
            return await self.read_single_attribute_check_success(cluster=cluster, attribute=attr, endpoint=endpoint)

        async def send(event, enable_key=key, expected=None):
            try:
                await self.send_single_cmd(cmd=gd.Commands.TestEventTrigger(enableKey=enable_key, eventTrigger=event), endpoint=0)
            except InteractionModelError as error:
                asserts.assert_equal(error.status, expected)
            else:
                asserts.assert_is_none(expected, 'Command unexpectedly accepted')

        async def registers():
            return [(await read(eem, a)).energy for a in
                    (eem.Attributes.CumulativeEnergyImported, eem.Attributes.CumulativeEnergyExported)]

        enabled = await read(gd, gd.Attributes.TestEventTriggersEnabled, 0)
        asserts.assert_equal(enabled, mode == 'run')
        if mode != 'run':
            await send(stop + 1, expected=Status.ConstraintError)
            if mode == 'restart':
                previous = json.loads(baseline.read_text())
                current = await registers()
                # Fresh laboratory fixture: synthetic energy was never persisted.
                # The node has just restarted; normal registers begin from zero.
                asserts.assert_greater(previous[0], current[0], 'Synthetic import survived restart or restart check was too late')
                logging.info('PASS restart: laboratory energy discarded, triggers disabled; current=%s previous=%s', current, previous)
            else:
                logging.info('PASS default disabled: valid laboratory key rejected')
        else:
            # Establish load before negative commands so they must not stop/change it.
            await send(stop + 1)
            for invalid in (bytes(16), bytes([255]) * 16, key[:15]):
                await send(stop + 2, invalid, Status.ConstraintError)
            await send(stop + 3, expected=Status.InvalidCommand)
            await send(0x0091000200000001, expected=Status.InvalidCommand)
            await asyncio.sleep(3.1)
            p1 = await read(epm, epm.Attributes.ActivePower)
            first = await registers()
            await asyncio.sleep(3.1)
            p2 = await read(epm, epm.Attributes.ActivePower)
            second = await registers()
            for p in (p1, p2):
                asserts.assert_true(980000 <= p <= 1020000, 'Expected approximately 1kW')
            asserts.assert_not_equal(p1, p2)
            asserts.assert_greater(second[0], first[0])
            asserts.assert_equal(second[1], first[1])
            await send(stop + 2)
            await asyncio.sleep(1.2)
            first = await registers()
            await asyncio.sleep(5.2)
            second = await registers()
            asserts.assert_equal(second[0], first[0])
            asserts.assert_greater(second[1], first[1])
            asserts.assert_less(await read(epm, epm.Attributes.ActivePower), 0)
            await send(stop)
            await asyncio.sleep(1.2)
            asserts.assert_in(await read(epm, epm.Attributes.ActivePower), (3600000, -1800000))
            baseline.write_text(json.dumps(await registers()))
            logging.info('PASS wrong/zero/short key, unknown event, changing load, directional energy, generator and stop')

        if self.user_params.get('remove', 0):
            oc = C.OperationalCredentials
            fabrics = await read(oc, oc.Attributes.CommissionedFabrics, 0)
            asserts.assert_equal(fabrics, 1, 'Only remove a fresh single-fabric laboratory node')
            index = await read(oc, oc.Attributes.CurrentFabricIndex, 0)
            response = await self.send_single_cmd(cmd=oc.Commands.RemoveFabric(fabricIndex=index), endpoint=0)
            asserts.assert_equal(response.statusCode, 0)
            logging.info('PASS last-fabric removal response; inspect node reset/clean shutdown separately')


if __name__ == '__main__':
    default_matter_test_main()
