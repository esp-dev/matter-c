"""Local SDK regression; separate from the unmodified CSA TC_OPCREDS_3_1.

Preserve the same enhanced window across AddNOC rollback and timer expiry;
rediscover its discriminator/CM and establish fresh PASE with the same code.
Verify rollback data, the original CASE fabric and explicit window revocation.
"""
import asyncio
import logging

from mobly import asserts
import matter.clusters as Clusters
import matter.discovery as Discovery
from matter.testing.decorators import async_test_body
from matter.testing.matter_testing import MatterBaseTest
from matter.testing.runner import default_matter_test_main


class FailsafeWindow(MatterBaseTest):
    @async_test_body
    async def test_failsafe_window(self):
        oc, gc, ac = Clusters.OperationalCredentials, Clusters.GeneralCommissioning, Clusters.AdministratorCommissioning
        case, node = self.default_controller, self.dut_node_id

        async def read(ctrl, target, attr, cluster=oc):
            return await self.read_single_attribute_check_success(
                dev_ctrl=ctrl, node_id=target, cluster=cluster, attribute=attr,
                endpoint=0, fabric_filtered=False)

        attrs = (oc.Attributes.NOCs, oc.Attributes.Fabrics, oc.Attributes.TrustedRootCertificates)
        initial = {a: await read(case, node, a) for a in attrs}
        ca = self.certificate_authority_manager.NewCertificateAuthority(maximizeCertChains=True)
        peer = ca.NewFabricAdmin(vendorId=0xFFF2, fabricId=2).NewController(nodeId=case.nodeId + 1)
        window = await self.open_commissioning_window()
        target = node + 1

        async def rediscover():
            devices = await peer.DiscoverCommissionableNodes(
                filterType=Discovery.FilterType.LONG_DISCRIMINATOR,
                filter=window.randomDiscriminator, stopOnFirst=False, timeoutSecond=3)
            asserts.assert_true(any(d.commissioningMode == 2 and d.longDiscriminator == window.randomDiscriminator
                                    for d in devices), 'Enhanced window disappeared after rollback')
            await peer.FindOrEstablishPASESession(setupCode=window.commissioningParameters.setupQRCode, nodeId=target)
            for attr, expected in initial.items():
                asserts.assert_equal(await read(peer, target, attr), expected)
                asserts.assert_equal(await read(case, node, attr), expected)
            asserts.assert_equal(await read(case, node, ac.Attributes.WindowStatus, ac),
                                 ac.Enums.CommissioningWindowStatusEnum.kEnhancedWindowOpen)

        try:
            await rediscover()
            for expiry in (120, 1):
                response = await peer.SendCommand(target, 0, gc.Commands.ArmFailSafe(expiryLengthSeconds=expiry))
                asserts.assert_equal(response.errorCode, gc.Enums.CommissioningErrorEnum.kOk)
                if expiry == 120:
                    csr = await peer.SendCommand(target, 0, oc.Commands.CSRRequest(CSRNonce=bytes(range(32))))
                    certs = await peer.IssueNOCChain(csr, target)
                    await peer.SendCommand(target, 0, oc.Commands.AddTrustedRootCertificate(certs.rcacBytes))
                    response = await peer.SendCommand(target, 0, oc.Commands.AddNOC(
                        NOCValue=certs.nocBytes, ICACValue=certs.icacBytes, IPKValue=certs.ipkBytes,
                        caseAdminSubject=peer.nodeId, adminVendorId=0xFFF2))
                    asserts.assert_equal(response.statusCode, oc.Enums.NodeOperationalCertStatusEnum.kOk)
                    response = await peer.SendCommand(target, 0, gc.Commands.ArmFailSafe(expiryLengthSeconds=0))
                    asserts.assert_equal(response.errorCode, gc.Enums.CommissioningErrorEnum.kOk)
                else:
                    await asyncio.sleep(2)
                peer.ExpireSessions(target)
                await rediscover()
                logging.info('PASS %s: same discriminator/CM2, fresh PASE, rollback lists, original CASE',
                             'AddNOC + ArmFailSafe(0)' if expiry == 120 else 'natural fail-safe expiry')
            # Exercise Revoke while a PASE fail-safe is armed: original CASE must survive.
            response = await peer.SendCommand(target, 0, gc.Commands.ArmFailSafe(expiryLengthSeconds=120))
            asserts.assert_equal(response.errorCode, gc.Enums.CommissioningErrorEnum.kOk)
            await case.SendCommand(node, 0, ac.Commands.RevokeCommissioning(), timedRequestTimeoutMs=6000)
            asserts.assert_equal(await read(case, node, ac.Attributes.WindowStatus, ac),
                                 ac.Enums.CommissioningWindowStatusEnum.kWindowNotOpen)
            devices = await peer.DiscoverCommissionableNodes(
                filterType=Discovery.FilterType.LONG_DISCRIMINATOR,
                filter=window.randomDiscriminator, stopOnFirst=False, timeoutSecond=3)
            asserts.assert_false(any(d.commissioningMode == 2 and d.longDiscriminator == window.randomDiscriminator
                                     for d in devices), 'Revoked window still advertised')
            for attr, expected in initial.items():
                asserts.assert_equal(await read(case, node, attr), expected)
            logging.info('PASS explicit Revoke: no window/discovery; CASE and committed credentials retained')
        finally:
            peer.Shutdown()


if __name__ == '__main__':
    default_matter_test_main()
