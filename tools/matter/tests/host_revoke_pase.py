"""Local Core 1.6.1 section 11.19.8.3 regression, NOT an official CSA case.

Run with the pinned TH Python SDK and a disposable commissioned host. A PASE
RevokeCommissioning caller must not expect a response. Check the consequences
over an independent CASE controller; a timeout alone is never a passing test.
"""
import logging

from mobly import asserts
import matter.clusters as Clusters
from matter.exceptions import ChipStackError
from matter.interaction_model import InteractionModelError, Status
from matter.testing.decorators import async_test_body
from matter.testing.matter_testing import MatterBaseTest
from matter.testing.runner import default_matter_test_main


class RevokePase(MatterBaseTest):
    @async_test_body
    async def test_revoke_pase(self):
        ac = Clusters.AdministratorCommissioning
        gc = Clusters.GeneralCommissioning
        oc = Clusters.OperationalCredentials
        case = self.default_controller
        admin = self.certificate_authority_manager.activeCaList[0].adminList[0]
        pase_node = self.dut_node_id + 1

        async def read(cluster, attribute):
            return await self.read_single_attribute_check_success(
                dev_ctrl=case, cluster=cluster, attribute=attribute, endpoint=0)

        async def disconnected(operation):
            try:
                await operation
            except ChipStackError as error:
                asserts.assert_in(error.err, (50, 72), 'Expected timeout/not-connected')
            else:
                asserts.fail('Revoked PASE unexpectedly returned a response')

        roots = await read(oc, oc.Attributes.TrustedRootCertificates)
        count = await read(oc, oc.Attributes.CommissionedFabrics)
        # Revoke by CASE must reply; revoke by PASE terminates its own session.
        for over_pase in (False, True):
            window = await self.open_commissioning_window()
            peer = admin.NewController(
                nodeId=self.matter_test_config.controller_node_id + 1,
                paaTrustStorePath=str(self.matter_test_config.paa_trust_store_path))
            try:
                await peer.FindOrEstablishPASESession(
                    setupCode=window.commissioningParameters.setupQRCode, nodeId=pase_node)
                response = await peer.SendCommand(pase_node, 0, gc.Commands.ArmFailSafe(
                    expiryLengthSeconds=900, breadcrumb=123))
                asserts.assert_equal(response.errorCode, gc.Enums.CommissioningErrorEnum.kOk)
                asserts.assert_equal(await read(gc, gc.Attributes.Breadcrumb), 123)
                await peer.SendCommand(pase_node, 0, oc.Commands.CSRRequest(CSRNonce=bytes(range(32))))
                revoke = (peer if over_pase else case).SendCommand(
                    pase_node if over_pase else self.dut_node_id, 0,
                    ac.Commands.RevokeCommissioning(), timedRequestTimeoutMs=6000)
                if over_pase:
                    await disconnected(revoke)
                else:
                    await revoke
                # A lost packet or dead node cannot pass these independent checks.
                asserts.assert_equal(await read(ac, ac.Attributes.WindowStatus),
                                     ac.Enums.CommissioningWindowStatusEnum.kWindowNotOpen)
                asserts.assert_equal(await read(gc, gc.Attributes.Breadcrumb), 0)
                asserts.assert_equal(await read(oc, oc.Attributes.CommissionedFabrics), count)
                asserts.assert_equal(await read(oc, oc.Attributes.TrustedRootCertificates), roots)
                await disconnected(peer.ReadAttribute(pase_node, [(0, Clusters.BasicInformation.Attributes.VendorName)]))
                # The PASE-owned fail-safe really was released, not just hidden.
                response = await case.SendCommand(self.dut_node_id, 0, gc.Commands.ArmFailSafe(expiryLengthSeconds=60))
                asserts.assert_equal(response.errorCode, gc.Enums.CommissioningErrorEnum.kOk)
                response = await case.SendCommand(self.dut_node_id, 0, gc.Commands.ArmFailSafe(expiryLengthSeconds=0))
                asserts.assert_equal(response.errorCode, gc.Enums.CommissioningErrorEnum.kOk)
                logging.info('PASS revoke via %s: closed window, cleared breadcrumb/fail-safe, retired PASE, intact CASE/fabric/root',
                             'PASE' if over_pase else 'CASE')
            finally:
                peer.Shutdown()
        # Closed-window status still has to reach a CASE caller.
        try:
            await case.SendCommand(self.dut_node_id, 0, ac.Commands.RevokeCommissioning(), timedRequestTimeoutMs=6000)
        except InteractionModelError as error:
            asserts.assert_equal(error.status, Status.Failure)
            asserts.assert_equal(error.clusterStatus, 4)
        else:
            asserts.fail('Expected WindowNotOpen')
        # Reopening after cleanup must work (and then close cleanly over CASE).
        await self.open_commissioning_window()
        await case.SendCommand(self.dut_node_id, 0, ac.Commands.RevokeCommissioning(), timedRequestTimeoutMs=6000)
        logging.info('PASS closed-window status and reopening after PASE revocation')


if __name__ == '__main__':
    default_matter_test_main()
