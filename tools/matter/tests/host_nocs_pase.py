"""Local NOCs/Fabrics filtering regression; not an official CSA test.

Run using the pinned TH Python SDK against a disposable commissioned host.
Exercise PASE before/after AddNOC, independent CASE, access denial and
rollback. A successful unfiltered read must not bypass other access checks.
"""
import logging

from mobly import asserts
import matter.clusters as Clusters
from matter.interaction_model import Status
from matter.testing.decorators import async_test_body
from matter.testing.matter_testing import MatterBaseTest
from matter.testing.runner import default_matter_test_main


class NocsPase(MatterBaseTest):
    @async_test_body
    async def test_nocs_pase(self):
        oc = Clusters.OperationalCredentials
        gc = Clusters.GeneralCommissioning
        case = self.default_controller
        node = self.dut_node_id

        async def read(ctrl, target, attribute, filtered=True):
            return await self.read_single_attribute_check_success(
                dev_ctrl=ctrl, node_id=target, cluster=oc, attribute=attribute,
                endpoint=0, fabric_filtered=filtered)

        initial = {}
        for attr in (oc.Attributes.NOCs, oc.Attributes.Fabrics):
            initial[attr] = await read(case, node, attr, False)
            asserts.assert_equal(len(initial[attr]), 1)
        roots = await read(case, node, oc.Attributes.TrustedRootCertificates)
        original_index = await read(case, node, oc.Attributes.CurrentFabricIndex)
        ca = self.certificate_authority_manager.NewCertificateAuthority(maximizeCertChains=True)
        admin = ca.NewFabricAdmin(vendorId=0xFFF2, fabricId=2)
        peer = admin.NewController(nodeId=case.nodeId + 1)
        window = await self.open_commissioning_window()
        pase_node = node + 1
        try:
            await peer.FindOrEstablishPASESession(
                setupCode=window.commissioningParameters.setupQRCode, nodeId=pase_node)
            asserts.assert_equal(await read(peer, pase_node, oc.Attributes.CurrentFabricIndex), 0)
            for attr in initial:
                asserts.assert_equal(await read(peer, pase_node, attr, False), initial[attr])
                asserts.assert_equal(await read(peer, pase_node, attr, True), [])
            acl = Clusters.AccessControl
            denied = await peer.ReadAttribute(pase_node, [(0, acl.Attributes.Acl)], fabricFiltered=False)
            value = denied[0][acl][acl.Attributes.Acl]
            asserts.assert_equal(value.Reason.status, Status.UnsupportedAccess)
            logging.info('PASS before AddNOC: unfiltered full lists, filtered empty lists, ACL denied')
            response = await peer.SendCommand(pase_node, 0, gc.Commands.ArmFailSafe(expiryLengthSeconds=900))
            asserts.assert_equal(response.errorCode, gc.Enums.CommissioningErrorEnum.kOk)
            csr = await peer.SendCommand(pase_node, 0, oc.Commands.CSRRequest(CSRNonce=bytes(range(32))))
            certs = await peer.IssueNOCChain(csr, pase_node)
            await peer.SendCommand(pase_node, 0, oc.Commands.AddTrustedRootCertificate(certs.rcacBytes))
            response = await peer.SendCommand(pase_node, 0, oc.Commands.AddNOC(
                NOCValue=certs.nocBytes, ICACValue=certs.icacBytes, IPKValue=certs.ipkBytes,
                caseAdminSubject=peer.nodeId, adminVendorId=0xFFF2))
            asserts.assert_equal(response.statusCode, oc.Enums.NodeOperationalCertStatusEnum.kOk)
            index = await read(peer, pase_node, oc.Attributes.CurrentFabricIndex)
            asserts.assert_not_equal(index, 0)
            asserts.assert_not_equal(index, original_index)
            for attr in initial:
                own = await read(peer, pase_node, attr, True)
                full = await read(peer, pase_node, attr, False)
                asserts.assert_equal(len(own), 1)
                asserts.assert_equal(own[0].fabricIndex, index)
                asserts.assert_equal(len(full), 2)
                asserts.assert_equal(await read(case, node, attr, True), initial[attr])
                asserts.assert_equal(await read(case, node, attr, False), full)
            nocs = await read(peer, pase_node, oc.Attributes.NOCs)
            asserts.assert_equal(nocs[0].noc, certs.nocBytes)
            asserts.assert_equal(nocs[0].icac, certs.icacBytes)
            logging.info('PASS after AddNOC: own-only filtered, two unfiltered, CASE isolation, exact NOC/ICAC')
        finally:
            try:
                await case.SendCommand(node, 0, Clusters.AdministratorCommissioning.Commands.RevokeCommissioning(),
                                       timedRequestTimeoutMs=6000)
            finally:
                peer.Shutdown()
        for attr in initial:
            asserts.assert_equal(await read(case, node, attr, False), initial[attr])
        asserts.assert_equal(await read(case, node, oc.Attributes.TrustedRootCertificates), roots)
        logging.info('PASS rollback: initial NOCs/Fabrics/roots restored; CASE remains usable')


if __name__ == '__main__':
    default_matter_test_main()
