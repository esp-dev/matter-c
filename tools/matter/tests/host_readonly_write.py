"""Local SDK read-only Write regression, separate from official CSA results.

PASE before/after AddNOC and CASE, empty/full/chunked lists, scalar attributes,
unchanged values, a legitimate scalar write, and fail-safe rollback.
"""
import logging

from mobly import asserts
import matter.clusters as Clusters
from matter.interaction_model import Status
from matter.testing.decorators import async_test_body
from matter.testing.matter_testing import MatterBaseTest
from matter.testing.runner import default_matter_test_main


class ReadonlyWrite(MatterBaseTest):
    @async_test_body
    async def test_readonly_write(self):
        oc = Clusters.OperationalCredentials
        gc = Clusters.GeneralCommissioning
        basic = Clusters.BasicInformation
        case, node = self.default_controller, self.dut_node_id

        async def read(ctrl, target, attr, cluster=oc):
            return await self.read_single_attribute_check_success(
                dev_ctrl=ctrl, node_id=target, cluster=cluster, attribute=attr,
                endpoint=0, fabric_filtered=False)

        async def reject(ctrl, target, attr, value, expected=Status.UnsupportedWrite):
            result = await ctrl.WriteAttribute(target, [(0, attr(value))])
            asserts.assert_true(result, 'Missing per-path WriteResponse')
            for item in result:
                asserts.assert_equal(item.Status, expected)
                asserts.assert_equal(item.Path.EndpointId, 0)
                asserts.assert_equal(item.Path.AttributeId, attr.attribute_id)

        async def check(ctrl, target, label):
            for attr in (oc.Attributes.NOCs, oc.Attributes.Fabrics, oc.Attributes.TrustedRootCertificates):
                before = await read(ctrl, target, attr)
                for value in ([], before):
                    await reject(ctrl, target, attr, value)
                    asserts.assert_equal(await read(ctrl, target, attr), before)
                if attr == oc.Attributes.TrustedRootCertificates:
                    # Three maximal RCACs force SDK list chunking/multiple IBs.
                    await reject(ctrl, target, attr, [before[0]] * 3)
                    asserts.assert_equal(await read(ctrl, target, attr), before)
            before = await read(ctrl, target, oc.Attributes.SupportedFabrics)
            await reject(ctrl, target, oc.Attributes.SupportedFabrics, before)
            asserts.assert_equal(await read(ctrl, target, oc.Attributes.SupportedFabrics), before)
            logging.info('PASS %s read-only empty/full/chunked lists and scalar; values unchanged', label)

        initial = {a: await read(case, node, a) for a in
                   (oc.Attributes.NOCs, oc.Attributes.Fabrics, oc.Attributes.TrustedRootCertificates)}
        await check(case, node, 'CASE')
        ca = self.certificate_authority_manager.NewCertificateAuthority(maximizeCertChains=True)
        peer = ca.NewFabricAdmin(vendorId=0xFFF2, fabricId=2).NewController(nodeId=case.nodeId + 1)
        window = await self.open_commissioning_window()
        target = node + 1
        try:
            await peer.FindOrEstablishPASESession(setupCode=window.commissioningParameters.setupQRCode, nodeId=target)
            await check(peer, target, 'PASE before AddNOC')
            await reject(peer, target, Clusters.AccessControl.Attributes.Acl, [], Status.UnsupportedAccess)
            # Existing legal PASE scalar writes still work and are restored.
            original_label = await read(peer, target, basic.Attributes.NodeLabel, basic)
            try:
                result = await peer.WriteAttribute(target, [(0, basic.Attributes.NodeLabel('TH02e'))])
                asserts.assert_equal(result[0].Status, Status.Success)
                asserts.assert_equal(await read(peer, target, basic.Attributes.NodeLabel, basic), 'TH02e')
            finally:
                result = await peer.WriteAttribute(target, [(0, basic.Attributes.NodeLabel(original_label))])
                asserts.assert_equal(result[0].Status, Status.Success)
            response = await peer.SendCommand(target, 0, gc.Commands.ArmFailSafe(expiryLengthSeconds=120))
            asserts.assert_equal(response.errorCode, gc.Enums.CommissioningErrorEnum.kOk)
            csr = await peer.SendCommand(target, 0, oc.Commands.CSRRequest(CSRNonce=bytes(range(32))))
            certs = await peer.IssueNOCChain(csr, target)
            await peer.SendCommand(target, 0, oc.Commands.AddTrustedRootCertificate(certs.rcacBytes))
            response = await peer.SendCommand(target, 0, oc.Commands.AddNOC(
                NOCValue=certs.nocBytes, ICACValue=certs.icacBytes, IPKValue=certs.ipkBytes,
                caseAdminSubject=peer.nodeId, adminVendorId=0xFFF2))
            asserts.assert_equal(response.statusCode, oc.Enums.NodeOperationalCertStatusEnum.kOk)
            await check(peer, target, 'PASE after AddNOC')
        finally:
            try:
                await case.SendCommand(node, 0, Clusters.AdministratorCommissioning.Commands.RevokeCommissioning(),
                                       timedRequestTimeoutMs=6000)
            finally:
                peer.Shutdown()
        for attr, value in initial.items():
            asserts.assert_equal(await read(case, node, attr), value)
        logging.info('PASS write access denial, valid scalar write/restore, AddNOC and rollback; CASE usable')


if __name__ == '__main__':
    default_matter_test_main()
