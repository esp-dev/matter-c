"""Local SDK regression for RCAC admission, not an official CSA test.

Commission a disposable node first. Corrupted self-signature and signed serial
number must fail without changing roots; a valid retry and rollback work.
Run once with PASE and once with CASE on the same instance.
"""
import logging

from mobly import asserts
import matter.clusters as Clusters
from matter.interaction_model import InteractionModelError, Status
from matter.testing.decorators import async_test_body
from matter.testing.matter_testing import MatterBaseTest
from matter.testing.runner import default_matter_test_main
from matter.tlv import TLVReader, TLVWriter


class RootAdmission(MatterBaseTest):
    @async_test_body
    async def test_root_admission(self):
        oc = Clusters.OperationalCredentials
        gc = Clusters.GeneralCommissioning
        case, node = self.default_controller, self.dut_node_id

        async def roots(ctrl, target):
            return await self.read_single_attribute_check_success(
                dev_ctrl=ctrl, node_id=target, cluster=oc,
                attribute=oc.Attributes.TrustedRootCertificates, endpoint=0)

        original = await roots(case, node)
        ca = self.certificate_authority_manager.NewCertificateAuthority(maximizeCertChains=True)
        peer = ca.NewFabricAdmin(vendorId=0xFFF2, fabricId=2).NewController(nodeId=case.nodeId + 1)
        try:
            for use_pase in (True, False):
                if use_pase:
                    window = await self.open_commissioning_window()
                    target, ctrl = node + 1, peer
                    await peer.FindOrEstablishPASESession(
                        setupCode=window.commissioningParameters.setupQRCode, nodeId=target)
                else:
                    target, ctrl = node, case
                try:
                    response = await ctrl.SendCommand(target, 0, gc.Commands.ArmFailSafe(expiryLengthSeconds=120))
                    asserts.assert_equal(response.errorCode, gc.Enums.CommissioningErrorEnum.kOk)
                    csr = await ctrl.SendCommand(target, 0, oc.Commands.CSRRequest(CSRNonce=bytes(range(32))))
                    certs = await peer.IssueNOCChain(csr, node + 1)
                    for change in ('signature_r', 'signature_s', 'serial'):
                        decoded = TLVReader(certs.rcacBytes).get()['Any']
                        tag = 1 if change == 'serial' else 11
                        value = bytearray(decoded[tag])
                        value[32 if change == 'signature_s' else 0] ^= 1
                        decoded[tag] = bytes(value)
                        writer = TLVWriter(bytearray())
                        writer.put(None, decoded)
                        try:
                            await ctrl.SendCommand(target, 0, oc.Commands.AddTrustedRootCertificate(bytes(writer.encoding)))
                        except InteractionModelError as error:
                            asserts.assert_equal(error.status, Status.InvalidCommand)
                        else:
                            asserts.fail('Accepted corrupted RCAC: ' + change)
                        asserts.assert_equal(await roots(ctrl, target), original)
                    await ctrl.SendCommand(target, 0, oc.Commands.AddTrustedRootCertificate(certs.rcacBytes))
                    accepted = await roots(ctrl, target)
                    asserts.assert_equal(len(accepted), len(original) + 1)
                    asserts.assert_in(certs.rcacBytes, accepted)
                    # An identical root is idempotent, including after negative retries.
                    await ctrl.SendCommand(target, 0, oc.Commands.AddTrustedRootCertificate(certs.rcacBytes))
                    asserts.assert_equal(await roots(ctrl, target), accepted)
                    logging.info('PASS %s RCAC r/s/TBS rejection, no root mutation, valid retry/idempotence',
                                 'PASE' if use_pase else 'CASE')
                finally:
                    if use_pase:
                        await case.SendCommand(node, 0, Clusters.AdministratorCommissioning.Commands.RevokeCommissioning(),
                                               timedRequestTimeoutMs=6000)
                    else:
                        response = await case.SendCommand(node, 0, gc.Commands.ArmFailSafe(expiryLengthSeconds=0))
                        asserts.assert_equal(response.errorCode, gc.Enums.CommissioningErrorEnum.kOk)
                asserts.assert_equal(await roots(case, node), original)
                logging.info('PASS rollback: original roots restored, CASE usable')
        finally:
            peer.Shutdown()


if __name__ == '__main__':
    default_matter_test_main()
