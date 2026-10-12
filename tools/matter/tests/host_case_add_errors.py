"""Local regression, NOT an official CSA case. Run with pinned CHIP Python SDK.

Reuse the controller storage/DUT from TC_OPCREDS_3_2 after its cleanup. Exercise
CASE AddRoot/AddNOC errors and rollback on the complete host application.
"""
from mobly import asserts
import matter.clusters as Clusters
from matter.interaction_model import InteractionModelError, Status
from matter.testing.decorators import async_test_body
from matter.testing.matter_testing import MatterBaseTest
from matter.testing.runner import default_matter_test_main


class CaseAddErrors(MatterBaseTest):
    @async_test_body
    async def test_case_add_errors(self):
        oc = Clusters.OperationalCredentials
        gc = Clusters.GeneralCommissioning

        async def read(attribute):
            return await self.read_single_attribute_check_success(
                cluster=oc, attribute=attribute, endpoint=0)

        async def send(command):
            return await self.default_controller.SendCommand(self.dut_node_id, 0, command)

        async def rejected(command, expected):
            try:
                await send(command)
            except InteractionModelError as error:
                asserts.assert_equal(error.status, expected)
            else:
                asserts.fail(f'Command unexpectedly succeeded; expected {expected}')

        count = await read(oc.Attributes.CommissionedFabrics)
        roots = await read(oc.Attributes.TrustedRootCertificates)
        asserts.assert_equal(count, 1)
        asserts.assert_equal(len(roots), 1)
        await rejected(oc.Commands.AddTrustedRootCertificate(roots[0]), Status.FailsafeRequired)
        response = await send(gc.Commands.ArmFailSafe(expiryLengthSeconds=60))
        asserts.assert_equal(response.errorCode, gc.Enums.CommissioningErrorEnum.kOk)
        try:
            await rejected(oc.Commands.AddTrustedRootCertificate(roots[0][:-1]), Status.InvalidCommand)
            await send(oc.Commands.AddTrustedRootCertificate(roots[0]))
            nocs = await read(oc.Attributes.NOCs)
            response = await send(oc.Commands.AddNOC(
                NOCValue=nocs[0].noc, ICACValue=nocs[0].icac, IPKValue=bytes(16),
                caseAdminSubject=self.default_controller.nodeId, adminVendorId=0xFFF1))
            asserts.assert_equal(response.statusCode, oc.Enums.NodeOperationalCertStatusEnum.kMissingCsr)
        finally:
            response = await send(gc.Commands.ArmFailSafe(expiryLengthSeconds=0))
            asserts.assert_equal(response.errorCode, gc.Enums.CommissioningErrorEnum.kOk)
        asserts.assert_equal(await read(oc.Attributes.CommissionedFabrics), count)
        asserts.assert_equal(await read(oc.Attributes.TrustedRootCertificates), roots)


if __name__ == '__main__':
    default_matter_test_main()
