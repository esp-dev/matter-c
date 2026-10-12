"""Normative root/fail-safe regression on a complete host; NOT a CSA test.

Core 1.6.1 11.18.5.5/11.18.6.13 and 11.10.7.2: distinguish duplicate
RCAC from a genuinely different issuer, check rollback and CASE/PASE ownership.
Keep the SDK wildcard subscription checks enabled.
"""
import asyncio
import hashlib
import logging

from mobly import asserts
import matter.clusters as Clusters
from matter.interaction_model import InteractionModelError, Status
from matter.testing.decorators import async_test_body
from matter.testing.matter_testing import MatterBaseTest
from matter.testing.runner import default_matter_test_main


class GeneralCommissioning(MatterBaseTest):
    @async_test_body
    async def test_root_failsafe(self):
        oc, gc, ac = Clusters.OperationalCredentials, Clusters.GeneralCommissioning, Clusters.AdministratorCommissioning
        case, node = self.default_controller, self.dut_node_id

        async def read(attr, cluster=oc):
            return await self.read_single_attribute_check_success(cluster=cluster, attribute=attr, endpoint=0, fabric_filtered=False)

        async def send(cmd):
            return await case.SendCommand(node, 0, cmd)

        async def reject(cmd, expected):
            try:
                await send(cmd)
            except InteractionModelError as error:
                asserts.assert_equal(error.status, expected)
            else:
                asserts.fail(f'Expected {expected}')

        async def arm(seconds, breadcrumb=0):
            r = await send(gc.Commands.ArmFailSafe(expiryLengthSeconds=seconds, breadcrumb=breadcrumb))
            asserts.assert_equal(r.errorCode, gc.Enums.CommissioningErrorEnum.kOk)

        roots = await read(oc.Attributes.TrustedRootCertificates)
        fabrics = await read(oc.Attributes.Fabrics)
        await reject(oc.Commands.AddTrustedRootCertificate(roots[0]), Status.FailsafeRequired)
        await arm(60, 11)
        csr = await send(oc.Commands.CSRRequest(CSRNonce=bytes(range(32))))
        same_issuer = await case.IssueNOCChain(csr, node)
        logging.info('ISSUER reused_rcac=%s stored_sha256=%s issued_sha256=%s',
                     same_issuer.rcacBytes in roots, hashlib.sha256(roots[0]).hexdigest(),
                     hashlib.sha256(same_issuer.rcacBytes).hexdigest())
        await send(oc.Commands.AddTrustedRootCertificate(roots[0]))
        await send(oc.Commands.AddTrustedRootCertificate(roots[0]))
        asserts.assert_equal(await read(oc.Attributes.TrustedRootCertificates), roots, 'Identical RCAC must not add an entry')
        await arm(0)
        await asyncio.sleep(0.2)
        asserts.assert_equal(await read(gc.Attributes.Breadcrumb, gc), 0)
        logging.info('PASS identical root: success without duplicate; zero-expiry rollback')

        ca = self.certificate_authority_manager.NewCertificateAuthority(maximizeCertChains=True)
        peer = ca.NewFabricAdmin(vendorId=0xFFF2, fabricId=2).NewController(nodeId=case.nodeId + 1)
        try:
            for natural in (False, True):
                await arm(60, 21)
                csr = await send(oc.Commands.CSRRequest(CSRNonce=bytes(range(32))))
                chain = await peer.IssueNOCChain(csr, node + 1)
                asserts.assert_not_in(chain.rcacBytes, roots, 'Test precondition: genuinely different RCAC')
                corrupt = bytearray(chain.rcacBytes)
                corrupt[-2] ^= 1
                await reject(oc.Commands.AddTrustedRootCertificate(bytes(corrupt)), Status.InvalidCommand)
                asserts.assert_equal(await read(oc.Attributes.TrustedRootCertificates), roots)
                await send(oc.Commands.AddTrustedRootCertificate(chain.rcacBytes))
                asserts.assert_equal(await read(oc.Attributes.TrustedRootCertificates), roots + [chain.rcacBytes])
                await send(oc.Commands.AddTrustedRootCertificate(chain.rcacBytes))
                asserts.assert_equal(await read(oc.Attributes.TrustedRootCertificates), roots + [chain.rcacBytes])
                await arm(1 if natural else 0, 22)
                await asyncio.sleep(2 if natural else 0.2)
                asserts.assert_equal(await read(oc.Attributes.TrustedRootCertificates), roots)
                asserts.assert_equal(await read(oc.Attributes.Fabrics), fabrics)
                asserts.assert_equal(await read(gc.Attributes.Breadcrumb, gc), 0)
                logging.info('PASS different root: signature rejection, immediate visibility, duplicate, rollback natural=%s', natural)

            # CASE SetRegulatoryConfig: valid and unknown enum, no Breadcrumb change on failure.
            response = await send(gc.Commands.SetRegulatoryConfig(newRegulatoryConfig=0, countryCode='PL', breadcrumb=33))
            asserts.assert_equal(response.errorCode, gc.Enums.CommissioningErrorEnum.kOk)
            unknown = gc.Enums.RegulatoryLocationTypeEnum.extend_enum_if_value_doesnt_exist(3)
            response = await send(gc.Commands.SetRegulatoryConfig(newRegulatoryConfig=unknown, countryCode='DE', breadcrumb=99))
            asserts.assert_equal(response.errorCode, gc.Enums.CommissioningErrorEnum.kValueOutsideRange)
            asserts.assert_equal(await read(gc.Attributes.Breadcrumb, gc), 33)
            asserts.assert_equal(await read(gc.Attributes.RegulatoryConfig, gc), 0)

            window = await self.open_commissioning_window()
            for seconds in (0, 60):
                response = await send(gc.Commands.ArmFailSafe(expiryLengthSeconds=seconds, breadcrumb=99))
                asserts.assert_equal(response.errorCode, gc.Enums.CommissioningErrorEnum.kBusyWithOtherAdmin)
                asserts.assert_equal(await read(gc.Attributes.Breadcrumb, gc), 33)
            await peer.FindOrEstablishPASESession(setupCode=window.commissioningParameters.setupQRCode, nodeId=node + 1)
            response = await peer.SendCommand(node + 1, 0, gc.Commands.ArmFailSafe(expiryLengthSeconds=60))
            asserts.assert_equal(response.errorCode, gc.Enums.CommissioningErrorEnum.kOk)
            response = await send(gc.Commands.ArmFailSafe(expiryLengthSeconds=0))
            asserts.assert_equal(response.errorCode, gc.Enums.CommissioningErrorEnum.kBusyWithOtherAdmin)
            await case.SendCommand(node, 0, ac.Commands.RevokeCommissioning(), timedRequestTimeoutMs=6000)
            await arm(60)
            await arm(0)
            await asyncio.sleep(0.2)
            response = await send(gc.Commands.CommissioningComplete())
            asserts.assert_equal(response.errorCode, gc.Enums.CommissioningErrorEnum.kNoFailSafe)
            asserts.assert_equal(await read(oc.Attributes.Fabrics), fabrics)
            logging.info('PASS CASE/PASE ownership, window priority, Revoke and NoFailSafe')
        finally:
            peer.Shutdown()


if __name__ == '__main__':
    default_matter_test_main()
