"""Local Core 1.6.1 ACL privacy/identifier regression; not a CSA result.

Use a disposable commissioned host and --no-wildcard-subscription. Creates a
second fabric, checks raw Read TLV and decoded Subscribe, rejects reserved target
IDs without changing grants, removes the second fabric and optionally the last
fabric (--int-arg remove:1) for normal node shutdown.
"""
import logging

from mobly import asserts
from matter import ChipDeviceCtrl
import matter.clusters as C
from matter.clusters.Types import NullValue
from matter.interaction_model import Status
from matter.testing.decorators import async_test_body
from matter.testing.matter_testing import MatterBaseTest
from matter.testing.runner import default_matter_test_main


class AclPrivacy(MatterBaseTest):
    @async_test_body
    async def test_acl_privacy(self):
        acl, oc = C.AccessControl, C.OperationalCredentials
        case, node = self.default_controller, self.dut_node_id

        async def read(ctrl, attr, cluster=acl):
            return await self.read_single_attribute_check_success(
                dev_ctrl=ctrl, endpoint=0, cluster=cluster, attribute=attr)

        original = await read(case, acl.Attributes.Acl)
        own = await read(case, oc.Attributes.CurrentFabricIndex, oc)
        asserts.assert_equal(await read(case, oc.Attributes.CommissionedFabrics, oc), 1,
                             'Use a disposable single-fabric fixture')
        events = await case.ReadEvent(node, events=[(0, acl.Events.AccessControlEntryChanged)], fabricFiltered=True)
        watermark = max(e.Header.EventNumber for e in events)
        response = await case.WriteAttribute(node, [(0, acl.Attributes.Acl(original))])
        asserts.assert_equal(response[0].Status, Status.Success)
        events = await case.ReadEvent(node, events=[(0, acl.Events.AccessControlEntryChanged)],
                                      fabricFiltered=True, eventNumberFilter=watermark+1)
        asserts.assert_equal(len(events), len(original), 'REPLACE must report retained entries as Changed')
        for event in events:
            asserts.assert_equal(event.Data.changeType, acl.Enums.ChangeTypeEnum.kChanged)
            asserts.assert_equal(event.Data.adminNodeID, case.nodeId)
        logging.info('PASS equal ACL replacement emits Changed')
        ca = self.certificate_authority_manager.NewCertificateAuthority()
        peer = ca.NewFabricAdmin(vendorId=0xFFF2, fabricId=2).NewController(nodeId=case.nodeId+7)
        window = await self.open_commissioning_window()
        await peer.CommissionOnNetwork(nodeId=node, setupPinCode=window.commissioningParameters.setupPinCode,
                                      filterType=ChipDeviceCtrl.DiscoveryFilterType.LONG_DISCRIMINATOR,
                                      filter=window.randomDiscriminator)
        foreign = await read(peer, oc.Attributes.CurrentFabricIndex, oc)
        try:
            for ctrl, accessing, other in ((case, own, foreign), (peer, foreign, own)):
                result = await ctrl.Read(node, attributes=[(0, acl.Attributes.Acl)], fabricFiltered=False)
                entries = result.tlvAttributes[0][acl.id][acl.Attributes.Acl.attribute_id]
                hidden = [e for e in entries if e[254] == other]
                visible = [e for e in entries if e[254] == accessing]
                asserts.assert_equal(len(hidden), 1)
                asserts.assert_equal(hidden[0], {254: other}, 'Foreign fields must be OMITTED from TLV')
                asserts.assert_equal(len(visible), 1)
                asserts.assert_equal(visible[0][3], [ctrl.nodeId])
                sub = await ctrl.ReadAttribute(node, [(0, acl.Attributes.Acl)], fabricFiltered=False,
                                               reportInterval=(0, 5), keepSubscriptions=False, autoResubscribe=False)
                try:
                    values = sub.GetAttributes()[0][acl][acl.Attributes.Acl]
                    hidden = [e for e in values if e.fabricIndex == other]
                    asserts.assert_equal(len(hidden), 1)
                    asserts.assert_equal(hidden[0].privilege, 0)
                    asserts.assert_equal(hidden[0].authMode, 0)
                    asserts.assert_true(hidden[0].subjects in (None, NullValue, []), 'Foreign subjects leaked')
                    asserts.assert_true(hidden[0].targets in (None, NullValue), 'Foreign targets leaked')
                finally:
                    sub.Shutdown()
            logging.info('PASS both fabrics: raw TLV omission and Subscribe privacy')
            for field, ids in (
                ('cluster', [0x8000, 0xfc00, 0x0001fbff, 0xfff4ffff, 0xfff5fc00, 0xffffffff]),
                ('endpoint', [0xffff]),
                ('deviceType', [0xc000, 0xfff50000, 0xffffffff]),
            ):
                for value in ids:
                    target = acl.Structs.AccessControlTargetStruct(**{field: value})
                    invalid = acl.Structs.AccessControlEntryStruct(privilege=1, authMode=2,
                                                                  subjects=[case.nodeId], targets=[target])
                    response = await case.WriteAttribute(node, [(0, acl.Attributes.Acl(original+[invalid]))])
                    asserts.assert_equal(response[0].Status, Status.ConstraintError, f'{field}={value:x}')
                    asserts.assert_equal(await read(case, acl.Attributes.Acl), original, 'Rejected write changed ACL')
            # Valid identifiers need not correspond to an installed cluster/type/endpoint.
            targets = [acl.Structs.AccessControlTargetStruct(cluster=0xfff4fffe),
                       acl.Structs.AccessControlTargetStruct(endpoint=0xfffe),
                       acl.Structs.AccessControlTargetStruct(deviceType=0xfff4bfff)]
            entry = acl.Structs.AccessControlEntryStruct(privilege=1, authMode=2, subjects=[999], targets=targets)
            response = await case.WriteAttribute(node, [(0, acl.Attributes.Acl(original+[entry]))])
            asserts.assert_equal(response[0].Status, Status.Success)
            actual = await read(case, acl.Attributes.Acl)
            asserts.assert_equal(actual[-1].targets, targets)
            logging.info('PASS invalid target IDs rejected atomically, valid boundary IDs retained')
            response = await case.TestOnlyWriteAttributeWithLegacyList(node, [(0, acl.Attributes.Acl(original))])
            asserts.assert_true(response, 'Missing legacy WriteResponse')
            for item in response:
                asserts.assert_equal(item.Status, Status.Success)
            asserts.assert_equal(await read(case, acl.Attributes.Acl), original)
            logging.info('PASS legacy clear+append ACL replacement preserves administrator')
            invalid_group = acl.Structs.AccessControlEntryStruct(privilege=3, authMode=3, subjects=[0])
            response = await case.TestOnlyWriteAttributeWithLegacyList(node, [(0, acl.Attributes.Acl(original+[invalid_group]))])
            statuses = [item.Status for item in response]
            asserts.assert_equal(statuses, [Status.Success, Status.Success, Status.ConstraintError],
                                 'Each legacy IB must report its own outcome, in order')
            asserts.assert_equal(await read(case, acl.Attributes.Acl), original)
            logging.info('PASS legacy invalid Group0 statuses %s; valid prefix retained', statuses)
        finally:
            response = await case.WriteAttribute(node, [(0, acl.Attributes.Acl(original))])
            asserts.assert_equal(response[0].Status, Status.Success)
            response = await case.SendCommand(node, 0, oc.Commands.RemoveFabric(fabricIndex=foreign))
            asserts.assert_equal(response.statusCode, 0)
        asserts.assert_equal(await read(case, oc.Attributes.CommissionedFabrics, oc), 1)
        if self.user_params.get('remove', 0):
            response = await case.SendCommand(node, 0, oc.Commands.RemoveFabric(fabricIndex=own))
            asserts.assert_equal(response.statusCode, 0)
            logging.info('PASS last fabric removed; verify normal shutdown and memory logs separately')


if __name__ == '__main__':
    default_matter_test_main()
