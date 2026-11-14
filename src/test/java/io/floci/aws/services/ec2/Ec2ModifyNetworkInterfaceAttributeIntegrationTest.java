package io.floci.aws.services.ec2;

import io.floci.aws.testing.AwsTestClients;
import io.floci.aws.testing.IamEnforcementProfile;
import io.floci.aws.testing.PartitionCleanup;
import io.quarkus.test.common.http.TestHTTPResource;
import io.quarkus.test.junit.QuarkusTest;
import io.quarkus.test.junit.TestProfile;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.RegisterExtension;
import software.amazon.awssdk.regions.Region;
import software.amazon.awssdk.services.ec2.Ec2Client;
import software.amazon.awssdk.services.ec2.model.Ec2Exception;
import software.amazon.awssdk.services.ec2.model.NetworkInterface;

import java.net.URI;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

@QuarkusTest
@TestProfile(IamEnforcementProfile.class)
class Ec2ModifyNetworkInterfaceAttributeIntegrationTest {
    @TestHTTPResource("/")
    URI endpoint;
    @RegisterExtension
    final PartitionCleanup cleanup = new PartitionCleanup();

    @Test
    void editsStandaloneInterfaceAndPreservesItWhenTerminationDeletionIsDisabled() {
        try (Ec2Client client = AwsTestClients.create(Ec2Client.builder(), "000000000000", Region.US_EAST_1, endpoint)) {
            String vpc = client.createVpc(r -> r.cidrBlock("10.204.0.0/16")).vpc().vpcId();
            String subnet = client.createSubnet(r -> r.vpcId(vpc).cidrBlock("10.204.1.0/24")).subnet().subnetId();
            String group = client.createSecurityGroup(r -> r.vpcId(vpc).groupName("modified-interface")
                    .description("test")).groupId();
            String eni = client.createNetworkInterface(r -> r.subnetId(subnet).description("before"))
                    .networkInterface().networkInterfaceId();
            String instance = client.runInstances(r -> r.subnetId(subnet).imageId("ami-0abcdef1234567891")
                    .instanceType("t3.micro").minCount(1).maxCount(1)).instances().getFirst().instanceId();
            try {
                client.modifyNetworkInterfaceAttribute(r -> r.networkInterfaceId(eni).description(v -> v.value("after")));
                assertEquals("after", read(client, eni).description());
                assertEquals("DryRunOperation", assertThrows(Ec2Exception.class, () -> client
                        .modifyNetworkInterfaceAttribute(r -> r.networkInterfaceId(eni).dryRun(true)
                                .sourceDestCheck(v -> v.value(false)))).awsErrorDetails().errorCode());
                assertTrue(read(client, eni).sourceDestCheck());
                client.modifyNetworkInterfaceAttribute(r -> r.networkInterfaceId(eni).sourceDestCheck(v -> v.value(false)));
                assertFalse(read(client, eni).sourceDestCheck());
                client.modifyNetworkInterfaceAttribute(r -> r.networkInterfaceId(eni).groups(group));
                assertEquals(group, read(client, eni).groups().getFirst().groupId());
                assertThrows(Ec2Exception.class, () -> client.modifyNetworkInterfaceAttribute(r -> r
                        .networkInterfaceId(eni).groups("sg-00000000000000000")));
                assertEquals(group, read(client, eni).groups().getFirst().groupId());
                assertThrows(Ec2Exception.class, () -> client.modifyNetworkInterfaceAttribute(r -> r
                        .networkInterfaceId(eni).description(v -> v.value("bad")).sourceDestCheck(v -> v.value(true))));
                assertEquals("after", read(client, eni).description());
                assertFalse(read(client, eni).sourceDestCheck());
                client.describeInstances(r -> r.instanceIds(instance));
                String attachment = client.attachNetworkInterface(r -> r.networkInterfaceId(eni).instanceId(instance)
                        .deviceIndex(1)).attachmentId();
                assertThrows(Ec2Exception.class, () -> client.modifyNetworkInterfaceAttribute(r -> r
                        .networkInterfaceId(eni).attachment(a -> a.attachmentId("eni-attach-missing").deleteOnTermination(true))));
                assertFalse(read(client, eni).attachment().deleteOnTermination());
                assertEquals("DryRunOperation", assertThrows(Ec2Exception.class, () -> client
                        .modifyNetworkInterfaceAttribute(r -> r.networkInterfaceId(eni).dryRun(true)
                                .attachment(a -> a.attachmentId(attachment).deleteOnTermination(true))))
                        .awsErrorDetails().errorCode());
                assertFalse(read(client, eni).attachment().deleteOnTermination());
                client.modifyNetworkInterfaceAttribute(r -> r.networkInterfaceId(eni)
                        .attachment(a -> a.attachmentId(attachment).deleteOnTermination(true)));
                assertTrue(read(client, eni).attachment().deleteOnTermination());
                client.modifyNetworkInterfaceAttribute(r -> r.networkInterfaceId(eni)
                        .attachment(a -> a.attachmentId(attachment).deleteOnTermination(false)));
                assertFalse(client.describeInstances(r -> r.instanceIds(instance)).reservations().getFirst()
                        .instances().getFirst().networkInterfaces().stream().filter(n -> eni.equals(n.networkInterfaceId()))
                        .findFirst().orElseThrow().attachment().deleteOnTermination());
                client.terminateInstances(r -> r.instanceIds(instance));
                assertEquals("available", read(client, eni).statusAsString());
            } finally {
                client.terminateInstances(r -> r.instanceIds(instance));
                client.deleteNetworkInterface(r -> r.networkInterfaceId(eni));
                client.deleteSecurityGroup(r -> r.groupId(group));
                client.deleteSubnet(r -> r.subnetId(subnet));
                client.deleteVpc(r -> r.vpcId(vpc));
            }
        }
    }

    @Test
    void launchCreatedPrimaryInterfaceCanBeRetainedOnTermination() {
        try (Ec2Client client = AwsTestClients.create(Ec2Client.builder(), "000000000000", Region.US_EAST_1, endpoint)) {
            String instance = client.runInstances(r -> r.imageId("ami-0abcdef1234567891").instanceType("t3.micro")
                    .minCount(1).maxCount(1)).instances().getFirst().instanceId();
            String eni = client.describeInstances(r -> r.instanceIds(instance)).reservations().getFirst()
                    .instances().getFirst().networkInterfaces().getFirst().networkInterfaceId();
            String attachment = read(client, eni).attachment().attachmentId();
            try {
                client.modifyNetworkInterfaceAttribute(r -> r.networkInterfaceId(eni).sourceDestCheck(v -> v.value(false)));
                assertFalse(read(client, eni).sourceDestCheck());
                client.modifyNetworkInterfaceAttribute(r -> r.networkInterfaceId(eni)
                        .attachment(a -> a.attachmentId(attachment).deleteOnTermination(false)));
                client.terminateInstances(r -> r.instanceIds(instance));
                assertEquals("available", read(client, eni).statusAsString());
                client.deleteNetworkInterface(r -> r.networkInterfaceId(eni));
            } finally {
                client.terminateInstances(r -> r.instanceIds(instance));
            }
        }
    }

    @Test
    void rejectsForeignGroupsAndDeletesAnInterfaceMarkedForTermination() {
        try (Ec2Client client = AwsTestClients.create(Ec2Client.builder(), "000000000000", Region.US_EAST_1, endpoint)) {
            String vpc = client.createVpc(r -> r.cidrBlock("10.208.0.0/16")).vpc().vpcId();
            String subnet = client.createSubnet(r -> r.vpcId(vpc).cidrBlock("10.208.1.0/24")).subnet().subnetId();
            String foreignVpc = client.createVpc(r -> r.cidrBlock("10.209.0.0/16")).vpc().vpcId();
            String group = client.createSecurityGroup(r -> r.vpcId(foreignVpc).groupName("foreign-group")
                    .description("test")).groupId();
            String eni = client.createNetworkInterface(r -> r.subnetId(subnet)).networkInterface().networkInterfaceId();
            String instance = client.runInstances(r -> r.subnetId(subnet).imageId("ami-0abcdef1234567891")
                    .instanceType("t3.micro").minCount(1).maxCount(1)).instances().getFirst().instanceId();
            try {
                NetworkInterface before = read(client, eni);
                assertEquals("InvalidGroup.NotFound", assertThrows(Ec2Exception.class, () -> client
                        .modifyNetworkInterfaceAttribute(r -> r.networkInterfaceId(eni).groups(group)))
                        .awsErrorDetails().errorCode());
                assertEquals(before.groups(), read(client, eni).groups());
                assertEquals("InvalidNetworkInterfaceID.NotFound", assertThrows(Ec2Exception.class, () -> client
                        .modifyNetworkInterfaceAttribute(r -> r.networkInterfaceId("eni-00000000000000000")
                                .description(v -> v.value("missing")))).awsErrorDetails().errorCode());
                client.describeInstances(r -> r.instanceIds(instance));
                String attachment = client.attachNetworkInterface(r -> r.networkInterfaceId(eni).instanceId(instance)
                        .deviceIndex(1)).attachmentId();
                client.modifyNetworkInterfaceAttribute(r -> r.networkInterfaceId(eni)
                        .attachment(a -> a.attachmentId(attachment).deleteOnTermination(true)));
                assertTrue(client.describeInstances(r -> r.instanceIds(instance)).reservations().getFirst()
                        .instances().getFirst().networkInterfaces().stream().filter(n -> eni.equals(n.networkInterfaceId()))
                        .findFirst().orElseThrow().attachment().deleteOnTermination());
                client.terminateInstances(r -> r.instanceIds(instance));
                assertEquals("InvalidNetworkInterfaceID.NotFound", assertThrows(Ec2Exception.class, () -> read(client, eni))
                        .awsErrorDetails().errorCode());
            } finally {
                client.terminateInstances(r -> r.instanceIds(instance));
                client.deleteSecurityGroup(r -> r.groupId(group));
                client.deleteSubnet(r -> r.subnetId(subnet));
                client.deleteVpc(r -> r.vpcId(vpc));
                client.deleteVpc(r -> r.vpcId(foreignVpc));
            }
        }
    }

    private NetworkInterface read(Ec2Client client, String id) {
        return client.describeNetworkInterfaces(r -> r.networkInterfaceIds(id)).networkInterfaces().getFirst();
    }
}
