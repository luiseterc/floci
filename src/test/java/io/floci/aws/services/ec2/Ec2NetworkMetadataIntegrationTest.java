package io.floci.aws.services.ec2;

import io.floci.aws.config.EmulatorConfig;
import io.floci.aws.services.ec2.model.Instance;
import io.floci.aws.testing.AwsTestClients;
import io.quarkus.test.common.http.TestHTTPResource;
import io.quarkus.test.junit.QuarkusTest;
import jakarta.inject.Inject;
import org.junit.jupiter.api.Test;
import software.amazon.awssdk.regions.Region;
import software.amazon.awssdk.services.ec2.Ec2Client;
import software.amazon.awssdk.services.ec2.model.NetworkInterface;
import software.amazon.awssdk.services.ec2.model.PrivateIpAddressSpecification;

import java.net.URI;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.Mockito.RETURNS_DEEP_STUBS;
import static org.mockito.Mockito.mock;

@QuarkusTest
class Ec2NetworkMetadataIntegrationTest {
    private static final String ACCOUNT = "246813579012";
    private static final Region REGION = Region.EU_WEST_1;
    private static final String PREFIX = "/latest/meta-data/network/interfaces/macs";
    @TestHTTPResource("/")
    URI endpoint;
    @Inject
    Ec2Service service;

    @Test
    void sdkAttachmentsDriveTokenProtectedMetadataAndDetachRemovesIt() throws Exception {
        try (Ec2Client client = AwsTestClients.create(Ec2Client.builder(), ACCOUNT, REGION, endpoint)) {
            String vpc = client.createVpc(r -> r.cidrBlock("10.94.0.0/16")).vpc().vpcId();
            String subnet = null;
            String eni = null;
            String attachment = null;
            List<String> instances = new ArrayList<>();
            try {
                subnet = client.createSubnet(r -> r.vpcId(vpc).cidrBlock("10.94.1.0/24")
                        .availabilityZone("eu-west-1a")).subnet().subnetId();
                String subnetId = subnet;
                String id = client.runInstances(r -> r.imageId("ami-test").instanceType("t3.micro")
                        .minCount(1).maxCount(1).subnetId(subnetId).metadataOptions(o -> o.httpTokens("required")))
                        .instances().getFirst().instanceId();
                instances.add(id);
                assertEquals("running", client.describeInstances(r -> r.instanceIds(id))
                        .reservations().getFirst().instances().getFirst().state().nameAsString());
                Instance instance = service.findInstanceForAccount(ACCOUNT, REGION.id(), id).orElseThrow();
                String primaryMac = instance.getNetworkInterfaces().getFirst().getMacAddress();
                NetworkInterface secondary = client.createNetworkInterface(r -> r.subnetId(subnetId)
                        .privateIpAddress("10.94.1.20").privateIpAddresses(PrivateIpAddressSpecification.builder()
                                .privateIpAddress("10.94.1.21").primary(false).build())).networkInterface();
                eni = secondary.networkInterfaceId();
                String eniId = eni;
                attachment = client.attachNetworkInterface(r -> r.instanceId(id).networkInterfaceId(eniId).deviceIndex(1))
                        .attachmentId();
                String secondaryMac = secondary.macAddress();
                try (Ec2MetadataTestFixture fixture = new Ec2MetadataTestFixture().withEc2(service)) {
                    fixture.start(null, mock(EmulatorConfig.class, RETURNS_DEEP_STUBS), instance);
                    String token = fixture.putToken("60").body();
                    assertEquals(primaryMac, fixture.get("/latest/meta-data/mac", token).body());
                    assertEquals(401, fixture.get(PREFIX, null).statusCode());
                    assertEquals(401, fixture.get(PREFIX + "/", "invalid").statusCode());
                    String listing = fixture.get(PREFIX, token).body();
                    assertTrue(listing.contains(primaryMac + "/"));
                    assertTrue(listing.contains(secondaryMac + "/"));
                    assertEquals(listing, fixture.get(PREFIX + "/", token).body());
                    String path = PREFIX + "/" + secondaryMac;
                    assertTrue(fixture.get(path, token).body().contains("local-ipv4s"));
                    assertEquals(fixture.get(path, token).body(), fixture.get(path + "/", token).body());
                    for (Map.Entry<String, String> field : Map.of(
                            "interface-id", eniId, "device-number", "1", "network-card", "0",
                            "owner-id", ACCOUNT, "subnet-id", subnetId, "vpc-id", vpc,
                            "local-ipv4s", "10.94.1.20\n10.94.1.21", "subnet-ipv4-cidr-block", "10.94.1.0/24",
                            "vpc-ipv4-cidr-blocks", "10.94.0.0/16").entrySet()) {
                        assertEquals(field.getValue(), fixture.get(path + "/" + field.getKey(), token).body(), field.getKey());
                    }
                    assertTrue(fixture.get(path + "/security-group-ids", token).body().startsWith("sg-"));
                    assertEquals(404, fixture.get(path + "/ipv4-prefix", token).statusCode());
                    assertEquals(404, fixture.get(PREFIX + "/00:00:00:00:00:00/interface-id", token).statusCode());
                    String otherId = client.runInstances(r -> r.imageId("ami-test").instanceType("t3.micro")
                            .minCount(1).maxCount(1).subnetId(subnetId)).instances().getFirst().instanceId();
                    instances.add(otherId);
                    Instance other = service.findInstanceForAccount(ACCOUNT, REGION.id(), otherId).orElseThrow();
                    fixture.server().registerContainer(Ec2MetadataTestFixture.CALLER_IP, otherId, other);
                    assertEquals(401, fixture.get(path + "/local-ipv4s", token).statusCode());
                    String otherToken = fixture.putToken("60").body();
                    assertEquals(404, fixture.get(path + "/local-ipv4s", otherToken).statusCode());
                    fixture.server().registerContainer(Ec2MetadataTestFixture.CALLER_IP, id, instance);
                    String attachmentId = attachment;
                    client.detachNetworkInterface(r -> r.attachmentId(attachmentId));
                    attachment = null;
                    assertEquals(404, fixture.get(path + "/local-ipv4s", token).statusCode());
                    assertFalse(fixture.get(PREFIX, token).body().contains(secondaryMac));
                    Instance wrongScope = Ec2MetadataTestFixture.instance(id);
                    wrongScope.setOwnerId("135792468013");
                    wrongScope.setRegion(REGION.id());
                    assertTrue(service.networkMetadata(wrongScope).isEmpty());
                    wrongScope.setOwnerId(ACCOUNT);
                    wrongScope.setRegion("us-east-1");
                    assertTrue(service.networkMetadata(wrongScope).isEmpty());
                }
            } finally {
                if (attachment != null) {
                    String attachmentId = attachment;
                    client.detachNetworkInterface(r -> r.attachmentId(attachmentId));
                }
                if (eni != null) {
                    String eniId = eni;
                    client.deleteNetworkInterface(r -> r.networkInterfaceId(eniId));
                }
                if (!instances.isEmpty()) {
                    client.terminateInstances(r -> r.instanceIds(instances));
                }
                if (subnet != null) {
                    String subnetId = subnet;
                    client.deleteSubnet(r -> r.subnetId(subnetId));
                }
                client.deleteVpc(r -> r.vpcId(vpc));
            }
        }
    }
}
