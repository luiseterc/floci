package io.floci.aws.services.ec2;

import io.floci.aws.testing.AwsTestClients;
import io.floci.aws.testing.EnforcementFixtures;
import io.floci.aws.testing.EnforcementFixtures.UserCredentials;
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
import software.amazon.awssdk.services.ec2.model.Tag;

import java.net.URI;
import java.util.UUID;

import static io.floci.aws.testing.EnforcementFixtures.auth;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

@QuarkusTest
@TestProfile(IamEnforcementProfile.class)
class Ec2PrivateIpAuthorizationIntegrationTest {
    @TestHTTPResource("/")
    URI baseUri;
    @RegisterExtension
    final PartitionCleanup cleanup = new PartitionCleanup();

    @Test
    void exactInterfaceVpcAndStoredOwnershipGateBothOperations() {
        try (Ec2Client root = AwsTestClients.create(Ec2Client.builder(), "test", Region.EU_WEST_1)) {
            String vpc = root.createVpc(r -> r.cidrBlock("10.98.0.0/16")).vpc().vpcId();
            String subnet = root.createSubnet(r -> r.vpcId(vpc).cidrBlock("10.98.1.0/24")).subnet().subnetId();
            String eni = root.createNetworkInterface(r -> r.subnetId(subnet).tagSpecifications(t -> t
                    .resourceType("network-interface").tags(Tag.builder().key("Owner").value("team-a").build())))
                    .networkInterface().networkInterfaceId();
            try {
                String policy = """
                        {"Version":"2012-10-17","Statement":[{"Effect":"Allow",
                        "Action":["ec2:AssignPrivateIpAddresses","ec2:UnassignPrivateIpAddresses"],
                        "Resource":"arn:aws:ec2:eu-west-1:000000000000:network-interface/%s",
                        "Condition":{"ArnEquals":{"ec2:Vpc":"arn:aws:ec2:eu-west-1:000000000000:vpc/%s"},
                        "StringEquals":{"aws:ResourceTag/Owner":"team-a"}}}]}""".formatted(eni, vpc);
                String user = "eni-address-" + UUID.randomUUID().toString().substring(0, 8);
                UserCredentials keys = EnforcementFixtures.createUser(cleanup, baseUri.getPort(), auth("test", "iam"), user);
                EnforcementFixtures.putUserPolicy(baseUri.getPort(), auth("test", "iam"), user, "addresses", policy);
                try (Ec2Client caller = AwsTestClients.create(Ec2Client.builder(), keys.accessKeyId(),
                        keys.secretAccessKey(), Region.EU_WEST_1)) {
                    caller.assignPrivateIpAddresses(r -> r.networkInterfaceId(eni).privateIpAddresses("10.98.1.20"));
                    caller.unassignPrivateIpAddresses(r -> r.networkInterfaceId(eni).privateIpAddresses("10.98.1.20"));
                    root.createTags(r -> r.resources(eni).tags(Tag.builder().key("Owner").value("team-b").build()));
                    denied(() -> caller.assignPrivateIpAddresses(r -> r.networkInterfaceId(eni).privateIpAddresses("10.98.1.20")));
                    root.assignPrivateIpAddresses(r -> r.networkInterfaceId(eni).privateIpAddresses("10.98.1.20"));
                    denied(() -> caller.unassignPrivateIpAddresses(r -> r.networkInterfaceId(eni).privateIpAddresses("10.98.1.20")));
                    assertEquals(2, root.describeNetworkInterfaces(r -> r.networkInterfaceIds(eni))
                            .networkInterfaces().getFirst().privateIpAddresses().size());
                    root.createTags(r -> r.resources(eni).tags(Tag.builder().key("Owner").value("team-a").build()));
                    EnforcementFixtures.putUserPolicy(baseUri.getPort(), auth("test", "iam"), user, "deny", """
                            {"Version":"2012-10-17","Statement":[{"Effect":"Deny","Action":"ec2:*","Resource":"*",
                            "Condition":{"StringEquals":{"aws:ResourceTag/Owner":"team-a"}}}]}""");
                    denied(() -> caller.unassignPrivateIpAddresses(r -> r.networkInterfaceId(eni).privateIpAddresses("10.98.1.20")));
                }
            } finally {
                root.deleteNetworkInterface(r -> r.networkInterfaceId(eni));
                root.deleteSubnet(r -> r.subnetId(subnet));
                root.deleteVpc(r -> r.vpcId(vpc));
            }
        }
    }

    private static void denied(Runnable action) {
        assertEquals("UnauthorizedOperation", assertThrows(Ec2Exception.class, action::run).awsErrorDetails().errorCode());
    }
}
