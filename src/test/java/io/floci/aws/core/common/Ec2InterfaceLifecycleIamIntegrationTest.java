package io.floci.aws.core.common;

import io.floci.aws.testing.AwsTestClients;
import io.floci.aws.testing.EnforcementFixtures;
import io.floci.aws.testing.EnforcementFixtures.UserCredentials;
import io.floci.aws.testing.IamEnforcementProfile;
import io.floci.aws.testing.PartitionCleanup;
import io.quarkus.test.common.http.TestHTTPResource;
import io.quarkus.test.junit.QuarkusTest;
import io.quarkus.test.junit.TestProfile;
import org.junit.jupiter.api.extension.RegisterExtension;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;
import software.amazon.awssdk.regions.Region;
import software.amazon.awssdk.services.ec2.Ec2Client;
import software.amazon.awssdk.services.ec2.model.Ec2Exception;

import java.net.URI;
import java.util.UUID;

import static io.floci.aws.testing.EnforcementFixtures.auth;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

@QuarkusTest
@TestProfile(IamEnforcementProfile.class)
class Ec2InterfaceLifecycleIamIntegrationTest {
    @TestHTTPResource("/")
    URI endpoint;
    @RegisterExtension
    final PartitionCleanup cleanup = new PartitionCleanup();

    @ParameterizedTest
    @CsvSource({"us-east-1,aws", "us-gov-west-1,aws-us-gov", "cn-north-1,aws-cn"})
    void lifecycleAuthorizesEachStoredResource(String region, String partition) {
        String user = "eni-lifecycle-" + UUID.randomUUID();
        UserCredentials credentials = EnforcementFixtures.createUser(cleanup, endpoint.getPort(),
                auth("000000000000", region, "iam"), user);
        String arn = "arn:" + partition + ":ec2:" + region + ":000000000000:";
        try (Ec2Client admin = AwsTestClients.create(Ec2Client.builder(), "000000000000", Region.of(region), endpoint);
             Ec2Client client = AwsTestClients.create(Ec2Client.builder(), credentials.accessKeyId(),
                     credentials.secretAccessKey(), Region.of(region), endpoint)) {
            String vpc = admin.createVpc(r -> r.cidrBlock("10.207.0.0/16")).vpc().vpcId();
            String subnet = admin.createSubnet(r -> r.vpcId(vpc).cidrBlock("10.207.1.0/24")).subnet().subnetId();
            String eni = admin.createNetworkInterface(r -> r.subnetId(subnet).tagSpecifications(t -> t
                    .resourceType("network-interface").tags(tag -> tag.key("Owner").value("network"))))
                    .networkInterface().networkInterfaceId();
            String instance = admin.runInstances(r -> r.imageId("ami-0abcdef1234567891").instanceType("t3.micro")
                    .subnetId(subnet).minCount(1).maxCount(1).tagSpecifications(t -> t.resourceType("instance")
                            .tags(tag -> tag.key("Owner").value("compute")))).instances().getFirst().instanceId();
            admin.describeInstances(r -> r.instanceIds(instance));
            String policy = """
                    {"Version":"2012-10-17","Statement":[{"Effect":"Allow",
                    "Action":["ec2:AttachNetworkInterface","ec2:DetachNetworkInterface","ec2:DeleteNetworkInterface",
                    "ec2:ModifyNetworkInterfaceAttribute"],
                    "Resource":"%snetwork-interface/%s","Condition":{"ArnEquals":{"ec2:Vpc":"%svpc/%s"},
                    "StringEquals":{"aws:ResourceTag/Owner":"network"}}},{"Effect":"Allow",
                    "Action":["ec2:AttachNetworkInterface","ec2:DetachNetworkInterface","ec2:ModifyNetworkInterfaceAttribute"],
                    "Resource":"%sinstance/%s","Condition":{"StringEquals":{"aws:ResourceTag/Owner":"compute"}}}]}
                    """.formatted(arn, eni, arn, vpc, arn, instance);
            EnforcementFixtures.putUserPolicy(endpoint.getPort(), auth("000000000000", region, "iam"),
                    user, "lifecycle", policy);
            try {
                String attachment = client.attachNetworkInterface(r -> r.networkInterfaceId(eni).instanceId(instance)
                        .deviceIndex(1)).attachmentId();
                client.modifyNetworkInterfaceAttribute(r -> r.networkInterfaceId(eni)
                        .attachment(a -> a.attachmentId(attachment).deleteOnTermination(true)));
                admin.createTags(r -> r.resources(instance).tags(t -> t.key("Owner").value("wrong")));
                assertEquals("UnauthorizedOperation", assertThrows(Ec2Exception.class, () -> client
                        .modifyNetworkInterfaceAttribute(r -> r.networkInterfaceId(eni)
                                .attachment(a -> a.attachmentId(attachment).deleteOnTermination(false))))
                        .awsErrorDetails().errorCode());
                assertEquals(true, admin.describeNetworkInterfaces(r -> r.networkInterfaceIds(eni))
                        .networkInterfaces().getFirst().attachment().deleteOnTermination());
                assertEquals("UnauthorizedOperation", assertThrows(Ec2Exception.class, () -> client
                        .detachNetworkInterface(r -> r.attachmentId(attachment))).awsErrorDetails().errorCode());
                assertEquals(attachment, admin.describeNetworkInterfaces(r -> r.networkInterfaceIds(eni))
                        .networkInterfaces().getFirst().attachment().attachmentId());
                admin.createTags(r -> r.resources(instance).tags(t -> t.key("Owner").value("compute")));
                client.detachNetworkInterface(r -> r.attachmentId(attachment));
                admin.createTags(r -> r.resources(eni).tags(t -> t.key("Owner").value("wrong")));
                assertEquals("UnauthorizedOperation", assertThrows(Ec2Exception.class, () -> client
                        .deleteNetworkInterface(r -> r.networkInterfaceId(eni))).awsErrorDetails().errorCode());
                admin.createTags(r -> r.resources(eni).tags(t -> t.key("Owner").value("network")));
                client.deleteNetworkInterface(r -> r.networkInterfaceId(eni));
                assertEquals("InvalidNetworkInterfaceID.NotFound", assertThrows(Ec2Exception.class, () -> admin
                        .describeNetworkInterfaces(r -> r.networkInterfaceIds(eni))).awsErrorDetails().errorCode());
            } finally {
                admin.terminateInstances(r -> r.instanceIds(instance));
            }
        }
    }
    @ParameterizedTest
    @CsvSource({"us-east-1,aws", "us-gov-west-1,aws-us-gov", "cn-north-1,aws-cn"})
    void creationUsesEachSubnetAndGroupVpc(String region, String partition) {
        String user = "eni-create-context-" + UUID.randomUUID();
        UserCredentials credentials = EnforcementFixtures.createUser(cleanup, endpoint.getPort(),
                auth("000000000000", region, "iam"), user);
        String arn = "arn:" + partition + ":ec2:" + region + ":000000000000:";
        try (Ec2Client admin = AwsTestClients.create(Ec2Client.builder(), "000000000000", Region.of(region), endpoint);
             Ec2Client client = AwsTestClients.create(Ec2Client.builder(), credentials.accessKeyId(),
                     credentials.secretAccessKey(), Region.of(region), endpoint)) {
            String vpc = admin.createVpc(r -> r.cidrBlock("10.210.0.0/16")).vpc().vpcId();
            String foreignVpc = admin.createVpc(r -> r.cidrBlock("10.211.0.0/16")).vpc().vpcId();
            String subnet = admin.createSubnet(r -> r.vpcId(vpc).cidrBlock("10.210.1.0/24")).subnet().subnetId();
            String foreignSubnet = admin.createSubnet(r -> r.vpcId(foreignVpc).cidrBlock("10.211.1.0/24"))
                    .subnet().subnetId();
            String group = admin.createSecurityGroup(r -> r.vpcId(vpc).groupName(user).description("test")).groupId();
            String foreignGroup = admin.createSecurityGroup(r -> r.vpcId(foreignVpc).groupName(user).description("test"))
                    .groupId();
            String policy = """
                    {"Version":"2012-10-17","Statement":[{"Effect":"Allow",
                    "Action":["ec2:CreateNetworkInterface","ec2:ModifyNetworkInterfaceAttribute"],
                    "Resource":"%snetwork-interface/*"},{"Effect":"Allow",
                    "Action":["ec2:CreateNetworkInterface","ec2:ModifyNetworkInterfaceAttribute"],
                    "Resource":["%ssubnet/*","%ssecurity-group/*"],"Condition":{"ArnEquals":{"ec2:Vpc":"%svpc/%s"}}}]}
                    """.formatted(arn, arn, arn, arn, vpc);
            EnforcementFixtures.putUserPolicy(endpoint.getPort(), auth("000000000000", region, "iam"),
                    user, "create", policy);
            String eni = client.createNetworkInterface(r -> r.subnetId(subnet).groups(group))
                    .networkInterface().networkInterfaceId();
            try {
                client.modifyNetworkInterfaceAttribute(r -> r.networkInterfaceId(eni).description(v -> v.value("standalone")));
                client.modifyNetworkInterfaceAttribute(r -> r.networkInterfaceId(eni).groups(group));
                assertEquals("UnauthorizedOperation", assertThrows(Ec2Exception.class, () -> client
                        .modifyNetworkInterfaceAttribute(r -> r.networkInterfaceId(eni).groups(foreignGroup)))
                        .awsErrorDetails().errorCode());
                assertEquals(group, admin.describeNetworkInterfaces(r -> r.networkInterfaceIds(eni))
                        .networkInterfaces().getFirst().groups().getFirst().groupId());
                int before = admin.describeNetworkInterfaces().networkInterfaces().size();
                assertEquals("UnauthorizedOperation", assertThrows(Ec2Exception.class, () -> client
                        .createNetworkInterface(r -> r.subnetId(subnet).groups(foreignGroup))).awsErrorDetails().errorCode());
                assertEquals("UnauthorizedOperation", assertThrows(Ec2Exception.class, () -> client
                        .createNetworkInterface(r -> r.subnetId(foreignSubnet).groups(group))).awsErrorDetails().errorCode());
                assertEquals(before, admin.describeNetworkInterfaces().networkInterfaces().size());
            } finally {
                admin.deleteNetworkInterface(r -> r.networkInterfaceId(eni));
                admin.deleteSecurityGroup(r -> r.groupId(group));
                admin.deleteSecurityGroup(r -> r.groupId(foreignGroup));
                admin.deleteSubnet(r -> r.subnetId(subnet));
                admin.deleteSubnet(r -> r.subnetId(foreignSubnet));
                admin.deleteVpc(r -> r.vpcId(vpc));
                admin.deleteVpc(r -> r.vpcId(foreignVpc));
            }
        }
    }

}
