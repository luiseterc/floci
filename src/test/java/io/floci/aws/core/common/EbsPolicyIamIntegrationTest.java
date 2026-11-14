package io.floci.aws.core.common;

import io.floci.aws.services.ec2.Ec2VolumeBlockDeviceManager;
import io.floci.aws.testing.AwsTestClients;
import io.floci.aws.testing.EnforcementFixtures;
import io.floci.aws.testing.EnforcementFixtures.UserCredentials;
import io.floci.aws.testing.IamEnforcementProfile;
import io.floci.aws.testing.PartitionCleanup;
import io.quarkus.test.InjectMock;
import io.quarkus.test.common.http.TestHTTPResource;
import io.quarkus.test.junit.QuarkusTest;
import io.quarkus.test.junit.TestProfile;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.RegisterExtension;
import software.amazon.awssdk.regions.Region;
import software.amazon.awssdk.services.ec2.Ec2Client;
import software.amazon.awssdk.services.ec2.model.Ec2Exception;
import software.amazon.awssdk.services.ec2.model.TagSpecification;
import software.amazon.awssdk.services.iam.IamClient;

import java.net.URI;
import java.time.Duration;
import java.util.UUID;

import static io.floci.aws.testing.EnforcementFixtures.auth;
import static org.awaitility.Awaitility.await;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

@QuarkusTest
@TestProfile(IamEnforcementProfile.class)
class EbsPolicyIamIntegrationTest {
    @TestHTTPResource("/")
    URI endpoint;

    @InjectMock
    Ec2VolumeBlockDeviceManager blockDevices;

    @RegisterExtension
    final PartitionCleanup cleanup = new PartitionCleanup();

    @Test
    void managedCsiPolicyCreatesAttachesExpandsAndDeletesOwnedVolumes() {
        String user = "ebs-policy-" + UUID.randomUUID();
        UserCredentials credentials = EnforcementFixtures.createUser(cleanup, endpoint.getPort(),
                auth("000000000000", "iam"), user);
        try (IamClient iam = AwsTestClients.create(IamClient.builder(), "000000000000", Region.US_EAST_1, endpoint);
             Ec2Client client = AwsTestClients.create(Ec2Client.builder(), credentials.accessKeyId(),
                     credentials.secretAccessKey(), Region.US_EAST_1, endpoint);
             Ec2Client admin = AwsTestClients.create(Ec2Client.builder(), "000000000000", Region.US_EAST_1, endpoint)) {
            iam.attachUserPolicy(r -> r.userName(user)
                    .policyArn("arn:aws:iam::aws:policy/service-role/AmazonEBSCSIDriverPolicy"));
            denied(() -> client.createVolume(r -> r.availabilityZone("us-east-1a").size(1)));
            String instance = admin.runInstances(r -> r.imageId("ami-1234567890abcdef0").instanceType("t3.micro")
                    .minCount(1).maxCount(1).placement(p -> p.availabilityZone("us-east-1a")))
                    .instances().getFirst().instanceId();
            String zone = admin.describeInstances(r -> r.instanceIds(instance)).reservations().getFirst()
                    .instances().getFirst().placement().availabilityZone();
            String volume = client.createVolume(r -> r.availabilityZone(zone).size(1).volumeType("gp3")
                    .tagSpecifications(csiTags())).volumeId();
            String foreign = admin.createVolume(r -> r.availabilityZone(zone).size(1)).volumeId();
            try {
                await().atMost(Duration.ofSeconds(10)).untilAsserted(() -> assertEquals("running",
                        admin.describeInstances(r -> r.instanceIds(instance)).reservations().getFirst()
                                .instances().getFirst().state().nameAsString()));
                denied(() -> client.deleteVolume(r -> r.volumeId(foreign)));
                String deny = """
                        {"Version":"2012-10-17","Statement":[{"Effect":"Deny","Action":"ec2:AttachVolume",
                         "Resource":"arn:aws:ec2:us-east-1:000000000000:instance/%s"}]}
                        """.formatted(instance);
                iam.putUserPolicy(r -> r.userName(user).policyName("deny-target").policyDocument(deny));
                denied(() -> client.attachVolume(r -> r.volumeId(volume).instanceId(instance).device("/dev/xvdf")));
                iam.deleteUserPolicy(r -> r.userName(user).policyName("deny-target"));
                client.attachVolume(r -> r.volumeId(volume).instanceId(instance).device("/dev/xvdf"));
                assertEquals(instance, admin.describeVolumes(r -> r.volumeIds(volume)).volumes().getFirst()
                        .attachments().getFirst().instanceId());
                client.modifyVolume(r -> r.volumeId(volume).size(2));
                assertEquals(2, admin.describeVolumes(r -> r.volumeIds(volume)).volumes().getFirst().size());
                client.detachVolume(r -> r.volumeId(volume).instanceId(instance));
                admin.deleteTags(r -> r.resources(volume).tags(t -> t.key("ebs.csi.aws.com/cluster")));
                denied(() -> client.deleteVolume(r -> r.volumeId(volume)));
                admin.createTags(r -> r.resources(volume).tags(t -> t.key("ebs.csi.aws.com/cluster").value("true")));
                client.deleteVolume(r -> r.volumeId(volume));
            } finally {
                admin.terminateInstances(r -> r.instanceIds(instance));
                admin.deleteVolume(r -> r.volumeId(foreign));
                // Account-scoped fixture cleanup also handles a failed assertion before deletion.
                if (admin.describeVolumes().volumes().stream().anyMatch(v -> v.volumeId().equals(volume))) {
                    admin.deleteVolume(r -> r.volumeId(volume));
                }
            }
        }
    }

    private TagSpecification csiTags() {
        return TagSpecification.builder().resourceType("volume")
                .tags(t -> t.key("ebs.csi.aws.com/cluster").value("true")).build();
    }

    private void denied(Runnable request) {
        Ec2Exception error = assertThrows(Ec2Exception.class, request::run);
        assertEquals(403, error.statusCode());
        assertEquals("UnauthorizedOperation", error.awsErrorDetails().errorCode());
    }
}
