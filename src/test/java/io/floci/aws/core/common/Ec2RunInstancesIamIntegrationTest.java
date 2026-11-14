package io.floci.aws.core.common;

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
import software.amazon.awssdk.services.ec2.model.Image;
import software.amazon.awssdk.services.ec2.model.Instance;
import software.amazon.awssdk.services.ec2.model.RunInstancesRequest;
import software.amazon.awssdk.services.ec2.model.TagSpecification;

import java.net.URI;
import java.util.List;
import java.util.Set;
import java.util.UUID;
import java.util.function.Consumer;
import java.util.stream.Collectors;

import static io.floci.aws.testing.EnforcementFixtures.auth;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

@QuarkusTest
@TestProfile(IamEnforcementProfile.class)
class Ec2RunInstancesIamIntegrationTest {
    private static final String ARN = "arn:aws:ec2:us-east-1:000000000000:";
    private static final String IMAGE = "ami-0abcdef1234567891";
    @TestHTTPResource("/")
    URI endpoint;
    @RegisterExtension
    final PartitionCleanup cleanup = new PartitionCleanup();

    @Test
    void everyResolvedResourceNeedsPermissionAndExplicitDeniesWin() {
        try (Fixture f = fixture()) {
            List<String> resources = List.of("arn:aws:ec2:us-east-1::image/" + IMAGE,
                    ARN + "instance/*", ARN + "network-interface/*", ARN + "volume/*",
                    ARN + "subnet/" + f.subnet, ARN + "security-group/" + f.first,
                    ARN + "security-group/" + f.second);
            for (String omitted : resources) {
                f.policy(resources.stream().filter(resource -> !resource.equals(omitted))
                        .map(resource -> grant("Allow", resource, "")).reduce((a, c) -> a + "," + c).orElseThrow());
                denied(() -> f.launch(r -> {}));
                assertEquals(0, f.live().size(), omitted);
            }
            f.policy(grant("Allow", "*", "") + "," + grant("Deny", ARN + "security-group/" + f.second, ""));
            denied(() -> f.launch(r -> {}));
            f.policy(resources.stream().map(resource -> grant("Allow", resource, ""))
                    .reduce((a, c) -> a + "," + c).orElseThrow());
            assertEquals(2, f.launch(r -> {}).securityGroups().size());
        }
    }

    @Test
    void instanceVolumeAndInterfaceTagsAreAuthorizedAndStoredSeparately() {
        try (Fixture f = fixture()) {
            String creation = grant("Allow", ARN + "instance/*", requestTag("instance")) + ","
                    + grant("Allow", ARN + "volume/*", requestTag("volume")) + ","
                    + grant("Allow", ARN + "network-interface/*", requestTag("interface"));
            String existing = grant("Allow", "arn:aws:ec2:us-east-1::image/*", "") + ","
                    + grant("Allow", ARN + "subnet/" + f.subnet, "") + ","
                    + grant("Allow", ARN + "security-group/*", "");
            String tagging = """
                    {"Effect":"Allow","Action":"ec2:CreateTags","Resource":"%s*/*",
                     "Condition":{"StringEquals":{"ec2:CreateAction":"RunInstances"}}}
                    """.formatted(ARN);
            f.policy(creation + "," + existing);
            denied(() -> f.launch(r -> r.tagSpecifications(tags("instance", "instance"),
                    tags("volume", "volume"), tags("network-interface", "interface"))));
            f.policy(creation + "," + existing + "," + tagging);
            denied(() -> f.launch(r -> r.tagSpecifications(tags("instance", "instance"),
                    tags("volume", "instance"), tags("network-interface", "interface"))));
            denied(() -> f.launch(r -> r.tagSpecifications(tags("instance", "instance"),
                    tags("network-interface", "interface"))));
            Instance instance = f.launch(r -> r.tagSpecifications(tags("instance", "instance"),
                    tags("volume", "volume"), tags("network-interface", "interface")));
            assertEquals("instance", instance.tags().getFirst().value());
            String volume = instance.blockDeviceMappings().getFirst().ebs().volumeId();
            assertEquals("volume", f.admin.describeVolumes(r -> r.volumeIds(volume)).volumes().getFirst()
                    .tags().getFirst().value());
            String eni = instance.networkInterfaces().getFirst().networkInterfaceId();
            assertEquals("interface", f.admin.describeNetworkInterfaces(r -> r.networkInterfaceIds(eni))
                    .networkInterfaces().getFirst().tagSet().getFirst().value());
        }
    }

    @Test
    void templateAndExistingInterfaceCannotHideTheImageSubnetOrGroups() {
        try (Fixture f = fixture()) {
            String eni = f.admin.createNetworkInterface(r -> r.subnetId(f.subnet).groups(f.first, f.second))
                    .networkInterface().networkInterfaceId();
            String template = f.admin.createLaunchTemplate(r -> r.launchTemplateName("iam-" + UUID.randomUUID())
                    .launchTemplateData(d -> d.imageId(IMAGE).instanceType("t3.micro")
                            .networkInterfaces(n -> n.deviceIndex(0).networkInterfaceId(eni))))
                    .launchTemplate().launchTemplateId();
            try {
                Runnable request = () -> f.client.runInstances(r -> r.minCount(1).maxCount(1)
                        .launchTemplate(t -> t.launchTemplateId(template)));
                for (String target : List.of("arn:aws:ec2:us-east-1::image/" + IMAGE,
                        ARN + "subnet/" + f.subnet, ARN + "security-group/" + f.second,
                        ARN + "network-interface/" + eni, ARN + "launch-template/" + template)) {
                    f.policy(grant("Allow", "*", "") + "," + grant("Deny", target, ""));
                    denied(request);
                    assertEquals(0, f.live().size());
                }
                f.policy(grant("Allow", "*", ""));
                request.run();
                assertEquals(1, f.live().size());
                assertEquals(f.subnet, f.live().getFirst().subnetId());
            } finally {
                f.admin.deleteLaunchTemplate(r -> r.launchTemplateId(template));
            }
        }
    }

    @Test
    void storedOwnershipTagsAreCheckedForEachSubnetAndGroup() {
        try (Fixture f = fixture()) {
            f.admin.createTags(r -> r.resources(f.subnet).tags(t -> t.key("Owner").value("subnet")));
            f.admin.createTags(r -> r.resources(f.first).tags(t -> t.key("Owner").value("group")));
            String grants = grant("Allow", "arn:aws:ec2:us-east-1::image/*", "") + ","
                    + grant("Allow", ARN + "instance/*", "") + ","
                    + grant("Allow", ARN + "volume/*", "") + ","
                    + grant("Allow", ARN + "network-interface/*", "") + ","
                    + grant("Allow", ARN + "subnet/*", "\"StringEquals\":{\"aws:ResourceTag/Owner\":\"subnet\"}") + ","
                    + grant("Allow", ARN + "security-group/*", "\"StringEquals\":{\"aws:ResourceTag/Owner\":\"group\"}");
            f.policy(grants);
            denied(() -> f.launch(r -> {}));
            f.admin.createTags(r -> r.resources(f.second).tags(t -> t.key("Owner").value("group")));
            f.launch(r -> {});
        }
    }

    @Test
    void templateVolumeAndInterfaceTagsRequireTaggingPermissionAndRequestOverridesReachStorage() {
        try (Fixture f = fixture()) {
            String template = f.admin.createLaunchTemplate(r -> r.launchTemplateName("tags-" + UUID.randomUUID())
                    .launchTemplateData(d -> d.imageId(IMAGE).instanceType("t3.micro")
                            .networkInterfaces(n -> n.deviceIndex(0).subnetId(f.subnet).groups(f.first))
                            .tagSpecifications(t -> t.resourceType("instance").tags(v -> v.key("Scope").value("instance")),
                                    t -> t.resourceType("volume").tags(v -> v.key("Scope").value("volume")),
                                    t -> t.resourceType("network-interface").tags(v -> v.key("Scope").value("interface")))))
                    .launchTemplate().launchTemplateId();
            try {
                RunInstancesRequest request = RunInstancesRequest.builder().minCount(1).maxCount(1)
                        .launchTemplate(t -> t.launchTemplateId(template))
                        .tagSpecifications(tags("volume", "override")).build();
                f.policy(grant("Allow", "*", ""));
                denied(() -> f.client.runInstances(request));
                f.policy(grant("Allow", "*", "")
                        + "," + "{\"Effect\":\"Allow\",\"Action\":\"ec2:CreateTags\",\"Resource\":\"*\"}");
                Instance instance = f.client.runInstances(request).instances().getFirst();
                assertEquals("instance", instance.tags().getFirst().value());
                String volume = instance.blockDeviceMappings().getFirst().ebs().volumeId();
                assertEquals("override", f.admin.describeVolumes(r -> r.volumeIds(volume)).volumes().getFirst()
                        .tags().getFirst().value());
                String eni = instance.networkInterfaces().getFirst().networkInterfaceId();
                assertEquals("interface", f.admin.describeNetworkInterfaces(r -> r.networkInterfaceIds(eni))
                        .networkInterfaces().getFirst().tagSet().getFirst().value());
            } finally {
                f.admin.deleteLaunchTemplate(r -> r.launchTemplateId(template));
            }
        }
    }

    @Test
    void verifiedPublisherAliasIsUsedForLaunchAuthorization() {
        try (Fixture f = fixture()) {
            String other = grant("Allow", ARN + "*/*", "");
            String image = grant("Allow", "arn:aws:ec2:us-east-1::image/*",
                    "\"StringEquals\":{\"ec2:Owner\":\"amazon\"}");
            f.policy(other + "," + image);
            assertEquals("ami-ubuntu2204", f.launch(r -> r.imageId("ami-ubuntu2204")).imageId());
            denied(() -> f.launch(r -> r.imageId("ami-unregistered")));
            f.launch(r -> {});
            f.policy(other + "," + image.replace("amazon", "099720109477"));
            denied(() -> f.launch(r -> r.imageId("ami-ubuntu2204")));
        }
    }

    @Test
    void ubuntuCatalogSupportsNumericOwnerAndVerifiedPublisherLookups() {
        try (Fixture f = fixture()) {
            List<Image> ubuntu = f.admin.describeImages(r -> r.owners("099720109477")).images();
            assertEquals(5, ubuntu.size());
            Set<String> verified = f.admin.describeImages(r -> r.owners("amazon"))
                    .images().stream().map(Image::imageId).collect(Collectors.toSet());
            for (Image image : ubuntu) {
                assertEquals("099720109477", image.ownerId());
                assertEquals("amazon", image.imageOwnerAlias());
                assertTrue(verified.contains(image.imageId()));
            }
            assertTrue(f.admin.describeImages(r -> r.owners("canonical")).images().isEmpty());
        }
    }

    @Test
    void dryRunChecksAuthorizationWithoutLaunching() {
        try (Fixture f = fixture()) {
            f.policy(grant("Allow", "*", "") + "," + grant("Deny", ARN + "volume/*", ""));
            denied(() -> f.launch(r -> r.dryRun(true)));
            f.policy(grant("Allow", "*", ""));
            Ec2Exception result = assertThrows(Ec2Exception.class, () -> f.launch(r -> r.dryRun(true)));
            assertEquals("DryRunOperation", result.awsErrorDetails().errorCode());
            assertTrue(f.live().isEmpty());
        }
    }

    private Fixture fixture() {
        String user = "launch-" + UUID.randomUUID();
        UserCredentials credentials = EnforcementFixtures.createUser(cleanup, endpoint.getPort(),
                auth("000000000000", "iam"), user);
        return new Fixture(user, credentials);
    }

    private final class Fixture implements AutoCloseable {
        final String user;
        final Ec2Client admin;
        final Ec2Client client;
        final String vpc;
        final String subnet;
        final String first;
        final String second;

        Fixture(String user, UserCredentials credentials) {
            this.user = user;
            admin = AwsTestClients.create(Ec2Client.builder(), "000000000000", Region.US_EAST_1, endpoint);
            client = AwsTestClients.create(Ec2Client.builder(), credentials.accessKeyId(),
                    credentials.secretAccessKey(), Region.US_EAST_1, endpoint);
            vpc = admin.createVpc(r -> r.cidrBlock("10.73.0.0/16")).vpc().vpcId();
            subnet = admin.createSubnet(r -> r.vpcId(vpc).cidrBlock("10.73.1.0/24")).subnet().subnetId();
            first = admin.createSecurityGroup(r -> r.vpcId(vpc).groupName("one").description("fixture")).groupId();
            second = admin.createSecurityGroup(r -> r.vpcId(vpc).groupName("two").description("fixture")).groupId();
        }

        Instance launch(Consumer<RunInstancesRequest.Builder> customize) {
            RunInstancesRequest.Builder request = RunInstancesRequest.builder().imageId(IMAGE).instanceType("t3.micro")
                    .minCount(1).maxCount(1).subnetId(subnet).securityGroupIds(first, second);
            customize.accept(request);
            return client.runInstances(request.build()).instances().getFirst();
        }

        void policy(String statements) {
            EnforcementFixtures.putUserPolicy(endpoint.getPort(), auth("000000000000", "iam"), user,
                    "launch", "{\"Version\":\"2012-10-17\",\"Statement\":[" + statements + "]}");
        }

        List<Instance> live() {
            return admin.describeInstances().reservations().stream().flatMap(r -> r.instances().stream())
                    .filter(i -> vpc.equals(i.vpcId()) && !"terminated".equals(i.state().nameAsString())).toList();
        }

        @Override
        public void close() {
            try {
                List<String> ids = live().stream().map(Instance::instanceId).toList();
                if (!ids.isEmpty()) {
                    admin.terminateInstances(r -> r.instanceIds(ids));
                }
                admin.describeNetworkInterfaces().networkInterfaces().stream().filter(n -> vpc.equals(n.vpcId()))
                        .forEach(n -> admin.deleteNetworkInterface(r -> r.networkInterfaceId(n.networkInterfaceId())));
                admin.deleteSecurityGroup(r -> r.groupId(second));
                admin.deleteSecurityGroup(r -> r.groupId(first));
                admin.deleteSubnet(r -> r.subnetId(subnet));
                admin.deleteVpc(r -> r.vpcId(vpc));
            } finally {
                client.close();
                admin.close();
            }
        }
    }

    private static String grant(String effect, String resource, String condition) {
        return "{\"Effect\":\"" + effect + "\",\"Action\":\"ec2:RunInstances\",\"Resource\":\"" + resource + "\""
                + (condition.isEmpty() ? "" : ",\"Condition\":{" + condition + "}") + "}";
    }

    private static String requestTag(String value) {
        return "\"StringEquals\":{\"aws:RequestTag/Scope\":\"" + value + "\"}";
    }

    private static TagSpecification tags(String type, String value) {
        return TagSpecification.builder().resourceType(type).tags(t -> t.key("Scope").value(value)).build();
    }

    private static void denied(Runnable request) {
        Ec2Exception error = assertThrows(Ec2Exception.class, request::run);
        assertEquals(403, error.statusCode());
        assertEquals("UnauthorizedOperation", error.awsErrorDetails().errorCode());
    }
}
