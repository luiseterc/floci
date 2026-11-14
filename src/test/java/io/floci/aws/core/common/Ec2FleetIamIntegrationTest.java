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
import software.amazon.awssdk.services.ec2.model.CreateFleetRequest;
import software.amazon.awssdk.services.ec2.model.Ec2Exception;
import software.amazon.awssdk.services.ec2.model.FleetLaunchTemplateConfigRequest;
import software.amazon.awssdk.services.ec2.model.Instance;
import software.amazon.awssdk.services.ec2.model.TagSpecification;

import java.net.URI;
import java.util.List;
import java.util.UUID;
import java.util.stream.Collectors;

import static io.floci.aws.testing.EnforcementFixtures.auth;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

@QuarkusTest
@TestProfile(IamEnforcementProfile.class)
class Ec2FleetIamIntegrationTest {
    private static final String ARN = "arn:aws:ec2:us-east-1:000000000000:";
    @TestHTTPResource("/")
    URI endpoint;
    @RegisterExtension
    final PartitionCleanup cleanup = new PartitionCleanup();

    @Test
    void dryRunRequiresEveryResolvedFleetResourceAndEveryOverride() {
        String user = "fleet-" + UUID.randomUUID();
        UserCredentials credentials = EnforcementFixtures.createUser(cleanup, endpoint.getPort(),
                auth("000000000000", "iam"), user);
        try (Ec2Client client = AwsTestClients.create(Ec2Client.builder(), credentials.accessKeyId(),
                credentials.secretAccessKey(), Region.US_EAST_1, endpoint);
             Ec2Client admin = AwsTestClients.create(Ec2Client.builder(), "000000000000", Region.US_EAST_1, endpoint)) {
            String vpc = admin.createVpc(r -> r.cidrBlock("10.206.0.0/16")).vpc().vpcId();
            String first = admin.createSubnet(r -> r.vpcId(vpc).cidrBlock("10.206.1.0/24")).subnet().subnetId();
            String second = admin.createSubnet(r -> r.vpcId(vpc).cidrBlock("10.206.2.0/24")).subnet().subnetId();
            String template = admin.createLaunchTemplate(r -> r.launchTemplateName(user)
                    .tagSpecifications(tags("launch-template", "template")).launchTemplateData(d -> d
                    .imageId("ami-0abcdef1234567891").instanceType("t3.micro"))).launchTemplate().launchTemplateId();
            CreateFleetRequest request = CreateFleetRequest.builder().type("instant").dryRun(true)
                    .targetCapacitySpecification(t -> t.totalTargetCapacity(1).defaultTargetCapacityType("on-demand"))
                    .launchTemplateConfigs(FleetLaunchTemplateConfigRequest.builder()
                            .launchTemplateSpecification(t -> t.launchTemplateId(template).version("1"))
                            .overrides(o -> o.subnetId(first), o -> o.subnetId(second)).build()).build();
            List<String> resources = List.of(ARN + "fleet/*", ARN + "instance/*", ARN + "volume/*",
                    "arn:aws:ec2:us-east-1::image/ami-0abcdef1234567891", ARN + "launch-template/" + template,
                    ARN + "subnet/" + first, ARN + "subnet/" + second);
            int before = admin.describeInstances().reservations().size();
            try {
                for (String missing : resources) {
                    policy(user, resources.stream().filter(r -> !r.equals(missing)).map(r -> grant("Allow", r))
                            .collect(Collectors.joining(",")));
                    Ec2Exception denied = assertThrows(Ec2Exception.class, () -> client.createFleet(request), missing);
                    assertEquals("UnauthorizedOperation", denied.awsErrorDetails().errorCode(), missing);
                }
                String allowed = resources.stream().map(r -> grant("Allow", r)).collect(Collectors.joining(","));
                policy(user, allowed);
                Ec2Exception dryRun = assertThrows(Ec2Exception.class, () -> client.createFleet(request));
                assertEquals("DryRunOperation", dryRun.awsErrorDetails().errorCode());
                assertEquals(before, admin.describeInstances().reservations().size());
                admin.createTags(r -> r.resources(template).tags(t -> t.key("ManagedBy").value("other")));
                assertEquals("UnauthorizedOperation", assertThrows(Ec2Exception.class,
                        () -> client.createFleet(request)).awsErrorDetails().errorCode());
                admin.createTags(r -> r.resources(template).tags(t -> t.key("ManagedBy").value("template")));

                CreateFleetRequest mixed = request.toBuilder().launchTemplateConfigs(
                        request.launchTemplateConfigs().getFirst().toBuilder().overrides(
                                o -> o.subnetId(first).instanceType("t3.micro"),
                                o -> o.subnetId(second).instanceType("t3.small")).build()).build();
                String restricted = resources.stream().map(r -> r.equals(ARN + "instance/*")
                        ? conditioned(r, "ec2:InstanceType", "t3.micro") : grant("Allow", r))
                        .collect(Collectors.joining(","));
                policy(user, restricted);
                assertEquals("UnauthorizedOperation", assertThrows(Ec2Exception.class,
                        () -> client.createFleet(mixed)).awsErrorDetails().errorCode());

                CreateFleetRequest tagged = request.toBuilder().dryRun(false).tagSpecifications(
                        tags("fleet", "fleet"), tags("instance", "instance"), tags("volume", "volume"),
                        tags("network-interface", "interface")).build();
                String taggedGrants = resources.stream().map(r -> {
                    for (String type : List.of("fleet", "instance", "volume")) {
                        if (r.equals(ARN + type + "/*")) {
                            return conditioned(r, "aws:RequestTag/ManagedBy", type);
                        }
                    }
                    return grant("Allow", r);
                }).collect(Collectors.joining(","));
                policy(user, taggedGrants);
                assertEquals("UnauthorizedOperation", assertThrows(Ec2Exception.class,
                        () -> client.createFleet(tagged)).awsErrorDetails().errorCode());
                String tagging = """
                        {"Effect":"Allow","Action":"ec2:CreateTags","Resource":"%s*/*",
                         "Condition":{"StringEquals":{"ec2:CreateAction":"CreateFleet"}}}
                        """.formatted(ARN);
                policy(user, taggedGrants + "," + tagging);
                CreateFleetRequest wrongVolume = tagged.toBuilder().tagSpecifications(tags("fleet", "fleet"),
                        tags("instance", "instance"), tags("volume", "instance")).build();
                assertEquals("UnauthorizedOperation", assertThrows(Ec2Exception.class,
                        () -> client.createFleet(wrongVolume)).awsErrorDetails().errorCode());
                String instanceId = client.createFleet(tagged).instances().getFirst().instanceIds().getFirst();
                try {
                    Instance instance = admin.describeInstances(r -> r.instanceIds(instanceId))
                            .reservations().getFirst().instances().getFirst();
                    assertEquals("instance", instance.tags().getFirst().value());
                    String volume = instance.blockDeviceMappings().getFirst().ebs().volumeId();
                    assertEquals("volume", admin.describeVolumes(r -> r.volumeIds(volume)).volumes().getFirst()
                            .tags().getFirst().value());
                    String networkInterface = instance.networkInterfaces().getFirst().networkInterfaceId();
                    assertEquals("interface", admin.describeNetworkInterfaces(r -> r.networkInterfaceIds(networkInterface))
                            .networkInterfaces().getFirst().tagSet().getFirst().value());
                } finally {
                    admin.terminateInstances(r -> r.instanceIds(instanceId));
                }
                policy(user, allowed + "," + grant("Deny", ARN + "subnet/" + second));
                assertEquals("UnauthorizedOperation", assertThrows(Ec2Exception.class,
                        () -> client.createFleet(request)).awsErrorDetails().errorCode());
            } finally {
                admin.deleteLaunchTemplate(r -> r.launchTemplateId(template));
                admin.deleteSubnet(r -> r.subnetId(first));
                admin.deleteSubnet(r -> r.subnetId(second));
                admin.deleteVpc(r -> r.vpcId(vpc));
            }
        }
    }

    private String grant(String effect, String resource) {
        if ("Allow".equals(effect) && resource.contains(":launch-template/")) {
            return conditioned(resource, "aws:ResourceTag/ManagedBy", "template");
        }
        return "{\"Effect\":\"" + effect + "\",\"Action\":\"ec2:CreateFleet\",\"Resource\":\"" + resource + "\"}";
    }

    private String conditioned(String resource, String key, String value) {
        return """
                {"Effect":"Allow","Action":"ec2:CreateFleet","Resource":"%s",
                 "Condition":{"StringEquals":{"%s":"%s"}}}
                """.formatted(resource, key, value);
    }

    private TagSpecification tags(String type, String value) {
        return TagSpecification.builder().resourceType(type).tags(t -> t.key("ManagedBy").value(value)).build();
    }

    private void policy(String user, String statements) {
        EnforcementFixtures.putUserPolicy(endpoint.getPort(), auth("000000000000", "iam"), user,
                "fleet", "{\"Version\":\"2012-10-17\",\"Statement\":[" + statements + "]}");
    }
}
