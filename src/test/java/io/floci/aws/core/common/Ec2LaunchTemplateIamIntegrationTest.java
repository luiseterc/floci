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
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;
import software.amazon.awssdk.regions.Region;
import software.amazon.awssdk.services.ec2.Ec2Client;
import software.amazon.awssdk.services.ec2.model.CreateLaunchTemplateRequest;
import software.amazon.awssdk.services.ec2.model.Ec2Exception;
import software.amazon.awssdk.services.ec2.model.TagSpecification;

import java.net.URI;
import java.util.List;
import java.util.UUID;

import static io.floci.aws.testing.EnforcementFixtures.auth;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

@QuarkusTest
@TestProfile(IamEnforcementProfile.class)
class Ec2LaunchTemplateIamIntegrationTest {
    @TestHTTPResource("/")
    URI endpoint;
    @RegisterExtension
    final PartitionCleanup cleanup = new PartitionCleanup();

    @ParameterizedTest
    @ValueSource(strings = {"us-east-1", "us-gov-west-1", "cn-north-1"})
    void creationAndDryRunRequireTheTemplateTagsAndBothPermissions(String region) {
        String user = "launch-template-" + UUID.randomUUID();
        UserCredentials credentials = EnforcementFixtures.createUser(cleanup, endpoint.getPort(),
                auth("000000000000", "iam"), user);
        String resource = AwsArnUtils.Arn.of("ec2", region, "000000000000", "launch-template/*").toString();
        String create = """
                {"Effect":"Allow","Action":"ec2:CreateLaunchTemplate","Resource":"%s",
                 "Condition":{"StringEquals":{"aws:RequestTag/ManagedBy":"integration-test"}}}
                """.formatted(resource);
        String tags = """
                {"Effect":"Allow","Action":"ec2:CreateTags","Resource":"%s",
                 "Condition":{"StringEquals":{"ec2:CreateAction":"CreateLaunchTemplate"}}}
                """.formatted(resource);
        try (Ec2Client client = AwsTestClients.create(Ec2Client.builder(), credentials.accessKeyId(),
                credentials.secretAccessKey(), Region.of(region), endpoint);
             Ec2Client admin = AwsTestClients.create(Ec2Client.builder(), "000000000000", Region.of(region), endpoint)) {
            CreateLaunchTemplateRequest request = request(user, "integration-test");
            policy(user, create);
            denied(client, request);
            policy(user, create + "," + tags);
            denied(client, request(user, "other"));
            denied(client, request.toBuilder().tagSpecifications(List.of()).build());
            denied(client, request.toBuilder().tagSpecifications(List.of()).launchTemplateData(d -> d
                    .imageId("ami-0abcdef1234567891").tagSpecifications(t -> t.resourceType("instance")
                            .tags(tag -> tag.key("ManagedBy").value("integration-test")))).build());
            int before = admin.describeLaunchTemplates().launchTemplates().size();
            Ec2Exception dryRun = assertThrows(Ec2Exception.class,
                    () -> client.createLaunchTemplate(request.toBuilder().dryRun(true).build()));
            assertEquals("DryRunOperation", dryRun.awsErrorDetails().errorCode());
            assertEquals(412, dryRun.statusCode());
            assertEquals(before, admin.describeLaunchTemplates().launchTemplates().size());
            String id = client.createLaunchTemplate(request).launchTemplate().launchTemplateId();
            try {
                assertEquals("integration-test", admin.describeLaunchTemplates(r -> r.launchTemplateIds(id))
                        .launchTemplates().getFirst().tags().getFirst().value());
                for (String action : List.of("ec2:CreateLaunchTemplate", "ec2:CreateTags")) {
                    policy(user, create + "," + tags + "," + """
                            {"Effect":"Deny","Action":"%s","Resource":"%s"}
                            """.formatted(action, resource));
                    denied(client, request.toBuilder().dryRun(true).build());
                }
                policy(user, create.replace(":000000000000:", ":111122223333:") + "," + tags);
                denied(client, request);
            } finally {
                admin.deleteLaunchTemplate(r -> r.launchTemplateId(id));
            }
        }
    }

    @Test
    void privilegedDryRunDoesNotCreateATemplate() {
        try (Ec2Client admin = AwsTestClients.create(Ec2Client.builder(), "000000000000", Region.US_EAST_1, endpoint)) {
            int before = admin.describeLaunchTemplates().launchTemplates().size();
            Ec2Exception error = assertThrows(Ec2Exception.class, () -> admin.createLaunchTemplate(
                    request("dry-run-" + UUID.randomUUID(), "integration-test").toBuilder().dryRun(true).build()));
            assertEquals("DryRunOperation", error.awsErrorDetails().errorCode());
            assertEquals(before, admin.describeLaunchTemplates().launchTemplates().size());
        }
    }

    private CreateLaunchTemplateRequest request(String name, String owner) {
        return CreateLaunchTemplateRequest.builder().launchTemplateName(name)
                .launchTemplateData(data -> data.imageId("ami-0abcdef1234567891").instanceType("t3.micro"))
                .tagSpecifications(TagSpecification.builder().resourceType("launch-template")
                        .tags(tag -> tag.key("ManagedBy").value(owner)).build()).build();
    }

    private void denied(Ec2Client client, CreateLaunchTemplateRequest request) {
        Ec2Exception error = assertThrows(Ec2Exception.class, () -> client.createLaunchTemplate(request));
        assertEquals("UnauthorizedOperation", error.awsErrorDetails().errorCode());
    }

    private void policy(String user, String statements) {
        EnforcementFixtures.putUserPolicy(endpoint.getPort(), auth("000000000000", "iam"), user,
                "create", "{\"Version\":\"2012-10-17\",\"Statement\":[" + statements + "]}");
    }
}
