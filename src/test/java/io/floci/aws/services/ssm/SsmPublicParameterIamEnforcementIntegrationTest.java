package io.floci.aws.services.ssm;

import io.floci.aws.testing.AwsTestClients;
import io.floci.aws.testing.EnforcementFixtures;
import io.floci.aws.testing.IamEnforcementProfile;
import io.floci.aws.testing.PartitionCleanup;
import io.floci.aws.testing.RestAssuredJsonUtils;
import io.quarkus.test.junit.QuarkusTest;
import io.quarkus.test.junit.TestProfile;
import io.restassured.RestAssured;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.RegisterExtension;
import software.amazon.awssdk.regions.Region;
import software.amazon.awssdk.services.ssm.SsmClient;
import software.amazon.awssdk.services.ssm.model.SsmException;

import java.util.List;
import java.util.UUID;

import static io.floci.aws.testing.EnforcementFixtures.auth;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;

@QuarkusTest
@TestProfile(IamEnforcementProfile.class)
class SsmPublicParameterIamEnforcementIntegrationTest {
    private static final String ACCOUNT = "000000000000";
    private static final String PATH = "/aws/service/ami-amazon-linux-latest";
    private static final String NAME = PATH + "/al2023-ami-kernel-default-arm64";
    private static final String ARN = "arn:aws:ssm:us-east-1::parameter" + NAME;

    @RegisterExtension
    final PartitionCleanup cleanup = new PartitionCleanup();

    @BeforeAll
    static void configureRestAssured() {
        RestAssuredJsonUtils.configureAwsContentTypes();
    }

    @Test
    void accountlessGrantAllowsPublicNamesArnsBatchesAndPaths() {
        try (SsmClient user = user("""
                {"Effect":"Allow","Action":["ssm:GetParameter","ssm:GetParameters","ssm:GetParametersByPath"],
                 "Resource":"arn:aws:ssm:us-east-1::parameter/aws/service/*"}
                """)) {
            assertEquals(ARN, user.getParameter(r -> r.name(NAME)).parameter().arn());
            assertEquals(ARN, user.getParameter(r -> r.name(ARN)).parameter().arn());
            assertEquals(ARN, user.getParameters(r -> r.names(NAME)).parameters().getFirst().arn());
            assertFalse(user.getParametersByPath(r -> r.path(PATH)).parameters().isEmpty());
        }
    }

    @Test
    void callerAccountGrantDoesNotAuthorizePublicName() {
        try (SsmClient user = user("""
                {"Effect":"Allow","Action":"ssm:GetParameter",
                 "Resource":"arn:aws:ssm:us-east-1:000000000000:parameter/aws/service/*"}
                """)) {
            denied(() -> user.getParameter(r -> r.name(NAME)));
        }
    }

    @Test
    void explicitDenyAppliesToPublicNamesAndBatchReads() {
        try (SsmClient user = user("""
                {"Effect":"Allow","Action":"ssm:Get*","Resource":"*"},
                {"Effect":"Deny","Action":["ssm:GetParameter","ssm:GetParameters"],"Resource":"%s"}
                """.formatted(ARN))) {
            denied(() -> user.getParameter(r -> r.name(NAME)));
            denied(() -> user.getParameters(r -> r.names(NAME)));
        }
    }

    @Test
    void publicGrantDoesNotAuthorizePrivateParameterInMixedBatch() {
        try (SsmClient user = user("""
                {"Effect":"Allow","Action":"ssm:GetParameters",
                 "Resource":"arn:aws:ssm:us-east-1::parameter/aws/service/*"}
                """)) {
            denied(() -> user.getParameters(r -> r.names(NAME, "/private/config")));
        }
    }

    @Test
    void publicArnCannotRedirectToAnotherAccountRegionOrPartition() {
        try (SsmClient root = AwsTestClients.create(SsmClient.builder(), ACCOUNT, Region.US_EAST_1)) {
            for (String invalid : List.of(
                    ARN.replace("us-east-1::", "us-east-1:" + ACCOUNT + ":"),
                    ARN.replace("us-east-1", "eu-west-1"), ARN.replace("arn:aws:", "arn:aws-cn:"),
                    "arn:aws:ssm:us-east-1::parameter/private/config")) {
                SsmException error = assertThrows(SsmException.class,
                        () -> root.getParameter(r -> r.name(invalid)));
                assertEquals("ParameterNotFound", error.awsErrorDetails().errorCode());
            }
        }
    }

    private SsmClient user(String statements) {
        String name = "ssm-public-" + UUID.randomUUID();
        EnforcementFixtures.UserCredentials credentials = EnforcementFixtures.createUser(
                cleanup, RestAssured.port, auth(ACCOUNT, "iam"), name);
        EnforcementFixtures.putUserPolicy(RestAssured.port, auth(ACCOUNT, "iam"), name, "p",
                "{\"Version\":\"2012-10-17\",\"Statement\":[" + statements + "]}");
        return AwsTestClients.create(SsmClient.builder(), credentials.accessKeyId(), Region.US_EAST_1);
    }

    private static void denied(Runnable request) {
        SsmException error = assertThrows(SsmException.class, request::run);
        assertEquals("AccessDeniedException", error.awsErrorDetails().errorCode());
    }
}
