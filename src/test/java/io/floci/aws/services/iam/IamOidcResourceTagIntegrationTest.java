package io.floci.aws.services.iam;

import io.floci.aws.testing.AwsTestClients;
import io.floci.aws.testing.EnforcementFixtures;
import io.floci.aws.testing.EnforcementFixtures.UserCredentials;
import io.floci.aws.testing.IamEnforcementProfile;
import io.floci.aws.testing.PartitionCleanup;
import io.quarkus.test.common.http.TestHTTPResource;
import io.quarkus.test.junit.QuarkusTest;
import io.quarkus.test.junit.TestProfile;
import jakarta.inject.Inject;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.RegisterExtension;
import software.amazon.awssdk.regions.Region;
import software.amazon.awssdk.services.iam.IamClient;
import software.amazon.awssdk.services.iam.model.IamException;
import software.amazon.awssdk.services.iam.model.Tag;

import java.net.URI;
import java.util.List;
import java.util.UUID;

import static io.floci.aws.testing.EnforcementFixtures.auth;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

@QuarkusTest
@TestProfile(IamEnforcementProfile.class)
class IamOidcResourceTagIntegrationTest {
    @TestHTTPResource("/")
    URI baseUri;
    @Inject
    IamService service;
    @RegisterExtension
    final PartitionCleanup cleanup = new PartitionCleanup();

    @Test
    void storedTagsGateReadsAndDeleteIncludingExplicitDenies() {
        try (IamClient admin = admin()) {
            String owned = provider(admin, List.of(tag("Owner", "team-a")));
            String other = provider(admin, List.of(tag("Owner", "team-b")));
            String untagged = provider(admin, List.of());
            String blocked = provider(admin, List.of(tag("Owner", "team-a"), tag("Blocked", "yes")));
            String policy = """
                    {"Version":"2012-10-17","Statement":[
                    {"Effect":"Allow","Action":["iam:GetOpenIDConnectProvider",
                     "iam:ListOpenIDConnectProviderTags","iam:DeleteOpenIDConnectProvider"],"Resource":"*",
                     "Condition":{"StringEquals":{"aws:ResourceTag/Owner":"team-a"}}},
                    {"Effect":"Deny","Action":"iam:*","Resource":"*",
                     "Condition":{"StringEquals":{"aws:ResourceTag/Blocked":"yes"}}}]}""";
            try (IamClient caller = caller(policy)) {
                assertEquals(List.of(tag("Owner", "team-a")),
                        caller.getOpenIDConnectProvider(r -> r.openIDConnectProviderArn(owned)).tags());
                assertEquals(List.of(tag("Owner", "team-a")),
                        caller.listOpenIDConnectProviderTags(r -> r.openIDConnectProviderArn(owned)).tags());
                for (String arn : List.of(other, untagged, blocked, owned + "-missing",
                        owned.replace("000000000000", "111122223333"))) {
                    denied(() -> caller.getOpenIDConnectProvider(r -> r.openIDConnectProviderArn(arn)));
                    denied(() -> caller.listOpenIDConnectProviderTags(r -> r.openIDConnectProviderArn(arn)));
                    denied(() -> caller.deleteOpenIDConnectProvider(r -> r.openIDConnectProviderArn(arn)));
                }
                assertEquals(List.of(tag("Owner", "team-b")),
                        admin.getOpenIDConnectProvider(r -> r.openIDConnectProviderArn(other)).tags());
                caller.deleteOpenIDConnectProvider(r -> r.openIDConnectProviderArn(owned));
                denied(() -> caller.getOpenIDConnectProvider(r -> r.openIDConnectProviderArn(owned)));
            }
        }
    }

    @Test
    void taggingDistinguishesStoredOwnershipFromRequestedValues() {
        try (IamClient admin = admin()) {
            String owned = provider(admin, List.of(tag("Owner", "team-a")));
            String other = provider(admin, List.of(tag("Owner", "team-b")));
            String policy = """
                    {"Version":"2012-10-17","Statement":[{"Effect":"Allow",
                    "Action":"iam:TagOpenIDConnectProvider","Resource":"*",
                    "Condition":{"StringEquals":{"aws:ResourceTag/Owner":"team-a",
                    "aws:RequestTag/Owner":"team-b"},"ForAllValues:StringEquals":{"aws:TagKeys":["Owner"]},
                    "Null":{"aws:TagKeys":"false"}}}]}""";
            try (IamClient caller = caller(policy)) {
                denied(() -> caller.tagOpenIDConnectProvider(r -> r.openIDConnectProviderArn(other).tags(tag("Owner", "team-b"))));
                denied(() -> caller.tagOpenIDConnectProvider(r -> r.openIDConnectProviderArn(owned).tags(tag("Owner", "team-a"))));
                denied(() -> caller.tagOpenIDConnectProvider(r -> r.openIDConnectProviderArn(owned)
                        .tags(tag("Owner", "team-b"), tag("Extra", "x"))));
                caller.tagOpenIDConnectProvider(r -> r.openIDConnectProviderArn(owned).tags(tag("Owner", "team-b")));
                assertEquals(List.of(tag("Owner", "team-b")),
                        admin.getOpenIDConnectProvider(r -> r.openIDConnectProviderArn(owned)).tags());
                denied(() -> caller.tagOpenIDConnectProvider(r -> r.openIDConnectProviderArn(owned).tags(tag("Owner", "team-b"))));
            }
        }
    }

    @Test
    void exactLookupDoesNotLeakAcrossAccountsPartitionsOrResourceKinds() {
        try (IamClient admin = admin()) {
            String arn = provider(admin, List.of(tag("Owner", "team-a")));
            assertTrue(service.findOpenIDConnectProvider("000000000000", arn).isPresent());
            assertTrue(service.findOpenIDConnectProvider("111122223333", arn).isEmpty());
            for (String invalid : List.of("invalid", arn + "-missing", arn.replace("arn:aws:", "arn:aws-cn:"),
                    arn.replace(":iam::", ":iam:eu-west-1:"), arn.replace(":iam:", ":sts:"),
                    arn.replace("oidc-provider/", "role/"))) {
                assertTrue(service.findOpenIDConnectProvider("000000000000", invalid).isEmpty(), invalid);
            }
        }
    }

    private IamClient admin() {
        return AwsTestClients.create(IamClient.builder(), "test", Region.US_EAST_1);
    }

    private String provider(IamClient admin, List<Tag> tags) {
        String arn = admin.createOpenIDConnectProvider(r -> r.url("https://issuer.example.test/" + suffix())
                .clientIDList("audience").thumbprintList("0".repeat(40)).tags(tags)).openIDConnectProviderArn();
        cleanup.register(() -> {
            try (IamClient owner = admin()) {
                owner.deleteOpenIDConnectProvider(r -> r.openIDConnectProviderArn(arn));
            } catch (IamException error) {
                if (!"NoSuchEntity".equals(error.awsErrorDetails().errorCode())) {
                    throw error;
                }
            }
        });
        return arn;
    }

    private IamClient caller(String policy) {
        String name = "oidc-tag-caller-" + suffix();
        UserCredentials credentials = EnforcementFixtures.createUser(cleanup, baseUri.getPort(), auth("test", "iam"), name);
        EnforcementFixtures.putUserPolicy(baseUri.getPort(), auth("test", "iam"), name, "tags", policy);
        return AwsTestClients.create(IamClient.builder(), credentials.accessKeyId(), credentials.secretAccessKey(), Region.US_EAST_1);
    }

    private static Tag tag(String key, String value) {
        return Tag.builder().key(key).value(value).build();
    }

    private static String suffix() {
        return UUID.randomUUID().toString().substring(0, 8);
    }

    private static void denied(Runnable action) {
        assertEquals("AccessDenied", assertThrows(IamException.class, action::run).awsErrorDetails().errorCode());
    }
}
