package io.floci.aws.core.common;

import io.floci.aws.services.eks.EksService;
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
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;
import software.amazon.awssdk.regions.Region;
import software.amazon.awssdk.services.eks.EksClient;
import software.amazon.awssdk.services.eks.model.AccessEntry;
import software.amazon.awssdk.services.eks.model.EksException;

import java.net.URI;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.util.Map;
import java.util.UUID;

import static io.floci.aws.testing.EnforcementFixtures.auth;
import static io.floci.aws.testing.IamTestPolicies.EMPTY_POLICY_DOCUMENT;
import static io.restassured.RestAssured.given;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

@QuarkusTest
@TestProfile(IamEnforcementProfile.class)
class EksAccessConditionsIntegrationTest {
    private static final String ACCOUNT = "000000000000";
    private static final String POLICY = "arn:aws:eks::aws:cluster-access-policy/AmazonEKSClusterAdminPolicy";
    @TestHTTPResource("/")
    URI endpoint;
    @RegisterExtension
    final PartitionCleanup cleanup = new PartitionCleanup();
    @Inject
    EksService eks;

    @ParameterizedTest
    @ValueSource(strings = {"STANDARD", "EC2_LINUX"})
    void creationChecksRequestedPrincipalAndTypeAndExistingReadsUseStoredIdentity(String type) {
        try (Fixture f = new Fixture()) {
            String condition = identity(f.role, type);
            String grant = grant("CreateAccessEntry", f.clusterArn(), condition);
            f.policy(grant);
            denied(() -> f.client.createAccessEntry(r -> r.clusterName(f.name).principalArn(f.otherRole).type(type)));
            denied(() -> f.client.createAccessEntry(r -> r.clusterName(f.name).principalArn(f.role)
                    .type("STANDARD".equals(type) ? "EC2_LINUX" : "STANDARD")));
            denied(() -> f.client.createAccessEntry(r -> r.clusterName(f.name).principalArn(f.role)));
            f.policy(grant + "," + grant.replace("Allow", "Deny"));
            denied(() -> f.client.createAccessEntry(r -> r.clusterName(f.name).principalArn(f.role).type(type)));
            f.policy(grant);
            denied(() -> f.client.createAccessEntry(r -> r.clusterName(f.name).principalArn(f.role).type(type)
                    .tags(Map.of("owner", "team"))));
            f.policy(grant + "," + grant("TagResource", f.clusterArn(), "{}"));
            AccessEntry entry = f.client.createAccessEntry(r -> r.clusterName(f.name).principalArn(f.role).type(type)
                    .tags(Map.of("owner", "team"))).accessEntry();
            assertEquals(f.role, entry.principalArn());
            assertEquals(type, entry.type());
            assertEquals("team", entry.tags().get("owner"));
            f.policy(grant("DescribeAccessEntry", entry.accessEntryArn(), condition));
            assertEquals(entry.accessEntryArn(), f.client.describeAccessEntry(r -> r.clusterName(f.name)
                    .principalArn(f.role)).accessEntry().accessEntryArn());
            f.policy(grant("DescribeAccessEntry", entry.accessEntryArn(), identity(f.otherRole, type)));
            denied(() -> f.client.describeAccessEntry(r -> r.clusterName(f.name).principalArn(f.role)));
        }
    }

    @Test
    void associationChecksStoredPrincipalRequestedPolicyAndScopeAndDisassociationChecksStoredScope() {
        try (Fixture f = new Fixture()) {
            AccessEntry entry = f.admin.createAccessEntry(r -> r.clusterName(f.name).principalArn(f.role)
                    .type("STANDARD")).accessEntry();
            f.admin.createAccessEntry(r -> r.clusterName(f.name).principalArn(f.otherRole).type("STANDARD"));
            String conditions = """
                    {"StringEquals":{"eks:principalArn":"%s","eks:accessEntryType":"STANDARD",
                     "eks:policyArn":"%s","eks:accessScope":"cluster"}}""".formatted(f.role, POLICY);
            String grant = grant("AssociateAccessPolicy", "*", conditions);
            f.policy(grant);
            denied(() -> f.client.associateAccessPolicy(r -> r.clusterName(f.name).principalArn(f.otherRole)
                    .policyArn(POLICY).accessScope(s -> s.type("cluster"))));
            denied(() -> f.client.associateAccessPolicy(r -> r.clusterName(f.name).principalArn(f.role)
                    .policyArn(POLICY).accessScope(s -> s.type("namespace").namespaces("default"))));
            denied(() -> f.client.associateAccessPolicy(r -> r.clusterName(f.name).principalArn(f.role)
                    .policyArn(POLICY.replace("AmazonEKSClusterAdminPolicy", "AmazonEKSViewPolicy"))
                    .accessScope(s -> s.type("cluster"))));
            // An extra body member cannot replace the principal selected by the URI's encoded role path.
            given().urlEncodingEnabled(false).port(endpoint.getPort()).header("Authorization", auth(f.credentials.accessKeyId(), "eks"))
                    .contentType("application/json").body("""
                            {"principalArn":"%s","policyArn":"%s","accessScope":{"type":"cluster"}}"""
                            .formatted(f.role, POLICY))
                    .post("/clusters/" + f.name + "/access-entries/"
                            + URLEncoder.encode(f.otherRole, StandardCharsets.UTF_8) + "/access-policies")
                    .then().statusCode(403);
            f.policy(grant + "," + grant.replace("Allow", "Deny"));
            denied(() -> f.client.associateAccessPolicy(r -> r.clusterName(f.name).principalArn(f.role)
                    .policyArn(POLICY).accessScope(s -> s.type("cluster"))));
            f.policy(grant);
            assertEquals("cluster", f.client.associateAccessPolicy(r -> r.clusterName(f.name).principalArn(f.role)
                    .policyArn(POLICY).accessScope(s -> s.type("cluster"))).associatedAccessPolicy().accessScope().typeAsString());
            assertEquals(1, f.admin.listAssociatedAccessPolicies(r -> r.clusterName(f.name).principalArn(f.role))
                    .associatedAccessPolicies().size());
            String remove = grant("DisassociateAccessPolicy", entry.accessEntryArn(), conditions);
            f.policy(remove.replace("\"cluster\"", "\"namespace\""));
            denied(() -> f.client.disassociateAccessPolicy(r -> r.clusterName(f.name).principalArn(f.role).policyArn(POLICY)));
            f.policy(remove);
            f.client.disassociateAccessPolicy(r -> r.clusterName(f.name).principalArn(f.role).policyArn(POLICY));
            assertTrue(f.admin.listAssociatedAccessPolicies(r -> r.clusterName(f.name).principalArn(f.role))
                    .associatedAccessPolicies().isEmpty());
        }
    }

    @Test
    void storedLookupRejectsWrongRegionAccountPartitionAndStaleIncarnation() {
        try (Fixture f = new Fixture()) {
            String arn = f.admin.createAccessEntry(r -> r.clusterName(f.name).principalArn(f.role).type("STANDARD"))
                    .accessEntry().accessEntryArn();
            assertTrue(eks.storedAccessEntry(arn, "us-east-1").isPresent());
            assertTrue(eks.storedAccessEntry(arn, "eu-west-1").isEmpty());
            assertTrue(eks.storedAccessEntry(arn.replace(ACCOUNT, "111111111111"), "us-east-1").isEmpty());
            assertTrue(eks.storedAccessEntry(arn.replace("arn:aws:", "arn:aws-cn:"), "us-east-1").isEmpty());
            f.admin.deleteCluster(r -> r.name(f.name));
            f.createCluster();
            f.admin.createAccessEntry(r -> r.clusterName(f.name).principalArn(f.role).type("STANDARD"));
            assertTrue(eks.storedAccessEntry(arn, "us-east-1").isEmpty());
        }
    }

    private static String identity(String role, String type) {
        return """
                {"ArnEquals":{"eks:principalArn":"%s"},"StringEquals":{"eks:accessEntryType":"%s"}}"""
                .formatted(role, type);
    }

    private static String grant(String action, String resource, String condition) {
        return """
                {"Effect":"Allow","Action":"eks:%s","Resource":"%s","Condition":%s}"""
                .formatted(action, resource, condition);
    }

    private static void denied(Runnable call) {
        EksException error = assertThrows(EksException.class, call::run);
        assertEquals(403, error.statusCode());
        assertEquals("AccessDeniedException", error.awsErrorDetails().errorCode());
    }

    private final class Fixture implements AutoCloseable {
        final String name = "access-condition-" + UUID.randomUUID();
        final String role;
        final String otherRole;
        final UserCredentials credentials;
        final EksClient admin;
        final EksClient client;

        Fixture() {
            credentials = EnforcementFixtures.createUser(cleanup, endpoint.getPort(), auth(ACCOUNT, "iam"), name);
            role = EnforcementFixtures.createRole(cleanup, endpoint.getPort(), ACCOUNT, "/teams/access-policies/", name,
                    EMPTY_POLICY_DOCUMENT);
            otherRole = EnforcementFixtures.createRole(cleanup, endpoint.getPort(), ACCOUNT, "/teams/", name + "-other",
                    EMPTY_POLICY_DOCUMENT);
            admin = AwsTestClients.create(EksClient.builder(), ACCOUNT, Region.US_EAST_1, endpoint);
            client = AwsTestClients.create(EksClient.builder(), credentials.accessKeyId(), credentials.secretAccessKey(),
                    Region.US_EAST_1, endpoint);
            createCluster();
        }

        void createCluster() {
            admin.createCluster(r -> r.name(name).roleArn(role).accessConfig(a -> a.authenticationMode("API_AND_CONFIG_MAP")
                    .bootstrapClusterCreatorAdminPermissions(false)));
        }

        String clusterArn() {
            return admin.describeCluster(r -> r.name(name)).cluster().arn();
        }

        void policy(String statements) {
            EnforcementFixtures.putUserPolicy(endpoint.getPort(), auth(ACCOUNT, "iam"), name, "conditions",
                    """
                    {"Version":"2012-10-17","Statement":[%s,
                     {"Effect":"Allow","Action":"iam:PassRole","Resource":["%s","%s"]}]}"""
                    .formatted(statements, role, otherRole));
        }

        @Override
        public void close() {
            try {
                admin.deleteCluster(r -> r.name(name));
            } finally {
                client.close();
                admin.close();
            }
        }
    }
}
