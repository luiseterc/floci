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
import software.amazon.awssdk.services.eventbridge.EventBridgeClient;
import software.amazon.awssdk.services.eventbridge.model.EventBridgeException;
import software.amazon.awssdk.services.eventbridge.model.Target;

import java.net.URI;
import java.util.ArrayList;
import java.util.List;
import java.util.UUID;

import static io.floci.aws.testing.EnforcementFixtures.auth;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

@QuarkusTest
@TestProfile(IamEnforcementProfile.class)
class EventBridgeRequestConditionsIntegrationTest {
    private static final String ACCOUNT = "000000000000";
    private static final String QUEUE = "arn:aws:sqs:us-east-1:000000000000:allowed";
    @TestHTTPResource("/")
    URI endpoint;
    @RegisterExtension
    final PartitionCleanup cleanup = new PartitionCleanup();

    @Test
    void putRuleRequiresEveryLiteralSourceAndRetainsScopedRuleAuthorization() {
        try (Fixture f = new Fixture()) {
            f.policy("""
                    {"Effect":"Allow","Action":"events:PutRule","Resource":"%s",
                     "Condition":{"Null":{"events:source":"false"},
                     "ForAllValues:StringEquals":{"events:source":["aws.ec2","aws.health"]}}}
                    """.formatted(f.ruleArn));
            f.putRule("{\"source\":[\"aws.ec2\",\"aws.health\"]}");
            denied(() -> f.putRule("{\"source\":[\"aws.ec2\",\"other\"]}"));
            denied(() -> f.putRule("{\"detail-type\":[\"example\"]}"));
            denied(() -> f.putRule("{\"source\":[\"aws.ec2\",{\"anything-but\":\"other\"}]}"));
            denied(() -> f.client.putRule(r -> r.name(f.name + "-foreign").eventPattern("{\"source\":[\"aws.ec2\"]}")));
            assertEquals("{\"source\":[\"aws.ec2\",\"aws.health\"]}",
                    f.admin.describeRule(r -> r.name(f.name)).eventPattern());
        }
    }

    @Test
    void explicitDenyUsesSourcesAndAbsentSourceRemainsAbsent() {
        try (Fixture f = new Fixture()) {
            f.policy("""
                    {"Effect":"Allow","Action":"events:PutRule","Resource":"%s"},
                    {"Effect":"Deny","Action":"events:PutRule","Resource":"%s",
                     "Condition":{"ForAnyValue:StringEquals":{"events:source":"aws.health"}}}
                    """.formatted(f.ruleArn, f.ruleArn));
            f.putRule("{\"source\":[\"aws.ec2\"]}");
            denied(() -> f.putRule("{\"source\":[\"aws.ec2\",\"aws.health\"]}"));
            f.client.putRule(r -> r.name(f.name).scheduleExpression("rate(1 hour)"));
        }
    }

    @Test
    void putTargetsChecksAllTargetArnsAndExplicitDeny() {
        try (Fixture f = new Fixture()) {
            f.admin.putRule(r -> r.name(f.name).eventPattern("{\"source\":[\"aws.ec2\"]}"));
            String allow = """
                    {"Effect":"Allow","Action":"events:PutTargets","Resource":"%s",
                     "Condition":{"Null":{"events:TargetArn":"false"},
                     "ForAllValues:ArnEquals":{"events:TargetArn":"%s"}}}
                    """.formatted(f.ruleArn, QUEUE);
            f.policy(allow);
            assertEquals(0, f.client.putTargets(r -> r.rule(f.name).targets(target("one", QUEUE))).failedEntryCount());
            denied(() -> f.client.putTargets(r -> r.rule(f.name).targets(
                    target("two", QUEUE), target("three", QUEUE + "-foreign"))));
            assertEquals(1, f.admin.listTargetsByRule(r -> r.rule(f.name)).targets().size());
            f.policy(allow + "," + """
                    {"Effect":"Deny","Action":"events:PutTargets","Resource":"%s",
                     "Condition":{"ForAnyValue:ArnEquals":{"events:TargetArn":"%s"}}}
                    """.formatted(f.ruleArn, QUEUE));
            denied(() -> f.client.putTargets(r -> r.rule(f.name).targets(target("four", QUEUE))));
        }
    }

    private static Target target(String id, String arn) {
        return Target.builder().id(id).arn(arn).build();
    }

    private static void denied(Runnable action) {
        EventBridgeException error = assertThrows(EventBridgeException.class, action::run);
        assertEquals("AccessDeniedException", error.awsErrorDetails().errorCode());
    }

    private final class Fixture implements AutoCloseable {
        final String name = "conditions-" + UUID.randomUUID();
        final String ruleArn = "arn:aws:events:us-east-1:" + ACCOUNT + ":rule/" + name;
        final EventBridgeClient admin;
        final EventBridgeClient client;

        Fixture() {
            UserCredentials credentials = EnforcementFixtures.createUser(cleanup, endpoint.getPort(), auth(ACCOUNT, "iam"), name);
            admin = AwsTestClients.create(EventBridgeClient.builder(), ACCOUNT, Region.US_EAST_1, endpoint);
            client = AwsTestClients.create(EventBridgeClient.builder(), credentials.accessKeyId(), credentials.secretAccessKey(),
                    Region.US_EAST_1, endpoint);
        }

        void policy(String statements) {
            EnforcementFixtures.putUserPolicy(endpoint.getPort(), auth(ACCOUNT, "iam"), name, "conditions",
                    "{\"Version\":\"2012-10-17\",\"Statement\":[" + statements + "]}");
        }

        void putRule(String pattern) {
            client.putRule(r -> r.name(name).eventPattern(pattern));
        }

        @Override
        public void close() {
            try {
                List<String> ids = new ArrayList<>();
                admin.listTargetsByRule(r -> r.rule(name)).targets().forEach(target -> ids.add(target.id()));
                if (!ids.isEmpty()) {
                    admin.removeTargets(r -> r.rule(name).ids(ids));
                }
                admin.deleteRule(r -> r.name(name));
            } finally {
                client.close();
                admin.close();
            }
        }
    }
}
