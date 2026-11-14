package io.floci.aws.core.common;

import com.fasterxml.jackson.core.type.TypeReference;
import io.floci.aws.core.storage.StorageFactory;
import io.floci.aws.services.kms.model.KmsAlias;
import io.floci.aws.services.kms.model.KmsKey;
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
import software.amazon.awssdk.core.SdkBytes;
import software.amazon.awssdk.regions.Region;
import software.amazon.awssdk.services.kms.KmsClient;
import software.amazon.awssdk.services.kms.model.KeyMetadata;
import software.amazon.awssdk.services.kms.model.KmsException;

import java.net.URI;
import java.util.Map;
import java.util.UUID;

import static io.floci.aws.testing.EnforcementFixtures.auth;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

@QuarkusTest
@TestProfile(IamEnforcementProfile.class)
class KmsResourceTagIntegrationTest {
    private static final String ACCOUNT = "000000000000";
    private static final String REGION = "us-east-1";
    private static final String KEYS = "arn:aws:kms:" + REGION + ":" + ACCOUNT + ":key/*";

    @TestHTTPResource("/")
    URI endpoint;
    @Inject
    StorageFactory storage;
    @RegisterExtension
    final PartitionCleanup cleanup = new PartitionCleanup();

    @ParameterizedTest
    @ValueSource(strings = {"id", "arn", "alias", "alias-arn"})
    void describeUsesStoredTagsForEveryKeyIdentifierAndHonorsTagChanges(String identifier) {
        try (Fixture f = new Fixture()) {
            KeyMetadata key = f.key("owned");
            String alias = f.alias(key.keyId());
            String requested = switch (identifier) {
                case "id" -> key.keyId();
                case "arn" -> key.arn();
                case "alias" -> alias;
                default -> "arn:aws:kms:" + REGION + ":" + ACCOUNT + ":" + alias;
            };
            f.policy(grant("Allow", "DescribeKey", "owned"));
            assertEquals(key.arn(), f.client.describeKey(r -> r.keyId(requested)).keyMetadata().arn());
            f.admin.tagResource(r -> r.keyId(key.keyId()).tags(t -> t.tagKey("Owner").tagValue("foreign")));
            denied(() -> f.client.describeKey(r -> r.keyId(requested)));
            f.admin.untagResource(r -> r.keyId(key.keyId()).tagKeys("Owner"));
            denied(() -> f.client.describeKey(r -> r.keyId(requested)));
            f.admin.tagResource(r -> r.keyId(key.keyId()).tags(t -> t.tagKey("Owner").tagValue("owned")));
            f.policy(grant("Allow", "DescribeKey", "owned") + "," + grant("Deny", "DescribeKey", "owned"));
            denied(() -> f.client.describeKey(r -> r.keyId(requested)));
        }
    }

    @Test
    void aliasRetargetingAndCiphertextLookupsReadTheActualKeysTags() {
        try (Fixture f = new Fixture()) {
            KeyMetadata owned = f.key("owned");
            KeyMetadata foreign = f.key("foreign");
            String alias = f.alias(owned.keyId());
            f.policy(grant("Allow", "DescribeKey", "owned") + "," + grant("Allow", "Encrypt", "owned")
                    + "," + grant("Allow", "Decrypt", "owned"));
            SdkBytes encrypted = f.client.encrypt(r -> r.keyId(alias).plaintext(SdkBytes.fromUtf8String("tags")))
                    .ciphertextBlob();
            assertEquals("tags", f.client.decrypt(r -> r.ciphertextBlob(encrypted)).plaintext().asUtf8String());
            f.admin.updateAlias(r -> r.aliasName(alias).targetKeyId(foreign.keyId()));
            denied(() -> f.client.describeKey(r -> r.keyId(alias)));
            denied(() -> f.client.encrypt(r -> r.keyId(alias).plaintext(SdkBytes.fromUtf8String("tags"))));
            f.admin.tagResource(r -> r.keyId(owned.keyId()).tags(t -> t.tagKey("Owner").tagValue("foreign")));
            denied(() -> f.client.decrypt(r -> r.ciphertextBlob(encrypted)));
        }
    }

    @Test
    void aliasUpdateRequiresBothKeyOwnersAndNeverCopiesKeyTagsToTheAlias() {
        try (Fixture f = new Fixture()) {
            KeyMetadata original = f.key("owned");
            KeyMetadata replacement = f.key("foreign");
            String alias = f.alias(original.keyId());
            String aliasGrant = "{\"Effect\":\"Allow\",\"Action\":\"kms:UpdateAlias\",\"Resource\":\"arn:aws:kms:"
                    + REGION + ":" + ACCOUNT + ":" + alias + "\"}";
            f.policy(aliasGrant + "," + grant("Allow", "UpdateAlias", "owned"));
            denied(() -> f.client.updateAlias(r -> r.aliasName(alias).targetKeyId(replacement.keyId())));
            assertEquals(original.arn(), f.admin.describeKey(r -> r.keyId(alias)).keyMetadata().arn());
            f.admin.tagResource(r -> r.keyId(replacement.keyId()).tags(t -> t.tagKey("Owner").tagValue("owned")));
            f.policy(grant("Allow", "UpdateAlias", "owned").replace(KEYS, "*"));
            denied(() -> f.client.updateAlias(r -> r.aliasName(alias).targetKeyId(replacement.keyId())));
            f.policy(aliasGrant + "," + grant("Allow", "UpdateAlias", "owned"));
            f.client.updateAlias(r -> r.aliasName(alias).targetKeyId(replacement.keyId()));
            assertEquals(replacement.arn(), f.admin.describeKey(r -> r.keyId(alias)).keyMetadata().arn());
        }
    }

    private static String grant(String effect, String action, String owner) {
        return """
                {"Effect":"%s","Action":"kms:%s","Resource":"%s",
                 "Condition":{"StringEquals":{"aws:ResourceTag/Owner":"%s"}}}
                """.formatted(effect, action, KEYS, owner);
    }

    private static void denied(Runnable call) {
        KmsException error = assertThrows(KmsException.class, call::run);
        assertEquals("AccessDeniedException", error.awsErrorDetails().errorCode());
    }

    private final class Fixture implements AutoCloseable {
        private final String user = "kms-tags-" + UUID.randomUUID();
        private final KmsClient admin;
        private final KmsClient client;

        private Fixture() {
            UserCredentials credentials = EnforcementFixtures.createUser(cleanup, endpoint.getPort(), auth(ACCOUNT, "iam"), user);
            admin = AwsTestClients.create(KmsClient.builder(), ACCOUNT, Region.US_EAST_1, endpoint);
            client = AwsTestClients.create(KmsClient.builder(), credentials.accessKeyId(), credentials.secretAccessKey(),
                    Region.US_EAST_1, endpoint);
        }

        private KeyMetadata key(String owner) {
            KeyMetadata key = admin.createKey(r -> r.tags(t -> t.tagKey("Owner").tagValue(owner))).keyMetadata();
            cleanup.register(() -> storage.create("kms", "kms-keys.json", new TypeReference<Map<String, KmsKey>>() {})
                    .deleteForAccount(ACCOUNT, REGION + "::" + key.keyId()));
            return key;
        }

        private String alias(String id) {
            String alias = "alias/tags-" + UUID.randomUUID();
            admin.createAlias(r -> r.aliasName(alias).targetKeyId(id));
            cleanup.register(() -> storage.create("kms", "kms-aliases.json", new TypeReference<Map<String, KmsAlias>>() {})
                    .deleteForAccount(ACCOUNT, REGION + "::" + alias));
            return alias;
        }

        private void policy(String statements) {
            EnforcementFixtures.putUserPolicy(endpoint.getPort(), auth(ACCOUNT, "iam"), user, "tags",
                    "{\"Version\":\"2012-10-17\",\"Statement\":[" + statements + "]}");
        }

        @Override
        public void close() {
            client.close();
            admin.close();
        }
    }
}
