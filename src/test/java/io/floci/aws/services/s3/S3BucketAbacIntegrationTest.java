package io.floci.aws.services.s3;

import io.floci.aws.testing.PartitionCleanup;
import io.floci.aws.testing.S3IamEnforcementProfile;
import io.quarkus.test.common.http.TestHTTPResource;
import io.quarkus.test.junit.QuarkusTest;
import io.quarkus.test.junit.TestProfile;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.RegisterExtension;
import software.amazon.awssdk.auth.credentials.AwsBasicCredentials;
import software.amazon.awssdk.auth.credentials.StaticCredentialsProvider;
import software.amazon.awssdk.core.sync.RequestBody;
import software.amazon.awssdk.regions.Region;
import software.amazon.awssdk.services.iam.IamClient;
import software.amazon.awssdk.services.iam.model.AccessKey;
import software.amazon.awssdk.services.s3.S3Client;
import software.amazon.awssdk.services.s3.model.S3Exception;
import software.amazon.awssdk.services.s3.model.Tag;
import software.amazon.awssdk.services.s3control.S3ControlClient;

import java.net.URI;
import java.util.UUID;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

@QuarkusTest
@TestProfile(S3IamEnforcementProfile.class)
class S3BucketAbacIntegrationTest {

    private static final String ACCOUNT = "000000000000";
    private static final StaticCredentialsProvider ROOT = credentials("test", "test");

    @TestHTTPResource("/")
    URI endpoint;

    @RegisterExtension
    final PartitionCleanup cleanup = new PartitionCleanup();

    @Test
    void defaultAndRoundTripRetainTagsAndChangeTheTaggingApi() {
        try (S3Client admin = client(ROOT);
             S3ControlClient control = S3ControlClient.builder().endpointOverride(endpoint)
                     .region(Region.US_EAST_1).credentialsProvider(ROOT).build()) {
            String bucket = bucket(admin);
            String arn = "arn:aws:s3:::" + bucket;
            assertEquals("Disabled", status(admin, bucket));
            tag(admin, bucket);
            abac(admin, bucket, "Enabled");
            assertEquals("Enabled", status(admin, bucket));
            assertEquals("blue", admin.getBucketTagging(r -> r.bucket(bucket)).tagSet().getFirst().value());
            assertEquals("InvalidRequest", assertThrows(S3Exception.class, () -> tag(admin, bucket))
                    .awsErrorDetails().errorCode());
            assertEquals("InvalidRequest", assertThrows(S3Exception.class,
                    () -> admin.deleteBucketTagging(r -> r.bucket(bucket))).awsErrorDetails().errorCode());
            control.tagResource(r -> r.accountId(ACCOUNT).resourceArn(arn)
                    .tags(t -> t.key("Owner").value("green")));
            assertEquals("green", control.listTagsForResource(r -> r.accountId(ACCOUNT).resourceArn(arn))
                    .tags().getFirst().value());
            control.untagResource(r -> r.accountId(ACCOUNT).resourceArn(arn).tagKeys("Owner"));
            assertEquals(0, control.listTagsForResource(r -> r.accountId(ACCOUNT).resourceArn(arn)).tags().size());
            abac(admin, bucket, "Disabled");
            tag(admin, bucket);
            admin.deleteBucketTagging(r -> r.bucket(bucket));
            assertEquals("Disabled", status(admin, bucket));
        }
    }

    @Test
    void scopedPermissionsAndExplicitDeniesProtectTheAbacState() {
        try (S3Client admin = client(ROOT)) {
            String bucket = bucket(admin);
            String other = bucket(admin);
            String allow = "{\"Effect\":\"Allow\",\"Action\":[\"s3:GetBucketAbac\",\"s3:PutBucketAbac\"],"
                    + "\"Resource\":\"arn:aws:s3:::" + bucket + "\"}";
            try (S3Client reader = user(allow)) {
                assertEquals("Disabled", status(reader, bucket));
                denied(() -> status(reader, other));
                denied(() -> abac(reader, other, "Enabled"));
                abac(reader, bucket, "Enabled");
                assertEquals("Enabled", status(reader, bucket));
            }
            try (S3Client denied = user(allow + ",{\"Effect\":\"Deny\",\"Action\":\"s3:PutBucketAbac\","
                    + "\"Resource\":\"arn:aws:s3:::" + bucket + "\"}")) {
                denied(() -> abac(denied, bucket, "Disabled"));
                assertEquals("Enabled", status(admin, bucket));
            }
            try (S3Client creator = user("{\"Effect\":\"Allow\",\"Action\":[\"s3:CreateBucket\","
                    + "\"s3:ListBucket\"],\"Resource\":\"*\"}")) {
                denied(() -> abac(creator, bucket, "Disabled"));
                denied(() -> status(creator, bucket));
            }
        }
    }

    @Test
    void ownerMismatchInvalidStatusAndMissingBucketsDoNotMutateState() {
        try (S3Client admin = client(ROOT)) {
            String bucket = bucket(admin);
            denied(() -> admin.getBucketAbac(r -> r.bucket(bucket).expectedBucketOwner("111111111111")));
            denied(() -> admin.putBucketAbac(r -> r.bucket(bucket).expectedBucketOwner("111111111111")
                    .abacStatus(s -> s.status("Enabled"))));
            assertEquals("InvalidArgument", assertThrows(S3Exception.class,
                    () -> abac(admin, bucket, "invalid")).awsErrorDetails().errorCode());
            assertEquals("Disabled", status(admin, bucket));
            String missing = "abac-missing-" + UUID.randomUUID();
            assertEquals("NoSuchBucket", assertThrows(S3Exception.class,
                    () -> abac(admin, missing, "Enabled")).awsErrorDetails().errorCode());
            assertEquals("NoSuchBucket", assertThrows(S3Exception.class,
                    () -> status(admin, missing)).awsErrorDetails().errorCode());
        }
    }

    @Test
    void bucketTagsAuthorizeOnlyWhileAbacIsEnabled() {
        try (S3Client admin = client(ROOT)) {
            String bucket = bucket(admin);
            tag(admin, bucket);
            for (String key : new String[] {"aws:ResourceTag/Owner", "s3:BucketTag/Owner"}) {
                try (S3Client scoped = user("{\"Effect\":\"Allow\",\"Action\":[\"s3:GetBucketAbac\","
                        + "\"s3:GetBucketTagging\",\"s3:DeleteBucket\"],\"Resource\":\"arn:aws:s3:::" + bucket
                        + "\",\"Condition\":{\"StringEquals\":{\"" + key + "\":\"blue\"}}}")) {
                    denied(() -> status(scoped, bucket));
                    denied(() -> scoped.deleteBucket(r -> r.bucket(bucket)));
                    abac(admin, bucket, "Enabled");
                    assertEquals("Enabled", status(scoped, bucket));
                    assertEquals("blue", scoped.getBucketTagging(r -> r.bucket(bucket)).tagSet().getFirst().value());
                    abac(admin, bucket, "Disabled");
                    denied(() -> status(scoped, bucket));
                }
            }
        }
    }

    @Test
    void explicitBucketTagDenyAppliesToObjectRequests() {
        try (S3Client admin = client(ROOT)) {
            String bucket = bucket(admin);
            tag(admin, bucket);
            admin.putObject(r -> r.bucket(bucket).key("item"),
                    RequestBody.fromString("payload"));
            cleanup.register(() -> {
                try (S3Client root = client(ROOT)) {
                    root.deleteObject(r -> r.bucket(bucket).key("item"));
                }
            });
            try (S3Client reader = user("{\"Effect\":\"Allow\",\"Action\":\"s3:GetObject\",\"Resource\":\"arn:aws:s3:::"
                    + bucket + "/*\"},{\"Effect\":\"Deny\",\"Action\":\"s3:GetObject\",\"Resource\":\"arn:aws:s3:::"
                    + bucket + "/*\",\"Condition\":{\"StringEquals\":{\"s3:BucketTag/Owner\":\"blue\"}}}")) {
                assertEquals("payload", reader.getObjectAsBytes(r -> r.bucket(bucket).key("item")).asUtf8String());
                abac(admin, bucket, "Enabled");
                denied(() -> reader.getObjectAsBytes(r -> r.bucket(bucket).key("item")));
                abac(admin, bucket, "Disabled");
                assertEquals("payload", reader.getObjectAsBytes(r -> r.bucket(bucket).key("item")).asUtf8String());
            }
        }
    }

    @Test
    void crossAccountUpdateChecksTheActualOwnerAndWritesBackToItsBucket() {
        try (S3Client admin = client(ROOT)) {
            String bucket = bucket(admin);
            String arn = "arn:aws:s3:::" + bucket;
            String statement = "{\"Effect\":\"Allow\",\"Action\":[\"s3:GetBucketAbac\",\"s3:PutBucketAbac\"],"
                    + "\"Resource\":\"" + arn + "\"}";
            try (S3Client caller = user(statement, "222222222222")) {
                denied(() -> status(caller, bucket));
                admin.putBucketPolicy(r -> r.bucket(bucket).policy("{\"Version\":\"2012-10-17\",\"Statement\":["
                        + "{\"Effect\":\"Allow\",\"Principal\":{\"AWS\":\"arn:aws:iam::222222222222:root\"},"
                        + "\"Action\":[\"s3:GetBucketAbac\",\"s3:PutBucketAbac\"],\"Resource\":\"" + arn + "\"}]}"));
                try {
                    assertEquals("Disabled", status(caller, bucket));
                    denied(() -> caller.putBucketAbac(r -> r.bucket(bucket).expectedBucketOwner("222222222222")
                            .abacStatus(v -> v.status("Enabled"))));
                    abac(caller, bucket, "Enabled");
                    assertEquals("Enabled", status(admin, bucket));
                } finally {
                    admin.deleteBucketPolicy(r -> r.bucket(bucket));
                }
            }
        }
    }

    private String bucket(S3Client admin) {
        String name = "abac-" + UUID.randomUUID();
        admin.createBucket(r -> r.bucket(name));
        cleanup.register(() -> {
            try (S3Client root = client(ROOT)) {
                root.deleteBucket(r -> r.bucket(name));
            }
        });
        return name;
    }

    private S3Client user(String statements) {
        return user(statements, "test");
    }

    private S3Client user(String statements, String account) {
        String name = "abac-" + UUID.randomUUID();
        try (IamClient iam = iam(account)) {
            iam.createUser(r -> r.userName(name));
            cleanup.register(() -> {
                try (IamClient root = iam(account)) {
                    root.listAccessKeys(r -> r.userName(name)).accessKeyMetadata().forEach(k ->
                            root.deleteAccessKey(r -> r.userName(name).accessKeyId(k.accessKeyId())));
                    root.deleteUserPolicy(r -> r.userName(name).policyName("p"));
                    root.deleteUser(r -> r.userName(name));
                }
            });
            iam.putUserPolicy(r -> r.userName(name).policyName("p")
                    .policyDocument("{\"Version\":\"2012-10-17\",\"Statement\":[" + statements + "]}"));
            AccessKey key = iam.createAccessKey(r -> r.userName(name)).accessKey();
            return client(credentials(key.accessKeyId(), key.secretAccessKey()));
        }
    }

    private IamClient iam(String account) {
        return IamClient.builder().endpointOverride(endpoint).region(Region.US_EAST_1)
                .credentialsProvider(credentials(account, "test")).build();
    }

    private S3Client client(StaticCredentialsProvider credentials) {
        return S3Client.builder().endpointOverride(endpoint).region(Region.US_EAST_1)
                .forcePathStyle(true).credentialsProvider(credentials).build();
    }

    private static StaticCredentialsProvider credentials(String key, String secret) {
        return StaticCredentialsProvider.create(AwsBasicCredentials.create(key, secret));
    }

    private static void tag(S3Client client, String bucket) {
        client.putBucketTagging(r -> r.bucket(bucket)
                .tagging(t -> t.tagSet(Tag.builder().key("Owner").value("blue").build())));
    }

    private static void abac(S3Client client, String bucket, String status) {
        client.putBucketAbac(r -> r.bucket(bucket).expectedBucketOwner(ACCOUNT).abacStatus(s -> s.status(status)));
    }

    private static String status(S3Client client, String bucket) {
        return client.getBucketAbac(r -> r.bucket(bucket).expectedBucketOwner(ACCOUNT)).abacStatus().statusAsString();
    }

    private static void denied(Runnable operation) {
        assertEquals(403, assertThrows(S3Exception.class, operation::run).statusCode());
    }
}
