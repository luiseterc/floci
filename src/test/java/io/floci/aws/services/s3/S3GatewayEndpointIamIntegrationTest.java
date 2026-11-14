package io.floci.aws.services.s3;

import io.floci.aws.core.common.AwsRegionFacts;
import io.floci.aws.core.common.AwsRegions;
import io.floci.aws.core.common.RequestScopes;
import io.floci.aws.services.ec2.Ec2MetadataServer;
import io.floci.aws.services.ec2.Ec2Service;
import io.floci.aws.services.ec2.model.Instance;
import io.floci.aws.services.ec2.model.VpcEndpoint;
import io.floci.aws.testing.EnforcementFixtures;
import io.floci.aws.testing.EnforcementFixtures.UserCredentials;
import io.floci.aws.testing.PartitionCleanup;
import io.floci.aws.testing.S3IamEnforcementProfile;
import io.floci.aws.testutil.S3RequestSigner;
import io.quarkus.test.common.http.TestHTTPResource;
import io.quarkus.test.junit.QuarkusTest;
import io.quarkus.test.junit.TestProfile;
import jakarta.inject.Inject;
import org.junit.jupiter.api.extension.RegisterExtension;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;
import software.amazon.awssdk.auth.credentials.AwsBasicCredentials;
import software.amazon.awssdk.auth.credentials.StaticCredentialsProvider;
import software.amazon.awssdk.core.sync.RequestBody;
import software.amazon.awssdk.regions.Region;
import software.amazon.awssdk.services.s3.S3Client;
import software.amazon.awssdk.services.s3.model.DeleteObjectsResponse;

import java.net.URI;
import java.util.List;
import java.util.Map;
import java.util.UUID;

import static io.floci.aws.testing.AwsSdkErrors.assertAwsError;
import static io.floci.aws.testing.EnforcementFixtures.auth;
import static io.restassured.RestAssured.given;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

@QuarkusTest
@TestProfile(S3IamEnforcementProfile.class)
class S3GatewayEndpointIamIntegrationTest {
    private static final String ACCOUNT = "111122223333";
    private String region;

    @Inject
    Ec2Service ec2;
    @Inject
    Ec2MetadataServer metadata;
    @TestHTTPResource("/")
    URI endpoint;
    @RegisterExtension
    final PartitionCleanup cleanup = new PartitionCleanup();

    @ParameterizedTest
    @ValueSource(strings = {"us-east-2", "us-gov-west-1", "cn-north-1"})
    void signedSdkRequestNeedsTheLiveGatewayRouteAndCannotSpoofItsContext(String testRegion) {
        region = testRegion;
        String name = "gateway-" + UUID.randomUUID();
        String bucket = "gateway-" + UUID.randomUUID();
        UserCredentials owner = EnforcementFixtures.createUser(cleanup, endpoint.getPort(), auth(ACCOUNT, region, "iam"), name);
        policy(name, "{\"Version\":\"2012-10-17\",\"Statement\":[{\"Effect\":\"Allow\",\"Action\":\"s3:*\",\"Resource\":\"*\"}]}");
        String callerName = name + "-reader";
        UserCredentials reader = EnforcementFixtures.createUser(cleanup, endpoint.getPort(), auth(ACCOUNT, region, "iam"), callerName);
        cleanup.register(() -> EnforcementFixtures.removeBucket(endpoint.getPort(),
                S3RequestSigner.signedAs(owner.accessKeyId(), owner.secretAccessKey()).inRegion(region), bucket));
        try (S3Client admin = client(owner); S3Client caller = client(reader)) {
            admin.createBucket(request -> request.bucket(bucket).createBucketConfiguration(c -> c.locationConstraint(region)));
            admin.putObject(request -> request.bucket(bucket).key("connectivity.txt"), RequestBody.fromString("fixture"));
            assertEquals("fixture", admin.getObjectAsBytes(request -> request.bucket(bucket).key("connectivity.txt")).asUtf8String());
            Gateway fixture = gateway();
            String allow = """
                    {"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":["s3:GetObject","s3:DeleteObject"],
                      "Resource":"arn:%s:s3:::%s/*","Condition":{"StringEquals":{
                        "aws:SourceVpce":"%s","aws:SourceVpc":"%s"}}}]}
                    """.formatted(AwsRegions.partitionFor(region), bucket, fixture.endpoint().getVpcEndpointId(), fixture.guest().getVpcId());
            policy(callerName, allow);
            assertAwsError("AccessDenied", 403, () -> caller.getObjectAsBytes(request -> request.bucket(bucket).key("connectivity.txt")));
            metadata.registerContainer("127.0.0.1", fixture.guest().getInstanceId(), fixture.guest());
            cleanup.register(() -> metadata.unregisterContainer("127.0.0.1", fixture.guest()));
            assertEquals("fixture", caller.getObjectAsBytes(request -> request.bucket(bucket).key("connectivity.txt")).asUtf8String());

            given().port(endpoint.getPort()).header("Authorization", auth(ACCOUNT, region, "iam"))
                    .contentType("application/x-www-form-urlencoded")
                    .formParam("Action", "TagUser").formParam("Version", "2010-05-08")
                    .formParam("UserName", callerName).formParam("Tags.member.1.Key", "S3Endpoint")
                    .formParam("Tags.member.1.Value", fixture.endpoint().getVpcEndpointId())
                    .post("/").then().statusCode(200);
            policy(callerName, """
                    {"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":["s3:GetObject","s3:DeleteObject"],
                      "Resource":"arn:%s:s3:::%s/*","Condition":{"StringEquals":{
                        "aws:PrincipalTag/S3Endpoint":"${aws:SourceVpce}"}}}]}
                    """.formatted(AwsRegions.partitionFor(region), bucket));
            assertEquals("fixture", caller.getObjectAsBytes(request -> request.bucket(bucket).key("connectivity.txt")).asUtf8String());

            fixture.endpoint().setRouteTableIds(List.of());
            assertAwsError("AccessDenied", 403, () -> caller.getObjectAsBytes(request -> request.bucket(bucket).key("connectivity.txt")));
            fixture.endpoint().setRouteTableIds(List.of(fixture.tableId()));
            fixture.endpoint().setPolicyDocument("{\"Statement\":[{\"Effect\":\"Deny\",\"Principal\":\"*\",\"Action\":\"*\",\"Resource\":\"*\"}]}");
            assertAwsError("AccessDenied", 403, () -> admin.getObjectAsBytes(request -> request.bucket(bucket).key("connectivity.txt")));
            fixture.endpoint().setPolicyDocument(null);

            admin.putBucketPolicy(request -> request.bucket(bucket).policy("""
                    {"Version":"2012-10-17","Statement":[{"Effect":"Deny","Principal":"*","Action":"s3:GetObject",
                      "Resource":"arn:%s:s3:::%s/*","Condition":{"StringNotEquals":{"aws:SourceVpce":"%s"}}}]}
                    """.formatted(AwsRegions.partitionFor(region), bucket, fixture.endpoint().getVpcEndpointId())));
            assertEquals("fixture", caller.getObjectAsBytes(request -> request.bucket(bucket).key("connectivity.txt")).asUtf8String());
            DeleteObjectsResponse deleted = caller.deleteObjects(request -> request.bucket(bucket)
                    .delete(d -> d.objects(o -> o.key("connectivity.txt"))));
            assertTrue(deleted.errors().isEmpty(), "per-object authorization must receive gateway context");
            assertEquals(List.of("connectivity.txt"), deleted.deleted().stream().map(object -> object.key()).toList());
            metadata.unregisterContainer("127.0.0.1", fixture.guest());
            assertAwsError("AccessDenied", 403, () -> caller.getObjectAsBytes(request -> request.bucket(bucket).key("connectivity.txt")
                    .overrideConfiguration(c -> c.putHeader("X-Forwarded-For", "127.0.0.1")
                            .putHeader("X-Amz-Source-Vpce", fixture.endpoint().getVpcEndpointId()))));
            admin.deleteBucketPolicy(request -> request.bucket(bucket));
        }
    }

    private Gateway gateway() {
        return RequestScopes.callAs(ACCOUNT, region, () -> {
            String vpc = ec2.createVpc(region, "10.81.0.0/16", false).getVpcId();
            cleanup.register(() -> RequestScopes.runAs(ACCOUNT, region, () -> ec2.deleteVpc(region, vpc)));
            String subnet = ec2.createSubnet(region, vpc, "10.81.0.0/24", region + "a").getSubnetId();
            cleanup.register(() -> RequestScopes.runAs(ACCOUNT, region, () -> ec2.deleteSubnet(region, subnet)));
            String table = ec2.createRouteTable(region, vpc).getRouteTableId();
            cleanup.register(() -> RequestScopes.runAs(ACCOUNT, region, () -> ec2.deleteRouteTable(region, table)));
            String association = ec2.associateRouteTable(region, table, subnet).getRouteTableAssociationId();
            cleanup.register(() -> RequestScopes.runAs(ACCOUNT, region, () -> ec2.disassociateRouteTable(region, association)));
            VpcEndpoint gateway = ec2.createVpcEndpoint(region, vpc, AwsRegionFacts.vpcEndpointServiceName(region, "s3"), "Gateway",
                    List.of(table), List.of(), List.of(), null, null, List.of());
            cleanup.register(() -> RequestScopes.runAs(ACCOUNT, region,
                    () -> ec2.deleteVpcEndpoints(region, List.of(gateway.getVpcEndpointId()))));
            Instance guest = ec2.runInstances(region, "ami-test", "t3.micro", 1, 1, null,
                    List.of(), subnet, null, List.of(), null, null).getInstances().getFirst();
            cleanup.register(() -> RequestScopes.runAs(ACCOUNT, region,
                    () -> ec2.terminateInstances(region, List.of(guest.getInstanceId()))));
            ec2.describeInstances(region, List.of(guest.getInstanceId()), Map.of());
            assertEquals(16, guest.getState().getCode());
            return new Gateway(guest, gateway, table);
        });
    }

    private void policy(String name, String document) {
        EnforcementFixtures.putUserPolicy(endpoint.getPort(), auth(ACCOUNT, region, "iam"), name, "gateway", document);
    }

    private S3Client client(UserCredentials credentials) {
        return S3Client.builder().endpointOverride(endpoint).region(Region.of(region)).forcePathStyle(true)
                .credentialsProvider(StaticCredentialsProvider.create(
                        AwsBasicCredentials.create(credentials.accessKeyId(), credentials.secretAccessKey()))).build();
    }

    private record Gateway(Instance guest, VpcEndpoint endpoint, String tableId) {}
}
