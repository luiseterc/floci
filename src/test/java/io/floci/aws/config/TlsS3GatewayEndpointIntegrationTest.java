package io.floci.aws.config;

import io.floci.aws.core.common.AwsRegionFacts;
import io.floci.aws.core.common.RequestScopes;
import io.floci.aws.services.ec2.Ec2MetadataServer;
import io.floci.aws.services.ec2.Ec2Service;
import io.floci.aws.services.ec2.model.Instance;
import io.floci.aws.services.ec2.model.VpcEndpoint;
import io.floci.aws.testing.AwsTestClients;
import io.floci.aws.testing.EnforcementFixtures;
import io.floci.aws.testing.EnforcementFixtures.UserCredentials;
import io.floci.aws.testing.PartitionCleanup;
import io.floci.aws.testing.S3IamEnforcementProfile;
import io.floci.aws.testutil.FreePorts;
import io.floci.aws.testutil.S3RequestSigner;
import io.quarkus.test.common.http.TestHTTPResource;
import io.quarkus.test.junit.QuarkusTest;
import io.quarkus.test.junit.TestProfile;
import io.vertx.core.Vertx;
import jakarta.inject.Inject;
import org.junit.jupiter.api.extension.RegisterExtension;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;
import software.amazon.awssdk.core.sync.RequestBody;
import software.amazon.awssdk.regions.Region;
import software.amazon.awssdk.services.s3.S3Client;

import java.net.Inet4Address;
import java.net.InetAddress;
import java.net.NetworkInterface;
import java.net.URI;
import java.util.Collections;
import java.util.List;
import java.util.Map;
import java.util.UUID;

import static io.floci.aws.testing.EnforcementFixtures.auth;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assumptions.assumeTrue;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

@QuarkusTest
@TestProfile(S3IamEnforcementProfile.class)
class TlsS3GatewayEndpointIntegrationTest {
    private static final String ACCOUNT = "111122223333";
    @Inject
    Ec2Service ec2;
    @Inject
    Ec2MetadataServer metadata;
    @Inject
    Vertx vertx;
    @Inject
    ProxyPeerAddresses peerAddresses;
    @TestHTTPResource("/")
    URI endpoint;
    @RegisterExtension
    final PartitionCleanup cleanup = new PartitionCleanup();

    @ParameterizedTest
    @CsvSource({"aws,eu-west-1", "aws-us-gov,us-gov-west-1", "aws-cn,cn-north-1"})
    void publicProxyPreservesRegisteredGuestForScopedSdkReads(String partition, String region) throws Exception {
        InetAddress address = null;
        for (NetworkInterface network : Collections.list(NetworkInterface.getNetworkInterfaces())) {
            if (!network.isUp() || network.isLoopback()) {
                continue;
            }
            for (InetAddress candidate : Collections.list(network.getInetAddresses())) {
                if (candidate instanceof Inet4Address && !candidate.isLoopbackAddress()) {
                    address = candidate;
                    break;
                }
            }
            if (address != null) {
                break;
            }
        }
        assumeTrue(address != null, "a non-loopback local address distinguishes the front peer from the backend proxy");
        String peer = address.getHostAddress();
        String name = "gateway-proxy-" + UUID.randomUUID();
        UserCredentials caller = EnforcementFixtures.createUser(cleanup, endpoint.getPort(), auth(ACCOUNT, region, "iam"), name);
        String bucket = "gateway-proxy-" + UUID.randomUUID();
        String ownerName = name + "-owner";
        UserCredentials owner = EnforcementFixtures.createUser(cleanup, endpoint.getPort(), auth(ACCOUNT, region, "iam"), ownerName);
        EnforcementFixtures.putUserPolicy(endpoint.getPort(), auth(ACCOUNT, region, "iam"), ownerName, "owner",
                "{\"Statement\":[{\"Effect\":\"Allow\",\"Action\":\"s3:*\",\"Resource\":\"*\"}]}");
        cleanup.register(() -> EnforcementFixtures.removeBucket(endpoint.getPort(),
                S3RequestSigner.signedAs(owner.accessKeyId(), owner.secretAccessKey()).inRegion(region), bucket));
        try (S3Client admin = AwsTestClients.create(S3Client.builder().forcePathStyle(true), owner.accessKeyId(),
                owner.secretAccessKey(), Region.of(region), endpoint)) {
            admin.createBucket(request -> request.bucket(bucket).createBucketConfiguration(c -> c.locationConstraint(region)));
            admin.putObject(request -> request.bucket(bucket).key("fixture"), RequestBody.fromString("fixture"));
            VpcEndpoint gateway = RequestScopes.callAs(ACCOUNT, region, () -> {
                String vpc = ec2.createVpc(region, "10.93.0.0/16", false).getVpcId();
                cleanup.register(() -> RequestScopes.runAs(ACCOUNT, region, () -> ec2.deleteVpc(region, vpc)));
                String subnet = ec2.createSubnet(region, vpc, "10.93.1.0/24", region + "a").getSubnetId();
                cleanup.register(() -> RequestScopes.runAs(ACCOUNT, region, () -> ec2.deleteSubnet(region, subnet)));
                String table = ec2.createRouteTable(region, vpc).getRouteTableId();
                cleanup.register(() -> RequestScopes.runAs(ACCOUNT, region, () -> ec2.deleteRouteTable(region, table)));
                String association = ec2.associateRouteTable(region, table, subnet).getRouteTableAssociationId();
                cleanup.register(() -> RequestScopes.runAs(ACCOUNT, region, () -> ec2.disassociateRouteTable(region, association)));
                VpcEndpoint result = ec2.createVpcEndpoint(region, vpc, AwsRegionFacts.vpcEndpointServiceName(region, "s3"),
                        "Gateway", List.of(table), List.of(), List.of(), null, null, List.of());
                cleanup.register(() -> RequestScopes.runAs(ACCOUNT, region,
                        () -> ec2.deleteVpcEndpoints(region, List.of(result.getVpcEndpointId()))));
                Instance guest = ec2.runInstances(region, "ami-test", "t3.micro", 1, 1, null,
                        List.of(), subnet, null, List.of(), null, null).getInstances().getFirst();
                cleanup.register(() -> RequestScopes.runAs(ACCOUNT, region,
                        () -> ec2.terminateInstances(region, List.of(guest.getInstanceId()))));
                ec2.describeInstances(region, List.of(guest.getInstanceId()), Map.of());
                metadata.registerContainer(peer, guest.getInstanceId(), guest);
                cleanup.register(() -> metadata.unregisterContainer(peer, guest));
                return result;
            });
            EnforcementFixtures.putUserPolicy(endpoint.getPort(), auth(ACCOUNT, region, "iam"), name, "gateway", """
                    {"Statement":[{"Effect":"Allow","Action":"s3:GetObject","Resource":"arn:%s:s3:::%s/fixture",
                    "Condition":{"StringEquals":{"aws:SourceVpce":"%s"}}}]}
                    """.formatted(partition, bucket, gateway.getVpcEndpointId()));
            int port = FreePorts.anyInterfacePort();
            EmulatorConfig config = mock(EmulatorConfig.class);
            EmulatorConfig.TlsConfig tls = mock(EmulatorConfig.TlsConfig.class);
            EmulatorConfig.SecurityConfig security = mock(EmulatorConfig.SecurityConfig.class);
            when(config.tls()).thenReturn(tls);
            when(config.security()).thenReturn(security);
            when(security.allowUnsafeNetworkExposure()).thenReturn(true);
            when(tls.enabled()).thenReturn(true);
            when(config.port()).thenReturn(port);
            TlsProxyServer proxy = new TlsProxyServer(vertx, config, peer, endpoint.getPort(), endpoint.getPort(), peerAddresses);
            try (S3Client client = AwsTestClients.create(S3Client.builder().forcePathStyle(true), caller.accessKeyId(),
                    caller.secretAccessKey(), Region.of(region), URI.create("http://" + peer + ":" + port))) {
                assertEquals("fixture", client.getObjectAsBytes(request -> request.bucket(bucket).key("fixture")).asUtf8String());
            } finally {
                proxy.stop();
            }
        }
    }
}
