package io.floci.aws.services.route53;

import io.floci.aws.core.common.RequestScopes;
import io.floci.aws.services.ec2.Ec2Service;
import io.floci.aws.testing.AwsTestClients;
import io.floci.aws.testing.EnforcementFixtures;
import io.floci.aws.testing.EnforcementFixtures.UserCredentials;
import io.floci.aws.testing.IamEnforcementProfile;
import io.floci.aws.testing.PartitionCleanup;
import io.quarkus.test.common.http.TestHTTPResource;
import io.quarkus.test.junit.QuarkusTest;
import io.quarkus.test.junit.TestProfile;
import jakarta.inject.Inject;
import org.junit.jupiter.api.extension.RegisterExtension;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;
import software.amazon.awssdk.regions.Region;
import software.amazon.awssdk.services.route53.Route53Client;
import software.amazon.awssdk.services.route53.model.Route53Exception;
import software.amazon.awssdk.services.route53.model.VPC;

import java.net.URI;
import java.util.UUID;

import static io.floci.aws.testing.EnforcementFixtures.auth;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

@QuarkusTest
@TestProfile(IamEnforcementProfile.class)
class Route53VpcConditionIntegrationTest {
    private static final String ACCOUNT = "000000000000";
    @Inject
    Ec2Service ec2;
    @TestHTTPResource("/")
    URI endpoint;
    @RegisterExtension
    final PartitionCleanup cleanup = new PartitionCleanup();

    @ParameterizedTest
    @CsvSource({"aws,us-east-1,eu-west-1", "aws-us-gov,us-gov-west-1,us-gov-east-1",
            "aws-cn,cn-north-1,cn-northwest-1"})
    void privateZoneLifecycleChecksTheCompositeVpcIdentity(String partition, String home, String peer) {
        String name = "zone-vpc-condition-" + UUID.randomUUID();
        UserCredentials credentials = EnforcementFixtures.createUser(cleanup, endpoint.getPort(), auth(ACCOUNT, home, "iam"), name);
        String existing = vpc(home, "10.82.0.0/16");
        String target = vpc(peer, "10.83.0.0/16");
        try (Route53Client admin = AwsTestClients.create(Route53Client.builder(), ACCOUNT, Region.of(home), endpoint);
             Route53Client caller = AwsTestClients.create(Route53Client.builder(), credentials.accessKeyId(),
                     credentials.secretAccessKey(), Region.of(home), endpoint)) {
            String zone = admin.createHostedZone(request -> request.name(name + ".test")
                    .callerReference(name).hostedZoneConfig(config -> config.privateZone(true))
                    .vpc(VPC.builder().vpcId(existing).vpcRegion(home).build())).hostedZone().id();
            try {
                String zoneArn = "arn:" + partition + ":route53:::hostedzone/" + zone.replace("/hostedzone/", "");
                String actions = "[\"route53:AssociateVPCWithHostedZone\",\"route53:DisassociateVPCFromHostedZone\","
                        + "\"route53:CreateVPCAssociationAuthorization\",\"route53:DeleteVPCAssociationAuthorization\"]";
                String condition = "{\"StringEquals\":{\"route53:VPCs\":\"VPCId=" + target
                        + ",VPCRegion=" + peer + "\"},\"Null\":{\"route53:VPCs\":\"false\"}}";
                EnforcementFixtures.putUserPolicy(endpoint.getPort(), auth(ACCOUNT, home, "iam"), name, "associate", """
                        {"Version":"2012-10-17","Statement":[
                         {"Effect":"Allow","Action":%s,"Resource":"%s","Condition":%s},
                         {"Effect":"Allow","Action":["route53:CreateHostedZone","route53:ListHostedZonesByVPC"],
                          "Resource":"*","Condition":%s}]}
                        """.formatted(actions, zoneArn, condition, condition));
                VPC selected = VPC.builder().vpcId(target).vpcRegion(peer).build();
                VPC wrong = VPC.builder().vpcId(existing).vpcRegion(home).build();
                assertEquals(403, assertThrows(Route53Exception.class,
                        () -> caller.associateVPCWithHostedZone(request -> request.hostedZoneId(zone).vpc(wrong)))
                        .statusCode());
                assertNotNull(caller.createVPCAssociationAuthorization(request -> request.hostedZoneId(zone)
                        .vpc(selected)).vpc());
                caller.deleteVPCAssociationAuthorization(request -> request.hostedZoneId(zone).vpc(selected));
                assertNotNull(caller.associateVPCWithHostedZone(request -> request.hostedZoneId(zone)
                        .vpc(selected)).changeInfo());
                assertTrue(caller.listHostedZonesByVPC(request -> request.vpcId(target).vpcRegion(peer))
                        .hostedZoneSummaries().stream().anyMatch(summary -> summary.hostedZoneId()
                                .equals(zone.replace("/hostedzone/", ""))));
                assertEquals(403, assertThrows(Route53Exception.class,
                        () -> caller.listHostedZonesByVPC(request -> request.vpcId(target).vpcRegion(home)))
                        .statusCode());
                assertNotNull(caller.disassociateVPCFromHostedZone(request -> request.hostedZoneId(zone)
                        .vpc(selected)).changeInfo());
                assertEquals(403, assertThrows(Route53Exception.class,
                        () -> caller.createHostedZone(request -> request.name(name + ".public.test")
                                .callerReference(name + "public"))).statusCode());
                String created = caller.createHostedZone(request -> request.name(name + ".private.test")
                        .callerReference(name + "private").vpc(selected)).hostedZone().id();
                admin.deleteHostedZone(request -> request.id(created));
                // A deny targeting the selected VPC must override an unconditional grant.
                EnforcementFixtures.putUserPolicy(endpoint.getPort(), auth(ACCOUNT, home, "iam"), name, "associate", """
                        {"Statement":[{"Effect":"Allow","Action":"route53:AssociateVPCWithHostedZone","Resource":"*"},
                        {"Effect":"Deny","Action":"route53:AssociateVPCWithHostedZone","Resource":"%s",
                        "Condition":{"ForAnyValue:StringLike":{"route53:VPCs":"VPCId=*,VPCRegion=%s"}}}]}
                        """.formatted(zoneArn, peer));
                assertEquals(403, assertThrows(Route53Exception.class,
                        () -> caller.associateVPCWithHostedZone(request -> request.hostedZoneId(zone).vpc(selected)))
                        .statusCode());
            } finally {
                admin.deleteHostedZone(request -> request.id(zone));
            }
        }
    }
    private String vpc(String region, String cidr) {
        String id = RequestScopes.callAs(ACCOUNT, region, () -> ec2.createVpc(region, cidr, false).getVpcId());
        cleanup.register(() -> RequestScopes.runAs(ACCOUNT, region, () -> ec2.deleteVpc(region, id)));
        return id;
    }
}
