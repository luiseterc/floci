package io.floci.aws.core.common;

import io.floci.aws.services.ec2.Ec2Service;
import io.floci.aws.services.ec2.model.Tag;
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
import software.amazon.awssdk.services.ec2.Ec2Client;
import software.amazon.awssdk.services.ec2.model.CreateVpcPeeringConnectionRequest;
import software.amazon.awssdk.services.ec2.model.Ec2Exception;
import software.amazon.awssdk.services.ec2.model.ResourceType;

import java.net.URI;
import java.util.List;
import java.util.UUID;

import static io.floci.aws.testing.EnforcementFixtures.auth;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

@QuarkusTest
@TestProfile(IamEnforcementProfile.class)
class Ec2VpcPeeringConditionIntegrationTest {
    private static final String REQUESTER = "000000000000";
    private static final String ACCEPTER = "111122223333";
    @Inject
    Ec2Service ec2;
    @TestHTTPResource("/")
    URI endpoint;
    @RegisterExtension
    final PartitionCleanup cleanup = new PartitionCleanup();

    @ParameterizedTest
    @CsvSource({"aws,us-east-1,eu-west-1", "aws-us-gov,us-gov-west-1,us-gov-east-1",
            "aws-cn,cn-north-1,cn-northwest-1"})
    void crossAccountPeeringUsesBothVpcIdentitiesAndChecksTheAccepterVpc(String partition, String home, String peer) {
        String name = "peering-condition-" + UUID.randomUUID();
        UserCredentials requesterUser = EnforcementFixtures.createUser(cleanup, endpoint.getPort(),
                auth(REQUESTER, home, "iam"), name);
        UserCredentials accepterUser = EnforcementFixtures.createUser(cleanup, endpoint.getPort(),
                auth(ACCEPTER, peer, "iam"), name);
        String requester = vpc(REQUESTER, home, "10.80.0.0/16");
        String accepter = vpc(ACCEPTER, peer, "10.81.0.0/16");
        String requesterArn = "arn:" + partition + ":ec2:" + home + ":" + REQUESTER + ":vpc/" + requester;
        String accepterArn = "arn:" + partition + ":ec2:" + peer + ":" + ACCEPTER + ":vpc/" + accepter;
        String requesterPeeringArn = "arn:" + partition + ":ec2:" + home + ":" + REQUESTER + ":vpc-peering-connection/*";
        String accepterPeeringArn = "arn:" + partition + ":ec2:" + peer + ":" + ACCEPTER + ":vpc-peering-connection/*";
        CreateVpcPeeringConnectionRequest request = CreateVpcPeeringConnectionRequest.builder().vpcId(requester)
                .peerVpcId(accepter).peerRegion(peer).peerOwnerId(ACCEPTER)
                .tagSpecifications(spec -> spec.resourceType(ResourceType.VPC_PEERING_CONNECTION)
                        .tags(tag -> tag.key("Purpose").value("Peering"))).build();
        try (Ec2Client caller = client(requesterUser, home); Ec2Client accepting = client(accepterUser, peer)) {
            String createPolicy = """
                    {"Version":"2012-10-17","Statement":[
                     {"Effect":"Allow","Action":"ec2:CreateVpcPeeringConnection","Resource":"%s",
                      "Condition":{"StringEquals":{"ec2:ResourceTag/Purpose":"Peering"}}},
                     {"Effect":"Allow","Action":"ec2:CreateVpcPeeringConnection","Resource":"%s",
                      "Condition":{"ArnEquals":{"ec2:AccepterVpc":"%s","ec2:RequesterVpc":"%s"},
                      "StringEquals":{"aws:RequestTag/Purpose":"Peering"}}},
                     {"Effect":"Allow","Action":"ec2:CreateTags","Resource":"%s",
                      "Condition":{"StringEquals":{"ec2:CreateAction":"CreateVpcPeeringConnection"}}}]}
                    """;
            policy(REQUESTER, home, name, createPolicy.formatted(requesterArn, requesterPeeringArn,
                    accepterArn + "wrong", requesterArn, requesterPeeringArn));
            assertEquals(403, assertThrows(Ec2Exception.class, () -> caller.createVpcPeeringConnection(request)).statusCode());
            policy(REQUESTER, home, name, createPolicy.formatted(requesterArn, requesterPeeringArn,
                    accepterArn, requesterArn, requesterPeeringArn));
            String id = caller.createVpcPeeringConnection(request).vpcPeeringConnection().vpcPeeringConnectionId();
            cleanup.register(() -> RequestScopes.runAs(REQUESTER, home, () -> ec2.deleteVpcPeeringConnection(home, id)));
            String grant = """
                    {"Effect":"Allow","Action":"ec2:AcceptVpcPeeringConnection","Resource":"%s",
                    "Condition":{"ArnEquals":{"ec2:RequesterVpc":"%s","ec2:AccepterVpc":"%s"}}}
                    """.formatted(accepterPeeringArn, requesterArn, accepterArn);
            policy(ACCEPTER, peer, name, "{\"Statement\":[" + grant + "]}");
            // Permission on the connection alone must not skip the accepter VPC's own authorization.
            assertEquals(403, assertThrows(Ec2Exception.class,
                    () -> accepting.acceptVpcPeeringConnection(value -> value.vpcPeeringConnectionId(id))).statusCode());
            policy(ACCEPTER, peer, name, """
                    {"Statement":[%s,{"Effect":"Allow","Action":"ec2:AcceptVpcPeeringConnection","Resource":"%s",
                    "Condition":{"StringEquals":{"ec2:ResourceTag/Purpose":"Peering"}}}]}
                    """.formatted(grant, accepterArn));
            assertEquals("active", accepting.acceptVpcPeeringConnection(value -> value.vpcPeeringConnectionId(id))
                    .vpcPeeringConnection().status().codeAsString());
            String deletePolicy = """
                    {"Statement":[{"Effect":"Allow","Action":"ec2:DeleteVpcPeeringConnection","Resource":"%s"},
                    {"Effect":"Deny","Action":"ec2:DeleteVpcPeeringConnection","Resource":"%s",
                    "Condition":{"ArnEquals":{"ec2:AccepterVpc":"%s"}}}]}
                    """;
            policy(REQUESTER, home, name, deletePolicy.formatted(requesterPeeringArn, requesterPeeringArn, accepterArn));
            assertEquals(403, assertThrows(Ec2Exception.class,
                    () -> caller.deleteVpcPeeringConnection(value -> value.vpcPeeringConnectionId(id))).statusCode());
            policy(REQUESTER, home, name, """
                    {"Statement":[{"Effect":"Allow","Action":"ec2:DeleteVpcPeeringConnection","Resource":"%s",
                    "Condition":{"ArnEquals":{"ec2:RequesterVpc":"%s","ec2:AccepterVpc":"%s"}}}]}
                    """.formatted(requesterPeeringArn, requesterArn, accepterArn));
            assertTrue(caller.deleteVpcPeeringConnection(value -> value.vpcPeeringConnectionId(id)).returnValue());
        }
    }

    private Ec2Client client(UserCredentials credentials, String region) {
        return AwsTestClients.create(Ec2Client.builder(), credentials.accessKeyId(), credentials.secretAccessKey(),
                Region.of(region), endpoint);
    }

    private void policy(String account, String region, String name, String document) {
        EnforcementFixtures.putUserPolicy(endpoint.getPort(), auth(account, region, "iam"), name, "peering", document);
    }

    private String vpc(String account, String region, String cidr) {
        String id = RequestScopes.callAs(account, region, () -> ec2.createVpc(region, cidr, false).getVpcId());
        RequestScopes.runAs(account, region, () -> ec2.createTags(region, List.of(id), List.of(new Tag("Purpose", "Peering"))));
        cleanup.register(() -> RequestScopes.runAs(account, region, () -> ec2.deleteVpc(region, id)));
        return id;
    }
}
