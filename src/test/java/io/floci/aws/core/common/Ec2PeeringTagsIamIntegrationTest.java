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
import software.amazon.awssdk.services.ec2.model.Ec2Exception;

import java.net.URI;
import java.util.List;
import java.util.UUID;

import static io.floci.aws.testing.EnforcementFixtures.auth;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

@QuarkusTest
@TestProfile(IamEnforcementProfile.class)
class Ec2PeeringTagsIamIntegrationTest {
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
    void scopedGrantsAndDeniesCheckEachConnectionInTheRequestedRegion(String partition, String home, String peer) {
        String name = "peering-tags-" + UUID.randomUUID();
        UserCredentials credentials = EnforcementFixtures.createUser(cleanup, endpoint.getPort(), auth(ACCOUNT, home, "iam"), name);
        String requester = vpc(home, "10.84.0.0/16");
        String accepter = vpc(peer, "10.85.0.0/16");
        String id = RequestScopes.callAs(ACCOUNT, home, () -> ec2.createVpcPeeringConnection(home,
                requester, accepter, ACCOUNT, peer, List.of(new Tag("Side", "requester"))).getVpcPeeringConnectionId());
        cleanup.register(() -> RequestScopes.runAs(ACCOUNT, home, () -> ec2.deleteVpcPeeringConnection(home, id)));
        String otherRequester = vpc(home, "10.86.0.0/16");
        String other = RequestScopes.callAs(ACCOUNT, home, () -> ec2.createVpcPeeringConnection(home,
                otherRequester, accepter, ACCOUNT, peer, List.of()).getVpcPeeringConnectionId());
        cleanup.register(() -> RequestScopes.runAs(ACCOUNT, home, () -> ec2.deleteVpcPeeringConnection(home, other)));
        String arn = "arn:" + partition + ":ec2:" + peer + ":" + ACCOUNT + ":vpc-peering-connection/" + id;
        policy(home, name, """
                {"Statement":[{"Effect":"Allow","Action":"ec2:CreateTags","Resource":"%s",
                "Condition":{"Null":{"aws:ResourceTag/Side":"true"},
                "StringEquals":{"aws:RequestTag/Side":"accepter"}}}]}
                """.formatted(arn));
        try (Ec2Client caller = AwsTestClients.create(Ec2Client.builder(), credentials.accessKeyId(),
                credentials.secretAccessKey(), Region.of(peer), endpoint)) {
            assertEquals(403, assertThrows(Ec2Exception.class, () -> caller.createTags(request -> request.resources(id, other)
                    .tags(tag -> tag.key("Side").value("accepter")))).statusCode());
            assertTrue(tags(peer, id).isEmpty());
            caller.createTags(request -> request.resources(id).tags(tag -> tag.key("Side").value("accepter")));
            assertEquals("accepter", tags(peer, id).getFirst().getValue());
            assertEquals("requester", tags(home, id).getFirst().getValue());
            String deletion = """
                    {"Statement":[{"Effect":"Allow","Action":"ec2:DeleteTags","Resource":"%s",
                    "Condition":{"StringEquals":{"aws:ResourceTag/Side":"%s"}}}]}
                    """;
            policy(home, name, deletion.formatted(arn, "requester"));
            assertEquals(403, assertThrows(Ec2Exception.class, () -> caller.deleteTags(request -> request.resources(id)
                    .tags(tag -> tag.key("Side")))).statusCode());
            policy(home, name, deletion.formatted(arn, "accepter"));
            caller.deleteTags(request -> request.resources(id).tags(tag -> tag.key("Side")));
            assertTrue(tags(peer, id).isEmpty());
            assertEquals("requester", tags(home, id).getFirst().getValue());
            policy(home, name, """
                    {"Statement":[{"Effect":"Allow","Action":"ec2:CreateTags","Resource":"*"},
                    {"Effect":"Deny","Action":"ec2:CreateTags","Resource":"%s"}]}
                    """.formatted(arn));
            assertEquals(403, assertThrows(Ec2Exception.class, () -> caller.createTags(request -> request.resources(id)
                    .tags(tag -> tag.key("Side").value("denied")))).statusCode());
            assertTrue(tags(peer, id).isEmpty());
        }
    }

    private List<Tag> tags(String region, String id) {
        return RequestScopes.callAs(ACCOUNT, region, () -> ec2.resourceTags(region, id));
    }

    private void policy(String region, String name, String document) {
        EnforcementFixtures.putUserPolicy(endpoint.getPort(), auth(ACCOUNT, region, "iam"), name, "tag", document);
    }

    private String vpc(String region, String cidr) {
        String id = RequestScopes.callAs(ACCOUNT, region, () -> ec2.createVpc(region, cidr, false).getVpcId());
        cleanup.register(() -> RequestScopes.runAs(ACCOUNT, region, () -> ec2.deleteVpc(region, id)));
        return id;
    }
}
