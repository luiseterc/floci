package io.floci.aws.services.ec2;

import org.junit.jupiter.api.Test;

import java.util.List;
import java.util.Map;
import java.util.Optional;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

class Ec2PeeringConditionsTest {
    @Test
    void defaultsPeerRegionAndAccountAndUsesStoredOwnerOverTheClaim() {
        Ec2Service service = mock(Ec2Service.class);
        when(service.findVpcOwnerAccount("cn-north-1", "vpc-peer")).thenReturn(Optional.empty());
        Map<String, String> form = Map.of("VpcId", "vpc-requester", "PeerVpcId", "vpc-peer");
        assertEquals(List.of("arn:aws-cn:ec2:cn-north-1:111122223333:vpc/vpc-peer"),
                Ec2PeeringConditions.resolve("ec2:CreateVpcPeeringConnection", form, "cn-north-1",
                        "111122223333", service).get("ec2:AccepterVpc"));
        when(service.findVpcOwnerAccount("cn-north-1", "vpc-peer")).thenReturn(Optional.of("444455556666"));
        Map<String, String> forged = Map.of("VpcId", "vpc-requester", "PeerVpcId", "vpc-peer",
                "PeerOwnerId", "111122223333");
        assertEquals(List.of("arn:aws-cn:ec2:cn-north-1:444455556666:vpc/vpc-peer"),
                Ec2PeeringConditions.resolve("ec2:CreateVpcPeeringConnection", forged, "cn-north-1",
                        "111122223333", service).get("ec2:AccepterVpc"));
    }

    @Test
    void anInvisibleConnectionDoesNotSupplyVpcConditions() {
        Ec2Service service = mock(Ec2Service.class);
        when(service.describeVpcPeeringConnections("eu-west-1", List.of("pcx-hidden"), Map.of())).thenReturn(List.of());
        assertTrue(Ec2PeeringConditions.resolve("ec2:DeleteVpcPeeringConnection",
                Map.of("VpcPeeringConnectionId", "pcx-hidden"), "eu-west-1", "111122223333", service).isEmpty());
        verify(service).describeVpcPeeringConnections("eu-west-1", List.of("pcx-hidden"), Map.of());
    }
}
