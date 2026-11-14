package io.floci.aws.services.ec2;

import io.floci.aws.services.ec2.model.Instance;
import io.floci.aws.services.ec2.model.InstanceState;
import io.floci.aws.services.ec2.model.RouteTable;
import io.floci.aws.services.ec2.model.RouteTableAssociation;
import io.floci.aws.services.ec2.model.VpcEndpoint;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.util.List;
import java.util.Map;
import java.util.Optional;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

class S3GatewayEndpointResolverTest {
    private static final String REGION = "us-east-2";
    private final Ec2MetadataServer metadata = mock(Ec2MetadataServer.class);
    private final Ec2Service ec2 = mock(Ec2Service.class);
    private final S3GatewayEndpointResolver resolver = new S3GatewayEndpointResolver(metadata, ec2);
    private Instance guest;
    private RouteTable table;
    private VpcEndpoint endpoint;

    @BeforeEach
    void setUp() {
        guest = new Instance();
        guest.setInstanceId("i-fixture");
        guest.setOwnerId("111122223333");
        guest.setRegion(REGION);
        guest.setSubnetId("subnet-fixture");
        guest.setVpcId("vpc-fixture");
        guest.setState(InstanceState.running());
        when(metadata.registeredContainer("172.18.0.10")).thenReturn(Optional.of(guest));
        when(ec2.getInstance(REGION, guest.getInstanceId())).thenReturn(Optional.of(guest));
        table = new RouteTable();
        table.setRouteTableId("rtb-fixture");
        table.setVpcId(guest.getVpcId());
        RouteTableAssociation association = new RouteTableAssociation();
        association.setSubnetId(guest.getSubnetId());
        table.setAssociations(List.of(association));
        when(ec2.describeRouteTables(REGION, List.of(), Map.of("vpc-id", List.of(guest.getVpcId()))))
                .thenReturn(List.of(table));
        endpoint = new VpcEndpoint();
        endpoint.setVpcEndpointId("vpce-fixture");
        endpoint.setVpcId(guest.getVpcId());
        endpoint.setRegion(REGION);
        endpoint.setServiceName("com.amazonaws.us-east-2.s3");
        endpoint.setRouteTableIds(List.of(table.getRouteTableId()));
        when(ec2.describeVpcEndpoints(REGION, List.of(), Map.of())).thenReturn(List.of(endpoint));
    }

    @Test
    void resolvesExplicitAssociationAndInvalidatesRemovedEndpoint() {
        assertEquals(Optional.of(endpoint), resolver.resolve("172.18.0.10", REGION));
        when(ec2.describeVpcEndpoints(REGION, List.of(), Map.of())).thenReturn(List.of());
        assertTrue(resolver.resolve("172.18.0.10", REGION).isEmpty());
    }

    @Test
    void resolvesReloadedIdentityButRejectsStaleRegistration() {
        Instance reloaded = new Instance();
        reloaded.setInstanceId(guest.getInstanceId());
        reloaded.setOwnerId(guest.getOwnerId());
        reloaded.setRegion(guest.getRegion());
        reloaded.setVpcId(guest.getVpcId());
        reloaded.setSubnetId(guest.getSubnetId());
        reloaded.setState(InstanceState.running());
        when(ec2.getInstance(REGION, guest.getInstanceId())).thenReturn(Optional.of(reloaded));
        assertEquals(Optional.of(endpoint), resolver.resolve("172.18.0.10", REGION));
        reloaded.setState(InstanceState.stopped());
        assertTrue(resolver.resolve("172.18.0.10", REGION).isEmpty());
        reloaded.setState(InstanceState.running());
        reloaded.setOwnerId("444455556666");
        assertTrue(resolver.resolve("172.18.0.10", REGION).isEmpty());
    }

    @Test
    void mainTableAppliesOnlyWithoutExplicitSubnetAssociation() {
        RouteTable main = new RouteTable();
        main.setRouteTableId("rtb-main");
        RouteTableAssociation association = new RouteTableAssociation();
        association.setMain(true);
        main.setAssociations(List.of(association));
        endpoint.setRouteTableIds(List.of(main.getRouteTableId()));
        when(ec2.describeRouteTables(REGION, List.of(), Map.of("vpc-id", List.of(guest.getVpcId()))))
                .thenReturn(List.of(main, table));
        assertTrue(resolver.resolve("172.18.0.10", REGION).isEmpty());
        table.setAssociations(List.of());
        assertEquals(Optional.of(endpoint), resolver.resolve("172.18.0.10", REGION));
        association.setAssociationState("disassociated");
        assertTrue(resolver.resolve("172.18.0.10", REGION).isEmpty());
    }

    @Test
    void requiresLiveRecognizedGuestAndMatchingDestinationRegion() {
        assertTrue(resolver.resolve("172.18.0.11", REGION).isEmpty());
        assertTrue(resolver.resolve("172.18.0.10", "us-west-2").isEmpty());
        guest.setState(InstanceState.stopped());
        assertTrue(resolver.resolve("172.18.0.10", REGION).isEmpty());
        guest.setState(InstanceState.running());
        when(ec2.getInstance(REGION, guest.getInstanceId())).thenReturn(Optional.empty());
        assertTrue(resolver.resolve("172.18.0.10", REGION).isEmpty());
    }

    @Test
    void rejectsUnrelatedOrUnavailableEndpointsAndAmbiguousRoutes() {
        endpoint.setVpcId("vpc-other");
        assertTrue(resolver.resolve("172.18.0.10", REGION).isEmpty());
        endpoint.setVpcId(guest.getVpcId());
        endpoint.setVpcEndpointType("Interface");
        assertTrue(resolver.resolve("172.18.0.10", REGION).isEmpty());
        endpoint.setVpcEndpointType("Gateway");
        endpoint.setState("deleted");
        assertTrue(resolver.resolve("172.18.0.10", REGION).isEmpty());
        endpoint.setState("available");
        endpoint.setServiceName("com.amazonaws.us-east-2.dynamodb");
        assertTrue(resolver.resolve("172.18.0.10", REGION).isEmpty());
        endpoint.setServiceName("com.amazonaws.us-east-2.s3");
        when(ec2.describeVpcEndpoints(REGION, List.of(), Map.of())).thenReturn(List.of(endpoint, endpoint));
        assertTrue(resolver.resolve("172.18.0.10", REGION).isEmpty());
        when(ec2.describeVpcEndpoints(REGION, List.of(), Map.of())).thenReturn(List.of(endpoint));
        when(ec2.describeRouteTables(REGION, List.of(), Map.of("vpc-id", List.of(guest.getVpcId()))))
                .thenReturn(List.of(table, table));
        assertTrue(resolver.resolve("172.18.0.10", REGION).isEmpty());
    }
}
