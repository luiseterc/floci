package io.floci.aws.services.ec2;

import io.floci.aws.core.common.AwsRegionFacts;
import io.floci.aws.core.common.RequestScopes;
import io.floci.aws.services.ec2.model.Instance;
import io.floci.aws.services.ec2.model.RouteTable;
import io.floci.aws.services.ec2.model.RouteTableAssociation;
import io.floci.aws.services.ec2.model.VpcEndpoint;
import jakarta.enterprise.context.ApplicationScoped;
import jakarta.inject.Inject;

import java.util.List;
import java.util.Map;
import java.util.Optional;

/** Resolves the modeled gateway route using a registered guest's actual transport address. */
@ApplicationScoped
public class S3GatewayEndpointResolver {

    private final Ec2MetadataServer metadata;
    private final Ec2Service ec2;

    @Inject
    public S3GatewayEndpointResolver(Ec2MetadataServer metadata, Ec2Service ec2) {
        this.metadata = metadata;
        this.ec2 = ec2;
    }

    public Optional<VpcEndpoint> resolve(String address, String region) {
        if (address == null || region == null) {
            return Optional.empty();
        }
        Optional<Instance> registered = metadata.registeredContainer(address);
        if (registered.isEmpty()) {
            return Optional.empty();
        }
        Instance guest = registered.get();
        if (!region.equals(guest.getRegion()) || guest.getOwnerId() == null
                || guest.getSubnetId() == null || guest.getVpcId() == null
                || guest.getState() == null || guest.getState().getCode() != 16) {
            return Optional.empty();
        }
        return RequestScopes.callAs(guest.getOwnerId(), region, () -> resolveGuest(guest, region));
    }

    private Optional<VpcEndpoint> resolveGuest(Instance guest, String region) {
        Optional<Instance> current = ec2.getInstance(region, guest.getInstanceId());
        if (current.isEmpty() || !guest.getOwnerId().equals(current.get().getOwnerId())
                || !region.equals(current.get().getRegion())
                || !guest.getVpcId().equals(current.get().getVpcId())
                || !guest.getSubnetId().equals(current.get().getSubnetId())
                || current.get().getState() == null || current.get().getState().getCode() != 16) {
            return Optional.empty();
        }
        List<RouteTable> tables = ec2.describeRouteTables(region, List.of(),
                Map.of("vpc-id", List.of(guest.getVpcId())));
        List<RouteTable> explicit = tables.stream().filter(table -> table.getAssociations().stream()
                .anyMatch(association -> associated(association)
                        && guest.getSubnetId().equals(association.getSubnetId()))).toList();
        List<RouteTable> effective = explicit.isEmpty() ? tables.stream()
                .filter(table -> table.getAssociations().stream()
                        .anyMatch(association -> associated(association) && association.isMain())).toList() : explicit;
        if (effective.size() != 1) {
            return Optional.empty();
        }
        String tableId = effective.getFirst().getRouteTableId();
        List<VpcEndpoint> endpoints = ec2.describeVpcEndpoints(region, List.of(), Map.of()).stream()
                .filter(endpoint -> guest.getVpcId().equals(endpoint.getVpcId())
                        && "Gateway".equals(endpoint.getVpcEndpointType())
                        && "available".equals(endpoint.getState())
                        && AwsRegionFacts.vpcEndpointServiceName(region, "s3").equals(endpoint.getServiceName())
                        && endpoint.getRouteTableIds().contains(tableId)).toList();
        return endpoints.size() == 1 ? Optional.of(endpoints.getFirst()) : Optional.empty();
    }

    private static boolean associated(RouteTableAssociation association) {
        return "associated".equals(association.getAssociationState());
    }
}
