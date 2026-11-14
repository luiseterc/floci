package io.floci.aws.services.ec2;

import io.floci.aws.core.common.AwsArnUtils;
import io.floci.aws.services.ec2.model.VpcPeeringConnection;
import io.floci.aws.services.ec2.model.VpcPeeringConnectionVpcInfo;

import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;

/** Peering IAM identities use each endpoint's own account and region. */
public final class Ec2PeeringConditions {
    private static final Set<String> ACTIONS = Set.of("ec2:CreateVpcPeeringConnection",
            "ec2:AcceptVpcPeeringConnection", "ec2:RejectVpcPeeringConnection",
            "ec2:DeleteVpcPeeringConnection", "ec2:ModifyVpcPeeringConnectionOptions");

    private Ec2PeeringConditions() {
    }

    public static boolean supports(String action) {
        return action != null && ACTIONS.contains(action);
    }

    public static Map<String, List<String>> resolve(String action, Map<String, String> form,
                                                    String region, String account, Ec2Service service) {
        Map<String, List<String>> context = new LinkedHashMap<>();
        if ("ec2:CreateVpcPeeringConnection".equals(action)) {
            put(context, "ec2:RequesterVpc", region, account, form.get("VpcId"));
            String peerRegion = nonBlankOr(form.get("PeerRegion"), region);
            String peerId = form.get("PeerVpcId");
            if (peerId != null && !peerId.isBlank()) {
                // Match the service: a locally known peer's stored owner wins over a claimed PeerOwnerId.
                String peerOwner = service.findVpcOwnerAccount(peerRegion, peerId)
                        .orElseGet(() -> nonBlankOr(form.get("PeerOwnerId"), account));
                put(context, "ec2:AccepterVpc", peerRegion, peerOwner, peerId);
            }
        } else {
            VpcPeeringConnection connection = find(form.get("VpcPeeringConnectionId"), region, service);
            if (connection != null) {
                put(context, "ec2:RequesterVpc", connection.getRequesterVpcInfo());
                put(context, "ec2:AccepterVpc", connection.getAccepterVpcInfo());
            }
        }
        return context;
    }

    public static VpcPeeringConnection find(String id, String region, Ec2Service service) {
        if (id == null || id.isBlank()) {
            return null;
        }
        List<VpcPeeringConnection> connections = service.describeVpcPeeringConnections(region, List.of(id), Map.of());
        return connections.isEmpty() ? null : connections.getFirst();
    }

    public static String vpcArn(VpcPeeringConnectionVpcInfo side) {
        return AwsArnUtils.Arn.of("ec2", side.getRegion(), side.getOwnerId(), "vpc/" + side.getVpcId()).toString();
    }

    private static void put(Map<String, List<String>> context, String key, VpcPeeringConnectionVpcInfo side) {
        if (side != null) {
            put(context, key, side.getRegion(), side.getOwnerId(), side.getVpcId());
        }
    }

    private static void put(Map<String, List<String>> context, String key, String region, String account, String id) {
        if (id != null && !id.isBlank() && region != null && account != null) {
            context.put(key, List.of(AwsArnUtils.Arn.of("ec2", region, account, "vpc/" + id).toString()));
        }
    }

    private static String nonBlankOr(String value, String fallback) {
        return value == null || value.isBlank() ? fallback : value;
    }
}
