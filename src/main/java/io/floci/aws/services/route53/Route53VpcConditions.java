package io.floci.aws.services.route53;

import io.floci.aws.core.common.XmlParser;
import jakarta.ws.rs.core.MultivaluedMap;

import java.util.List;
import java.util.Map;
import java.util.Set;

/** The composite VPC identity Route 53 exposes to IAM for private hosted zone operations. */
public final class Route53VpcConditions {
    private static final Set<String> ACTIONS = Set.of("route53:CreateHostedZone",
            "route53:AssociateVPCWithHostedZone", "route53:DisassociateVPCFromHostedZone",
            "route53:CreateVPCAssociationAuthorization", "route53:DeleteVPCAssociationAuthorization",
            "route53:ListHostedZonesByVPC");

    private Route53VpcConditions() {
    }

    public static boolean supports(String action) {
        return action != null && ACTIONS.contains(action);
    }

    public static Map<String, List<String>> resolve(String action, String body,
                                                    MultivaluedMap<String, String> query) {
        String id;
        String region;
        if ("route53:ListHostedZonesByVPC".equals(action)) {
            id = query.getFirst("vpcid");
            region = query.getFirst("vpcregion");
        } else {
            // Read the same first VPC group the controller uses, including namespace-qualified XML.
            List<Map<String, String>> groups = XmlParser.extractGroups(body, "VPC");
            if (groups.isEmpty()) {
                return null;
            }
            id = groups.getFirst().get("VPCId");
            region = groups.getFirst().get("VPCRegion");
        }
        if (id == null || id.isBlank() || region == null || region.isBlank()) {
            return null;
        }
        return Map.of("route53:VPCs", List.of("VPCId=" + id + ",VPCRegion=" + region));
    }
}
