package io.floci.aws.services.ec2;

import io.floci.aws.services.ec2.model.GroupIdentifier;
import io.floci.aws.services.ec2.model.InstanceNetworkInterface;
import io.floci.aws.services.ec2.model.NetworkInterface;
import io.floci.aws.services.ec2.model.NetworkInterfacePrivateIpAddress;
import io.floci.aws.services.ec2.model.Subnet;
import io.floci.aws.services.ec2.model.Vpc;
import io.floci.aws.services.ec2.model.VpcCidrBlockAssociation;

import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

/** IPv4 IMDS fields derived from the interface and its existing network resources. */
final class Ec2NetworkMetadata {
    private Ec2NetworkMetadata() {}

    static Map<String, String> fields(InstanceNetworkInterface attached, NetworkInterface stored,
                                     Subnet subnet, Vpc vpc) {
        Map<String, String> result = new LinkedHashMap<>();
        put(result, "device-number", Integer.toString(attached.getDeviceIndex()));
        // The EC2 interface model currently represents one network card.
        put(result, "network-card", "0");
        put(result, "interface-id", attached.getNetworkInterfaceId());
        put(result, "mac", attached.getMacAddress());
        put(result, "owner-id", attached.getOwnerId());
        put(result, "subnet-id", attached.getSubnetId());
        put(result, "vpc-id", attached.getVpcId());
        put(result, "local-hostname", stored == null ? attached.getPrivateDnsName() : stored.getPrivateDnsName());
        Set<String> addresses = new LinkedHashSet<>();
        String primary = stored == null ? attached.getPrivateIpAddress() : stored.getPrivateIpAddress();
        if (primary != null && !primary.isBlank()) {
            addresses.add(primary);
        }
        if (stored != null) {
            for (NetworkInterfacePrivateIpAddress address : stored.getPrivateIpAddresses()) {
                if (address.getPrivateIpAddress() != null && !address.getPrivateIpAddress().isBlank()) {
                    addresses.add(address.getPrivateIpAddress());
                }
            }
        }
        put(result, "local-ipv4s", String.join("\n", addresses));
        List<GroupIdentifier> groups = stored == null ? attached.getGroups() : stored.getGroups();
        put(result, "security-group-ids", join(groups.stream().map(GroupIdentifier::getGroupId).toList()));
        put(result, "security-groups", join(groups.stream().map(GroupIdentifier::getGroupName).toList()));
        if (subnet != null) {
            put(result, "subnet-ipv4-cidr-block", subnet.getCidrBlock());
        }
        if (vpc != null) {
            put(result, "vpc-ipv4-cidr-block", vpc.getCidrBlock());
            Set<String> cidrs = new LinkedHashSet<>();
            if (vpc.getCidrBlock() != null) {
                cidrs.add(vpc.getCidrBlock());
            }
            for (VpcCidrBlockAssociation association : vpc.getCidrBlockAssociationSet()) {
                if ("associated".equals(association.getCidrBlockState()) && association.getCidrBlock() != null) {
                    cidrs.add(association.getCidrBlock());
                }
            }
            put(result, "vpc-ipv4-cidr-blocks", String.join("\n", cidrs));
        }
        return Map.copyOf(result);
    }

    private static String join(List<String> values) {
        return String.join("\n", values.stream().filter(value -> value != null && !value.isBlank()).distinct().toList());
    }

    private static void put(Map<String, String> fields, String key, String value) {
        if (value != null && !value.isBlank()) {
            fields.put(key, value);
        }
    }
}
