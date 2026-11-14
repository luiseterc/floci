package io.floci.aws.services.ec2;

import io.floci.aws.testing.AwsTestClients;
import io.quarkus.test.junit.QuarkusTest;
import org.junit.jupiter.api.Test;
import software.amazon.awssdk.regions.Region;
import software.amazon.awssdk.services.ec2.Ec2Client;
import software.amazon.awssdk.services.ec2.model.AssignedPrivateIpAddress;
import software.amazon.awssdk.services.ec2.model.Ec2Exception;
import software.amazon.awssdk.services.ec2.model.NetworkInterface;

import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

@QuarkusTest
class Ec2PrivateIpAssignmentIntegrationTest {
    @Test
    void secondaryAddressesRoundTripAndRejectedBatchesDoNotMutate() {
        try (Ec2Client ec2 = AwsTestClients.create(Ec2Client.builder(), "test", Region.EU_WEST_1)) {
            String vpc = ec2.createVpc(r -> r.cidrBlock("10.96.0.0/16")).vpc().vpcId();
            String subnet = ec2.createSubnet(r -> r.vpcId(vpc).cidrBlock("10.96.1.0/28")).subnet().subnetId();
            String first = ec2.createNetworkInterface(r -> r.subnetId(subnet).privateIpAddress("10.96.1.4"))
                    .networkInterface().networkInterfaceId();
            String second = ec2.createNetworkInterface(r -> r.subnetId(subnet).privateIpAddress("10.96.1.5"))
                    .networkInterface().networkInterfaceId();
            try {
                List<String> assigned = ec2.assignPrivateIpAddresses(r -> r.networkInterfaceId(first)
                        .privateIpAddresses("10.96.1.6", "10.96.1.7")).assignedPrivateIpAddresses().stream()
                        .map(AssignedPrivateIpAddress::privateIpAddress).toList();
                assertEquals(List.of("10.96.1.6", "10.96.1.7"), assigned);
                assertEquals(3, view(ec2, first).privateIpAddresses().size());
                try (Ec2Client foreign = AwsTestClients.create(Ec2Client.builder(), "111122223333", Region.EU_WEST_1);
                     Ec2Client otherRegion = AwsTestClients.create(Ec2Client.builder(), "test", Region.US_EAST_1)) {
                    for (Ec2Client scoped : List.of(foreign, otherRegion)) {
                        error("InvalidNetworkInterfaceID.NotFound", () -> scoped.assignPrivateIpAddresses(r ->
                                r.networkInterfaceId(first).secondaryPrivateIpAddressCount(1)));
                        error("InvalidNetworkInterfaceID.NotFound", () -> scoped.unassignPrivateIpAddresses(r ->
                                r.networkInterfaceId(first).privateIpAddresses("10.96.1.6")));
                    }
                }
                error("InvalidIPAddress.InUse", () -> ec2.assignPrivateIpAddresses(r -> r.networkInterfaceId(second)
                        .privateIpAddresses("10.96.1.8", "10.96.1.6")));
                assertEquals(1, view(ec2, second).privateIpAddresses().size());
                error("InvalidParameterValue", () -> ec2.unassignPrivateIpAddresses(r -> r.networkInterfaceId(first)
                        .privateIpAddresses("10.96.1.6", "10.96.1.4")));
                assertEquals(3, view(ec2, first).privateIpAddresses().size());
                error("InvalidParameterCombination", () -> ec2.assignPrivateIpAddresses(r -> r.networkInterfaceId(first)
                        .privateIpAddresses("10.96.1.8").secondaryPrivateIpAddressCount(1)));
                error("InvalidParameterValue", () -> ec2.assignPrivateIpAddresses(r -> r.networkInterfaceId(first)
                        .privateIpAddresses("10.96.1.0")));
                error("InvalidParameterValue", () -> ec2.assignPrivateIpAddresses(r -> r.networkInterfaceId(first)
                        .privateIpAddresses("10.96.2.8")));
                error("UnsupportedOperation", () -> ec2.assignPrivateIpAddresses(r -> r.networkInterfaceId(first)
                        .ipv4PrefixCount(1)));
                error("InsufficientFreeAddressesInSubnet", () -> ec2.assignPrivateIpAddresses(r -> r.networkInterfaceId(first)
                        .secondaryPrivateIpAddressCount(20)));
                assertEquals(3, view(ec2, first).privateIpAddresses().size());
                ec2.unassignPrivateIpAddresses(r -> r.networkInterfaceId(first).privateIpAddresses(assigned));
                ec2.assignPrivateIpAddresses(r -> r.networkInterfaceId(second).privateIpAddresses(assigned));
                assertEquals(3, view(ec2, second).privateIpAddresses().size());
                List<AssignedPrivateIpAddress> automatic = ec2.assignPrivateIpAddresses(r -> r.networkInterfaceId(first)
                        .secondaryPrivateIpAddressCount(2)).assignedPrivateIpAddresses();
                assertEquals(2, automatic.size());
                assertTrue(automatic.stream().noneMatch(ip -> assigned.contains(ip.privateIpAddress())));
            } finally {
                ec2.deleteNetworkInterface(r -> r.networkInterfaceId(first));
                ec2.deleteNetworkInterface(r -> r.networkInterfaceId(second));
                ec2.deleteSubnet(r -> r.subnetId(subnet));
                ec2.deleteVpc(r -> r.vpcId(vpc));
            }
        }
    }

    @Test
    void launchPrimarySupportsSecondaryAddressesAndInstanceLimits() {
        try (Ec2Client ec2 = AwsTestClients.create(Ec2Client.builder(), "test", Region.EU_WEST_1)) {
            String vpc = ec2.createVpc(r -> r.cidrBlock("10.97.0.0/16")).vpc().vpcId();
            String subnet = ec2.createSubnet(r -> r.vpcId(vpc).cidrBlock("10.97.1.0/24")).subnet().subnetId();
            String instance = ec2.runInstances(r -> r.imageId("ami-test").instanceType("t3.micro")
                    .minCount(1).maxCount(1).subnetId(subnet)).instances().getFirst().instanceId();
            try {
                String eni = ec2.describeInstances(r -> r.instanceIds(instance)).reservations().getFirst()
                        .instances().getFirst().networkInterfaces().getFirst().networkInterfaceId();
                ec2.assignPrivateIpAddresses(r -> r.networkInterfaceId(eni).secondaryPrivateIpAddressCount(1));
                assertEquals(2, view(ec2, eni).privateIpAddresses().size());
                assertEquals(2, ec2.describeInstances(r -> r.instanceIds(instance)).reservations().getFirst()
                        .instances().getFirst().networkInterfaces().getFirst().privateIpAddresses().size());
                error("PrivateIpAddressLimitExceeded", () -> ec2.assignPrivateIpAddresses(r -> r.networkInterfaceId(eni)
                        .secondaryPrivateIpAddressCount(100)));
                assertEquals(2, view(ec2, eni).privateIpAddresses().size());
            } finally {
                ec2.terminateInstances(r -> r.instanceIds(instance));
                ec2.deleteSubnet(r -> r.subnetId(subnet));
                ec2.deleteVpc(r -> r.vpcId(vpc));
            }
        }
    }

    private static NetworkInterface view(Ec2Client ec2, String id) {
        return ec2.describeNetworkInterfaces(r -> r.networkInterfaceIds(id)).networkInterfaces().getFirst();
    }

    private static void error(String code, Runnable action) {
        assertEquals(code, assertThrows(Ec2Exception.class, action::run).awsErrorDetails().errorCode());
    }
}
