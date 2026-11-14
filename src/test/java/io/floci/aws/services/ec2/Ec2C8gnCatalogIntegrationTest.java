package io.floci.aws.services.ec2;

import io.floci.aws.testing.AwsTestClients;
import io.quarkus.test.junit.QuarkusTest;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvFileSource;
import software.amazon.awssdk.regions.Region;
import software.amazon.awssdk.services.ec2.Ec2Client;
import software.amazon.awssdk.services.ec2.model.InstanceTypeInfo;
import software.amazon.awssdk.services.ec2.model.LocationType;
import software.amazon.awssdk.services.ec2.model.NetworkCardInfo;

import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

@QuarkusTest
class Ec2C8gnCatalogIntegrationTest {
    @ParameterizedTest
    @CsvFileSource(resources = "/ec2/c8gn-instance-types.csv", numLinesToSkip = 1)
    void instanceReadAndNetworkCardsMatchAwsSnapshot(String name, int vcpus, long memoryMib,
            int ipv4PerInterface, String interfacesPerCard) {
        try (Ec2Client ec2 = AwsTestClients.create(Ec2Client.builder(), "test", Region.EU_WEST_1)) {
            List<InstanceTypeInfo> types = ec2.describeInstanceTypes(r -> r.instanceTypesWithStrings(name)).instanceTypes();
            assertEquals(1, types.size());
            InstanceTypeInfo type = types.getFirst();
            assertEquals(name, type.instanceTypeAsString());
            assertEquals(vcpus, type.vCpuInfo().defaultVCpus());
            assertEquals(memoryMib, type.memoryInfo().sizeInMiB());
            assertEquals(List.of("arm64"), type.processorInfo().supportedArchitecturesAsStrings());
            assertEquals("AWS", type.processorInfo().manufacturer());
            assertTrue(type.currentGeneration());
            assertFalse(type.instanceStorageSupported());
            assertFalse(type.burstablePerformanceSupported());
            assertTrue(type.networkInfo().encryptionInTransitSupported());
            assertEquals(0, type.networkInfo().defaultNetworkCardIndex());
            assertEquals(ipv4PerInterface, type.networkInfo().ipv4AddressesPerInterface());
            String[] capacities = interfacesPerCard.split("\\|");
            assertEquals(capacities.length, type.networkInfo().networkCards().size());
            for (int index = 0; index < capacities.length; index++) {
                NetworkCardInfo card = type.networkInfo().networkCards().get(index);
                assertEquals(index, card.networkCardIndex());
                assertEquals(Integer.parseInt(capacities[index]), card.maximumNetworkInterfaces());
            }
            assertEquals(List.of(name), ec2.describeInstanceTypeOfferings(r -> r
                    .locationType(LocationType.REGION).filters(f -> f.name("instance-type").values(name)))
                    .instanceTypeOfferings().stream().map(offering -> offering.instanceTypeAsString()).toList());
        }
    }
}
