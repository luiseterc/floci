package io.floci.aws.services.ec2;

import io.floci.aws.services.ec2.model.Instance;
import io.floci.aws.services.ec2.model.LaunchTemplateData;
import io.floci.aws.services.ec2.model.Reservation;
import io.floci.aws.services.ec2.model.Tag;
import io.floci.aws.services.ec2.model.VolumeAttachment;

import java.util.ArrayList;
import java.util.List;

/** The effective launch inputs after Query parsing and launch-template overrides. */
public record Ec2RunInstancesRequest(
        String imageId, String instanceType, int minCount, int maxCount, String keyName,
        List<String> securityGroupIds, String subnetId, String clientToken, List<Tag> instanceTags,
        String userData, String iamInstanceProfileArn, Boolean associatePublicIp,
        String networkInterfaceId, int networkInterfaceDeviceIndex,
        LaunchTemplateData.MetadataOptions metadataOptions, String creditSpecificationCpuCredits,
        String encodedUserData, boolean dryRun, String hostId, String tenancy,
        List<LaunchTemplateData.BlockDeviceMapping> blockDeviceMappings, boolean spot,
        String privateIpAddress, LaunchTemplateData.CapacityReservationSpecification capacitySpecification,
        Boolean ebsOptimized, List<Tag> networkInterfaceTags, List<Tag> volumeTags, String launchTemplateId) {

    public Ec2RunInstancesRequest {
        securityGroupIds = List.copyOf(securityGroupIds);
        instanceTags = List.copyOf(instanceTags);
        blockDeviceMappings = List.copyOf(blockDeviceMappings);
        networkInterfaceTags = List.copyOf(networkInterfaceTags);
        volumeTags = List.copyOf(volumeTags);
    }

    Reservation run(Ec2Service service, String region) {
        Reservation result = service.runInstances(region, imageId, instanceType, minCount, maxCount,
                keyName, securityGroupIds, subnetId, clientToken, instanceTags, userData, iamInstanceProfileArn,
                associatePublicIp, networkInterfaceId, networkInterfaceDeviceIndex, null, metadataOptions,
                creditSpecificationCpuCredits, encodedUserData, dryRun, hostId, tenancy, blockDeviceMappings,
                spot, privateIpAddress, capacitySpecification);
        if (ebsOptimized != null) {
            for (Instance instance : result.getInstances()) {
                service.modifyInstanceAttribute(region, instance.getInstanceId(), "ebsOptimized", ebsOptimized.toString());
                instance.setEbsOptimized(ebsOptimized);
            }
        }
        if (!networkInterfaceTags.isEmpty()) {
            List<String> interfaceIds = new ArrayList<>();
            for (Instance instance : result.getInstances()) {
                instance.getNetworkInterfaces().forEach(networkInterface ->
                        interfaceIds.add(networkInterface.getNetworkInterfaceId()));
            }
            if (!interfaceIds.isEmpty()) {
                service.createTags(region, interfaceIds, networkInterfaceTags);
            }
        }
        if (!volumeTags.isEmpty()) {
            List<String> volumeIds = service.instanceVolumeAttachments(result.getInstances()).values().stream()
                    .flatMap(List::stream).map(VolumeAttachment::getVolumeId).distinct().toList();
            if (!volumeIds.isEmpty()) {
                service.createTags(region, volumeIds, volumeTags);
            }
        }
        return result;
    }
}
