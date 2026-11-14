package io.floci.aws.services.ec2;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.node.ArrayNode;
import com.fasterxml.jackson.databind.node.JsonNodeFactory;
import com.fasterxml.jackson.databind.node.ObjectNode;
import io.floci.aws.core.common.AwsException;
import io.floci.aws.core.common.IamConditionContextResolver;
import io.floci.aws.core.common.PreparedRequest;
import io.floci.aws.core.common.RequestPreparation;
import io.floci.aws.services.ec2.model.GroupIdentifier;
import io.floci.aws.services.ec2.model.LaunchTemplateData;
import io.floci.aws.services.ec2.model.Tag;
import jakarta.enterprise.context.ApplicationScoped;
import jakarta.inject.Inject;
import jakarta.ws.rs.container.ContainerRequestContext;
import jakarta.ws.rs.core.MultivaluedHashMap;
import jakarta.ws.rs.core.MultivaluedMap;

import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;

/** Projects the same launch inputs and service plan that execution consumes, without allocating resources. */
@ApplicationScoped
public class Ec2LaunchPreparation implements RequestPreparation {
    private final Ec2QueryHandler handler;
    private final Ec2Service service;

    @Inject
    public Ec2LaunchPreparation(Ec2QueryHandler handler, Ec2Service service) {
        this.handler = handler;
        this.service = service;
    }

    @Override
    public String operation() {
        return "ec2:RunInstances";
    }

    @Override
    public PreparedRequest prepare(ContainerRequestContext context, String region) {
        MultivaluedMap<String, String> params = new MultivaluedHashMap<>();
        IamConditionContextResolver.formParameters(context).forEach(params::putSingle);
        Ec2RunInstancesRequest request = handler.prepareRunInstances(params, region);
        Ec2Service.LaunchPreview preview = service.previewRunInstances(region, request);
        return new Launch(request, preview, projection(request, preview), networkIdentity(preview.network()));
    }

    public record Launch(Ec2RunInstancesRequest request, Ec2Service.LaunchPreview preview,
                          JsonNode model, List<String> networkIdentity) implements PreparedRequest {
        @Override
        public Map<String, List<String>> context(String type, String resource) {
            Map<String, List<String>> context = new LinkedHashMap<>();
            if ("image".equals(type) && preview.imageOwner() != null) {
                context.put("ec2:Owner", List.of(preview.imageOwner()));
            }
            if ("instance".equals(type)) {
                context.put("ec2:InstanceType", List.of(request.instanceType() == null ? "t2.micro" : request.instanceType()));
            }
            Map<String, String> tags = tags().getOrDefault(type, Map.of());
            tags.forEach((key, value) -> context.put("aws:RequestTag/" + key, List.of(value)));
            if (!tags.isEmpty()) {
                context.put("aws:TagKeys", List.copyOf(tags.keySet()));
            }
            return context;
        }

        @Override
        public Map<String, Map<String, String>> tags() {
            return Map.of("instance", tagMap(request.instanceTags()), "volume", tagMap(request.volumeTags()),
                    "network-interface", tagMap(request.networkInterfaceTags()));
        }

        private static Map<String, String> tagMap(List<Tag> tags) {
            Map<String, String> values = new LinkedHashMap<>();
            for (Tag tag : tags) {
                values.put(tag.getKey(), tag.getValue() == null ? "" : tag.getValue());
            }
            return values;
        }

        void verify(Ec2Service.LaunchNetwork network, String imageOwner, List<Ec2Service.LaunchVolume> volumes) {
            if (!networkIdentity.equals(Ec2LaunchPreparation.networkIdentity(network))
                    || !Objects.equals(preview.imageOwner(), imageOwner) || !preview.volumes().equals(volumes)) {
                throw new AwsException("InvalidParameterValue",
                        "Launch resources changed after authorization; retry the request.", 400);
            }
        }
    }

    static List<String> networkIdentity(Ec2Service.LaunchNetwork network) {
        return List.of(network.subnet() == null ? "" : network.subnet().getSubnetId(), network.vpcId(),
                network.availabilityZone(), network.suppliedInterface() == null ? ""
                        : network.suppliedInterface().getNetworkInterfaceId(),
                String.join(",", network.groups().stream().map(GroupIdentifier::getGroupId).sorted().toList()));
    }

    static JsonNode projection(Ec2RunInstancesRequest request, Ec2Service.LaunchPreview preview) {
        ObjectNode root = JsonNodeFactory.instance.objectNode();
        ObjectNode input = root.putObject("input");
        put(input, "KeyName", request.keyName());
        if (request.launchTemplateId() != null) {
            input.putObject("LaunchTemplate").put("LaunchTemplateId", request.launchTemplateId());
        }
        ArrayNode mappings = input.putArray("BlockDeviceMappings");
        for (LaunchTemplateData.BlockDeviceMapping mapping : request.blockDeviceMappings()) {
            if (mapping.getNoDevice() == null && mapping.getEbs() != null && mapping.getEbs().getSnapshotId() != null) {
                mappings.addObject().putObject("Ebs").put("SnapshotId", mapping.getEbs().getSnapshotId());
            }
        }
        ArrayNode tagSpecifications = input.putArray("TagSpecifications");
        tags(tagSpecifications, "instance", request.instanceTags());
        tags(tagSpecifications, "network-interface", request.networkInterfaceTags());
        tags(tagSpecifications, "volume", request.volumeTags());
        ObjectNode instance = root.putObject("output").putArray("Instances").addObject();
        instance.put("InstanceId", "*");
        instance.put("ImageId", request.imageId());
        if (request.capacitySpecification() != null
                && request.capacitySpecification().getCapacityReservationTarget() != null) {
            put(instance, "CapacityReservationId", request.capacitySpecification().getCapacityReservationTarget()
                    .getCapacityReservationId());
        }
        if (preview.network().subnet() != null) {
            instance.put("SubnetId", preview.network().subnet().getSubnetId());
        }
        ArrayNode groups = instance.putArray("SecurityGroups");
        for (GroupIdentifier group : preview.network().groups()) {
            groups.addObject().put("GroupId", group.getGroupId());
        }
        instance.putArray("NetworkInterfaces").addObject().put("NetworkInterfaceId",
                preview.network().suppliedInterface() == null ? "*"
                        : preview.network().suppliedInterface().getNetworkInterfaceId());
        ArrayNode devices = instance.putArray("BlockDeviceMappings");
        for (Ec2Service.LaunchVolume volume : preview.volumes()) {
            devices.addObject().put("DeviceName", volume.deviceName()).putObject("Ebs").put("VolumeId", "*");
        }
        return root;
    }

    private static void tags(ArrayNode specifications, String type, List<Tag> tags) {
        if (!tags.isEmpty()) {
            ArrayNode values = specifications.addObject().put("ResourceType", type).putArray("Tags");
            for (Tag tag : tags) {
                values.addObject().put("Key", tag.getKey()).put("Value", tag.getValue());
            }
        }
    }

    private static void put(ObjectNode node, String name, String value) {
        if (value != null && !value.isBlank()) {
            node.put(name, value);
        }
    }
}
