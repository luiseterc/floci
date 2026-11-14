package io.floci.aws.services.ec2;

import io.floci.aws.config.EmulatorConfig;
import io.floci.aws.core.common.AwsException;
import io.floci.aws.core.common.RegionResolver;
import io.floci.aws.core.storage.InMemoryStorage;
import io.floci.aws.services.ec2.model.BlockDeviceMapping;
import io.floci.aws.services.ec2.model.EbsBlockDevice;
import io.floci.aws.services.ec2.model.GroupIdentifier;
import io.floci.aws.services.ec2.model.Image;
import io.floci.aws.services.ec2.model.Instance;
import io.floci.aws.services.ec2.model.LaunchTemplate;
import io.floci.aws.services.ec2.model.LaunchTemplateData;
import io.floci.aws.services.ec2.model.NetworkInterface;
import io.floci.aws.services.ec2.model.SecurityGroup;
import io.floci.aws.services.ec2.model.Subnet;
import io.floci.aws.services.ec2.model.Tag;
import io.floci.aws.services.ec2.model.Volume;
import io.floci.aws.services.ec2.model.Vpc;
import io.floci.aws.services.ec2.portforward.Ec2PortForwardManager;
import jakarta.ws.rs.container.ContainerRequestContext;
import jakarta.ws.rs.core.MultivaluedHashMap;
import jakarta.ws.rs.core.MultivaluedMap;
import org.junit.jupiter.api.Test;

import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.Mockito.doReturn;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.spy;
import static org.mockito.Mockito.when;

class Ec2RunInstancesPreparationTest {
    private static final String REGION = "us-east-1";
    private final InMemoryStorage<String, Vpc> vpcs = new InMemoryStorage<>();
    private final InMemoryStorage<String, Subnet> subnets = new InMemoryStorage<>();
    private final InMemoryStorage<String, SecurityGroup> groups = new InMemoryStorage<>();
    private final InMemoryStorage<String, Instance> instances = new InMemoryStorage<>();
    private final InMemoryStorage<String, Volume> volumes = new InMemoryStorage<>();
    private final EmulatorConfig config = mock(EmulatorConfig.class);
    private final Ec2Service service = service();
    private final Ec2QueryHandler handler = new Ec2QueryHandler(service, config, mock(FlowLogService.class),
            mock(Ec2EbsEncryptionService.class), mock(Ec2BlockPublicAccessService.class),
            mock(Ec2IpamService.class), mock(RegionResolver.class));

    @Test
    void previewDoesNotSeedDefaultsOrCreateInstancesAndVolumes() {
        Ec2RunInstancesRequest request = handler.prepareRunInstances(params(), REGION);
        Ec2Service.LaunchPreview preview = service.previewRunInstances(REGION, request);
        assertEquals(1, preview.network().groups().size());
        assertEquals(1, preview.volumes().size());
        assertTrue(vpcs.scan(key -> true).isEmpty());
        assertTrue(subnets.scan(key -> true).isEmpty());
        assertTrue(groups.scan(key -> true).isEmpty());
        assertTrue(instances.scan(key -> true).isEmpty());
        assertTrue(volumes.scan(key -> true).isEmpty());

        Instance actual = request.run(service, REGION).getInstances().getFirst();
        assertEquals(preview.network().subnet().getSubnetId(), actual.getSubnetId());
        assertEquals(preview.network().groups().getFirst().getGroupId(),
                actual.getSecurityGroups().getFirst().getGroupId());
        assertEquals(preview.volumes().size(), volumes.scan(key -> true).size());
    }

    @Test
    void explicitlyNamedDefaultGroupCanBePreviewedBeforeLazySeeding() {
        Ec2Service.LaunchPreview initial = service.previewRunInstances(REGION,
                handler.prepareRunInstances(params(), REGION));
        MultivaluedMap<String, String> params = params();
        String group = initial.network().groups().getFirst().getGroupId();
        params.putSingle("SecurityGroupId.1", group);
        Ec2RunInstancesRequest request = handler.prepareRunInstances(params, REGION);
        assertEquals(group, service.previewRunInstances(REGION, request).network().groups().getFirst().getGroupId());
        assertTrue(vpcs.scan(key -> true).isEmpty());
        assertEquals(group, request.run(service, REGION).getInstances().getFirst().getSecurityGroups()
                .getFirst().getGroupId());
    }

    @Test
    void invalidPreviewLeavesTheDefaultNetworkUnseeded() {
        MultivaluedMap<String, String> params = params();
        params.remove("ImageId");
        Ec2RunInstancesRequest request = handler.prepareRunInstances(params, REGION);
        assertThrows(AwsException.class, () -> service.previewRunInstances(REGION, request));
        assertTrue(vpcs.scan(key -> true).isEmpty());
    }

    @Test
    void existingInterfaceDeterminesSubnetAndGroups() {
        Vpc vpc = service.createVpc(REGION, "10.65.0.0/16", false);
        Subnet subnet = service.createSubnet(REGION, vpc.getVpcId(), "10.65.1.0/24", REGION + "b");
        SecurityGroup group = service.createSecurityGroup(REGION, "attached", "attached", vpc.getVpcId());
        NetworkInterface eni = service.createNetworkInterface(REGION, subnet.getSubnetId(), "primary", null,
                List.of(), List.of(group.getGroupId()), List.of());
        MultivaluedMap<String, String> params = params();
        params.putSingle("NetworkInterface.1.NetworkInterfaceId", eni.getNetworkInterfaceId());
        params.putSingle("SecurityGroupId.1", "sg-unused");
        Ec2RunInstancesRequest request = handler.prepareRunInstances(params, REGION);
        Ec2Service.LaunchPreview preview = service.previewRunInstances(REGION, request);
        assertEquals(subnet.getSubnetId(), preview.network().subnet().getSubnetId());
        assertEquals(group.getGroupId(), preview.network().groups().getFirst().getGroupId());
        assertNull(eni.getAttachment());
        assertTrue(instances.scan(key -> true).isEmpty());
        Instance actual = request.run(service, REGION).getInstances().getFirst();
        assertEquals(subnet.getSubnetId(), actual.getSubnetId());
        assertEquals(group.getGroupId(), actual.getSecurityGroups().getFirst().getGroupId());
    }

    @Test
    void templateDefaultsAndExplicitOverridesUseTheSameParserAsExecution() {
        LaunchTemplateData data = new LaunchTemplateData();
        data.setImageId("ami-template");
        data.setInstanceType("t3.small");
        data.setTagSpecifications(List.of(new LaunchTemplateData.TagSpecification("instance",
                List.of(new Tag("owner", "template"), new Tag("keep", "yes")))));
        LaunchTemplate template = service.createLaunchTemplate(REGION, "preview", data, List.of());
        MultivaluedMap<String, String> params = params();
        params.remove("ImageId");
        params.putSingle("LaunchTemplate.LaunchTemplateId", template.getLaunchTemplateId());
        params.putSingle("InstanceType", "t3.micro");
        params.putSingle("TagSpecification.1.ResourceType", "instance");
        params.putSingle("TagSpecification.1.Tag.1.Key", "owner");
        params.putSingle("TagSpecification.1.Tag.1.Value", "request");
        Ec2RunInstancesRequest request = handler.prepareRunInstances(params, REGION);
        assertEquals("ami-template", request.imageId());
        assertEquals("t3.micro", request.instanceType());
        assertEquals(List.of("owner=request", "keep=yes"), request.instanceTags().stream()
                .map(tag -> tag.getKey() + "=" + tag.getValue()).toList());
        assertTrue(instances.scan(key -> true).isEmpty());
        Instance actual = request.run(service, REGION).getInstances().getFirst();
        assertEquals(request.imageId(), actual.getImageId());
        assertEquals(request.instanceType(), actual.getInstanceType());
    }

    @Test
    void previewUsesTrustedImageOwnershipAndMergedVolumesWithoutChangingTheImage() {
        Image image = service.registerImage(REGION, "preview-image", "", "x86_64", "/dev/sda1",
                List.of(device("/dev/sda1", 16), device("/dev/sdf", 8)));
        MultivaluedMap<String, String> params = params();
        params.putSingle("ImageId", image.getImageId());
        params.putSingle("Owner", "amazon");
        params.putSingle("BlockDeviceMapping.1.DeviceName", "/dev/sda1");
        params.putSingle("BlockDeviceMapping.1.Ebs.VolumeSize", "24");
        params.putSingle("BlockDeviceMapping.2.DeviceName", "/dev/sdf");
        params.putSingle("BlockDeviceMapping.2.NoDevice", "");
        Ec2RunInstancesRequest request = handler.prepareRunInstances(params, REGION);
        Ec2Service.LaunchPreview preview = service.previewRunInstances(REGION, request);
        assertEquals("000000000000", preview.imageOwnerId());
        assertEquals("000000000000", preview.imageOwner());
        assertEquals(List.of(24), preview.volumes().stream().map(Ec2Service.LaunchVolume::size).toList());
        assertEquals(16, image.getBlockDeviceMappings().getFirst().getEbs().getVolumeSize());
        assertTrue(volumes.scan(key -> true).isEmpty());
        request.run(service, REGION);
        assertEquals(List.of(24), volumes.scan(key -> true).stream().map(Volume::getSize).toList());
    }

    @Test
    void missingLaunchTemplateDoesNotSeedDefaultsDuringPreparation() {
        MultivaluedMap<String, String> params = params();
        params.putSingle("LaunchTemplate.LaunchTemplateId", "lt-missing");
        assertThrows(AwsException.class, () -> handler.prepareRunInstances(params, REGION));
        assertTrue(vpcs.scan(key -> true).isEmpty());
        assertTrue(subnets.scan(key -> true).isEmpty());
    }

    @Test
    void changingAnInterfacesGroupsAfterPreparationFailsBeforeLaunching() {
        Vpc vpc = service.createVpc(REGION, "10.66.0.0/16", false);
        Subnet subnet = service.createSubnet(REGION, vpc.getVpcId(), "10.66.1.0/24", REGION + "b");
        SecurityGroup original = service.createSecurityGroup(REGION, "original", "original", vpc.getVpcId());
        SecurityGroup changed = service.createSecurityGroup(REGION, "changed", "changed", vpc.getVpcId());
        NetworkInterface eni = service.createNetworkInterface(REGION, subnet.getSubnetId(), "primary", null,
                List.of(), List.of(original.getGroupId()), List.of());
        MultivaluedMap<String, String> params = params();
        params.putSingle("NetworkInterface.1.NetworkInterfaceId", eni.getNetworkInterfaceId());
        Map<String, String> form = new LinkedHashMap<>();
        params.forEach((key, values) -> form.put(key, values.getFirst()));
        ContainerRequestContext context = mock(ContainerRequestContext.class);
        when(context.getProperty("floci.bufferedFormBody")).thenReturn(form);
        Ec2LaunchPreparation.Launch prepared = (Ec2LaunchPreparation.Launch)
                new Ec2LaunchPreparation(handler, service).prepare(context, REGION);
        eni.getGroups().clear();
        eni.getGroups().add(new GroupIdentifier(changed.getGroupId(), "changed"));
        Ec2Service guarded = spy(service);
        doReturn(prepared).when(guarded).preparedLaunch();
        AwsException failure = assertThrows(AwsException.class, () -> prepared.request().run(guarded, REGION));
        assertTrue(failure.getMessage().contains("changed after authorization"));
        assertTrue(instances.scan(key -> true).isEmpty());
        assertTrue(volumes.scan(key -> true).isEmpty());
        assertNull(eni.getAttachment());
    }

    private static BlockDeviceMapping device(String name, int size) {
        BlockDeviceMapping mapping = new BlockDeviceMapping();
        mapping.setDeviceName(name);
        EbsBlockDevice ebs = new EbsBlockDevice();
        ebs.setVolumeSize(size);
        ebs.setVolumeType("gp3");
        mapping.setEbs(ebs);
        return mapping;
    }

    private static MultivaluedMap<String, String> params() {
        MultivaluedMap<String, String> params = new MultivaluedHashMap<>();
        params.putSingle("ImageId", "ami-preview");
        params.putSingle("MinCount", "1");
        params.putSingle("MaxCount", "1");
        return params;
    }

    private Ec2Service service() {
        EmulatorConfig.ServicesConfig services = mock(EmulatorConfig.ServicesConfig.class);
        EmulatorConfig.Ec2ServiceConfig ec2 = mock(EmulatorConfig.Ec2ServiceConfig.class);
        when(config.defaultAccountId()).thenReturn("000000000000");
        when(config.services()).thenReturn(services);
        when(services.ec2()).thenReturn(ec2);
        when(ec2.mock()).thenReturn(true);
        when(ec2.mockPublicAddresses()).thenReturn(EmulatorConfig.Ec2ServiceConfig.MockPublicAddresses.NONE);
        Ec2ImageCatalog catalog = new Ec2ImageCatalog();
        return new Ec2Service(config, null, mock(Ec2PortForwardManager.class), new AmiImageResolver(catalog), catalog,
                new Ec2InstanceTypeCatalog(), vpcs, subnets, groups, new InMemoryStorage<>(),
                new InMemoryStorage<>(), new InMemoryStorage<>(), new InMemoryStorage<>(), new InMemoryStorage<>(),
                instances, volumes, new InMemoryStorage<>(), new InMemoryStorage<>(), new InMemoryStorage<>(),
                new InMemoryStorage<>(), new InMemoryStorage<>(), new InMemoryStorage<>(), new InMemoryStorage<>(),
                new InMemoryStorage<>(), new InMemoryStorage<>(), new InMemoryStorage<>());
    }
}
