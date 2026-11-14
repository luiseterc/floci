package io.floci.aws.services.ec2;

import io.floci.aws.services.ec2.model.InstanceNetworkInterface;
import io.floci.aws.services.ec2.model.Vpc;
import io.floci.aws.services.ec2.model.VpcCidrBlockAssociation;
import org.junit.jupiter.api.Test;

import java.util.List;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;

class Ec2NetworkMetadataTest {
    @Test
    void cidrListIncludesOnlyAssociatedCidrsWithoutDuplicatingThePrimary() {
        Vpc vpc = new Vpc();
        vpc.setCidrBlock("10.0.0.0/16");
        VpcCidrBlockAssociation removed = new VpcCidrBlockAssociation("removed", "10.2.0.0/16");
        removed.setCidrBlockState("disassociated");
        vpc.setCidrBlockAssociationSet(List.of(new VpcCidrBlockAssociation("primary", "10.0.0.0/16"),
                new VpcCidrBlockAssociation("secondary", "10.1.0.0/16"), removed));
        Map<String, String> fields = Ec2NetworkMetadata.fields(new InstanceNetworkInterface(), null, null, vpc);
        assertEquals("10.0.0.0/16", fields.get("vpc-ipv4-cidr-block"));
        assertEquals("10.0.0.0/16\n10.1.0.0/16", fields.get("vpc-ipv4-cidr-blocks"));
        assertFalse(fields.containsKey("subnet-ipv4-cidr-block"));
        assertFalse(fields.containsKey("local-ipv4s"));
        assertFalse(fields.containsKey("ipv4-prefix"));
    }
}
