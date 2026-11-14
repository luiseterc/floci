package io.floci.aws.services.route53;

import jakarta.ws.rs.core.MultivaluedHashMap;
import org.junit.jupiter.api.Test;

import java.util.List;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;

class Route53VpcConditionsTest {
    @Test
    void readsTheSameFirstNamespaceQualifiedVpcAsTheController() {
        String body = """
                <r:AssociateVPCWithHostedZoneRequest xmlns:r="urn:route53">
                 <r:VPC><r:VPCId>vpc-first</r:VPCId><r:VPCRegion>eu-west-1</r:VPCRegion></r:VPC>
                 <r:VPC><r:VPCId>vpc-other</r:VPCId><r:VPCRegion>us-east-1</r:VPCRegion></r:VPC>
                </r:AssociateVPCWithHostedZoneRequest>
                """;
        assertEquals(Map.of("route53:VPCs", List.of("VPCId=vpc-first,VPCRegion=eu-west-1")),
                Route53VpcConditions.resolve("route53:AssociateVPCWithHostedZone", body, new MultivaluedHashMap<>()));
    }

    @Test
    void missingOrIncompleteVpcDoesNotSupplyACondition() {
        for (String body : List.of("", "<CreateHostedZoneRequest/>",
                "<Request><VPC><VPCId>vpc-a</VPCId></VPC></Request>",
                "<Request><VPC><VPCRegion>eu-west-1</VPCRegion></VPC></Request>")) {
            assertNull(Route53VpcConditions.resolve("route53:CreateHostedZone", body, new MultivaluedHashMap<>()));
        }
    }
}
