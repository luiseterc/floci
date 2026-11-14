package io.floci.aws.services.s3;

import com.fasterxml.jackson.databind.ObjectMapper;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.NullAndEmptySource;
import org.junit.jupiter.params.provider.ValueSource;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

class S3GatewayEndpointFilterTest {
    private final ObjectMapper mapper = new ObjectMapper();

    @ParameterizedTest
    @NullAndEmptySource
    @ValueSource(strings = {
            "{\"Statement\":[{\"Effect\":\"Allow\",\"Principal\":\"*\",\"Action\":\"*\",\"Resource\":\"*\"}]}",
            "{\"Statement\":{\"Effect\":\"Allow\",\"Principal\":{\"AWS\":[\"*\"]},\"Action\":[\"*\"],\"Resource\":[\"*\"]}}"
    })
    void acceptsOnlyDefaultFullAccessPolicies(String policy) {
        assertTrue(S3GatewayEndpointFilter.defaultPolicy(policy, mapper));
    }

    @ParameterizedTest
    @ValueSource(strings = {
            "invalid", "null", "{}", "{\"Statement\":[]}",
            "{\"Statement\":[{\"Effect\":\"Deny\",\"Principal\":\"*\",\"Action\":\"*\",\"Resource\":\"*\"}]}",
            "{\"Statement\":[{\"Effect\":\"Allow\",\"Principal\":\"*\",\"Action\":\"s3:GetObject\",\"Resource\":\"*\"}]}",
            "{\"Statement\":[{\"Effect\":\"Allow\",\"Principal\":{\"Service\":\"*\"},\"Action\":\"*\",\"Resource\":\"*\"}]}",
            "{\"Statement\":[{\"Effect\":\"Allow\",\"Principal\":\"*\",\"Action\":\"*\",\"Resource\":\"*\",\"Condition\":{}}]}"
    })
    void refusesUnsupportedPoliciesInsteadOfIgnoringTheirRestrictions(String policy) {
        assertFalse(S3GatewayEndpointFilter.defaultPolicy(policy, mapper));
    }
}
