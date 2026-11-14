package io.floci.aws.core.common;

import com.fasterxml.jackson.databind.JsonNode;
import jakarta.ws.rs.container.ContainerRequestContext;

import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * A service's effective modeled input and read-only output projection. The generated table alone
 * selects authorization resources from these values. A planned, not-yet-allocated identifier is '*'.
 */
public interface PreparedRequest {
    String PROPERTY = PreparedRequest.class.getName();

    JsonNode model();

    /** Effective creation tags after the service resolves inherited defaults and overrides. */
    Map<String, Map<String, String>> tags();

    /** Facts about one selected resource, including its own tags, never another resource's tags. */
    Map<String, List<String>> context(String type, String resource);

    static PreparedRequest from(ContainerRequestContext context) {
        return context.getProperty(PROPERTY) instanceof PreparedRequest prepared ? prepared : null;
    }

    static Map<String, List<String>> withContext(ContainerRequestContext request, String operation,
                                                  String resource, Map<String, List<String>> base) {
        PreparedRequest prepared = from(request);
        if (prepared == null || !AwsArnUtils.isArn(resource)) {
            return base;
        }
        String namespace = operation.substring(0, operation.indexOf(':'));
        Map<String, RequestResourceMembers.ArnFormat> formats = RequestResourceMembers.table().formats()
                .getOrDefault(namespace, Map.of());
        for (String type : RequestResourceMembers.table().types().getOrDefault(operation, List.of())) {
            RequestResourceMembers.ArnFormat format = formats.get(type);
            if (format != null && format.pattern().matcher(resource).matches()) {
                Map<String, List<String>> result = base == null ? new LinkedHashMap<>() : new LinkedHashMap<>(base);
                result.keySet().removeIf(key -> key.startsWith("aws:RequestTag/") || "aws:TagKeys".equals(key));
                result.putAll(prepared.context(type, resource));
                return result;
            }
        }
        return base;
    }
}
