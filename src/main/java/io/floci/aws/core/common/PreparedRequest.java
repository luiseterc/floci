package io.floci.aws.core.common;

import com.fasterxml.jackson.databind.JsonNode;
import jakarta.ws.rs.container.ContainerRequestContext;

import java.util.Collections;
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

    default List<Map<String, Map<String, String>>> tagSets() {
        return List.of(tags());
    }

    default List<Map<String, List<String>>> contexts(String type, String resource) {
        return List.of(context(type, resource));
    }

    /** Facts about one selected resource, including its own tags, never another resource's tags. */
    Map<String, List<String>> context(String type, String resource);

    static PreparedRequest from(ContainerRequestContext context) {
        return context.getProperty(PROPERTY) instanceof PreparedRequest prepared ? prepared : null;
    }

    static List<Map<String, List<String>>> withContexts(ContainerRequestContext request, String operation,
                                                  String resource, Map<String, List<String>> base) {
        PreparedRequest prepared = from(request);
        if (prepared == null || !AwsArnUtils.isArn(resource)) {
            return Collections.singletonList(base);
        }
        String namespace = operation.substring(0, operation.indexOf(':'));
        Map<String, RequestResourceMembers.ArnFormat> formats = RequestResourceMembers.table().formats()
                .getOrDefault(namespace, Map.of());
        for (String type : RequestResourceMembers.table().types().getOrDefault(operation, List.of())) {
            RequestResourceMembers.ArnFormat format = formats.get(type);
            if (format != null && format.pattern().matcher(resource).matches()) {
                return prepared.contexts(type, resource).stream().map(facts -> {
                    Map<String, List<String>> result = base == null ? new LinkedHashMap<String, List<String>>()
                            : new LinkedHashMap<>(base);
                    result.keySet().removeIf(key -> key.startsWith("aws:RequestTag/") || "aws:TagKeys".equals(key));
                    result.putAll(facts);
                    return result;
                }).toList();
            }
        }
        return Collections.singletonList(base);
    }
}
