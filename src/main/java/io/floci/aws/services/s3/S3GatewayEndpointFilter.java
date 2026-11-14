package io.floci.aws.services.s3;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import io.floci.aws.config.EmulatorConfig;
import io.floci.aws.config.ProxyPeerAddresses;
import io.floci.aws.core.common.RequestContext;
import io.floci.aws.services.ec2.S3GatewayEndpointResolver;
import io.floci.aws.services.ec2.model.VpcEndpoint;
import io.quarkus.vertx.http.runtime.CurrentVertxRequest;
import io.vertx.core.net.SocketAddress;
import io.vertx.ext.web.RoutingContext;
import jakarta.annotation.Priority;
import jakarta.enterprise.context.ApplicationScoped;
import jakarta.inject.Inject;
import jakarta.ws.rs.Priorities;
import jakarta.ws.rs.container.ContainerRequestContext;
import jakarta.ws.rs.container.ContainerRequestFilter;
import jakarta.ws.rs.container.ResourceInfo;
import jakarta.ws.rs.core.Context;
import jakarta.ws.rs.ext.Provider;

import java.util.Iterator;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Set;

/** Adds network identity only for a registered EC2 transport peer with a modeled S3 gateway route. */
@Provider
@ApplicationScoped
@Priority(Priorities.AUTHORIZATION - 1)
public class S3GatewayEndpointFilter implements ContainerRequestFilter {

    private static final String CONTEXT_KEY = S3GatewayEndpointFilter.class.getName();
    private final S3GatewayEndpointResolver resolver;
    private final CurrentVertxRequest currentRequest;
    private final RequestContext requestContext;
    private final EmulatorConfig config;
    private final ObjectMapper mapper;
    private final ProxyPeerAddresses peerAddresses;

    @Context
    ResourceInfo resourceInfo;

    @Inject
    public S3GatewayEndpointFilter(S3GatewayEndpointResolver resolver, CurrentVertxRequest currentRequest,
                                   RequestContext requestContext, EmulatorConfig config, ObjectMapper mapper,
                                   ProxyPeerAddresses peerAddresses) {
        this.resolver = resolver;
        this.currentRequest = currentRequest;
        this.requestContext = requestContext;
        this.config = config;
        this.mapper = mapper;
        this.peerAddresses = peerAddresses;
    }

    @Override
    public void filter(ContainerRequestContext context) {
        if (!config.services().iam().enforcementEnabled() || resourceInfo == null
                || resourceInfo.getResourceClass() != S3Controller.class) {
            return;
        }
        RoutingContext routing = currentRequest.getCurrent();
        if (routing == null || routing.request().connection() == null) {
            return;
        }
        SocketAddress peer = peerAddresses.resolve(routing.request().connection().remoteAddress(),
                routing.request().connection().localAddress());
        if (peer == null) {
            return;
        }
        // Forwarded headers are caller-controlled and cannot identify a guest or endpoint.
        String region = requestContext.getRegion() == null ? config.defaultRegion() : requestContext.getRegion();
        Optional<VpcEndpoint> endpoint = resolver.resolve(peer.host(), region);
        if (endpoint.isEmpty()) {
            return;
        }
        VpcEndpoint gateway = endpoint.get();
        // Narrow initial support to the default full-access endpoint policy. Never let
        // the newly available IAM context bypass a restrictive endpoint policy.
        if (!defaultPolicy(gateway.getPolicyDocument(), mapper)) {
            context.abortWith(PreSignedUrlFilter.errorResponse(403, "AccessDenied",
                    "The modeled S3 gateway route requires a supported endpoint policy"));
            return;
        }
        routing.put(CONTEXT_KEY, new NetworkContext(Map.of(
                "aws:SourceVpce", List.of(gateway.getVpcEndpointId()),
                "aws:SourceVpc", List.of(gateway.getVpcId()))));
    }

    public static Map<String, List<String>> conditions(CurrentVertxRequest request) {
        RoutingContext routing = request == null ? null : request.getCurrent();
        if (routing != null && routing.get(CONTEXT_KEY) instanceof NetworkContext context) {
            return context.conditions();
        }
        return Map.of();
    }

    static boolean defaultPolicy(String document, ObjectMapper mapper) {
        if (document == null || document.isBlank()) {
            return true;
        }
        try {
            JsonNode policy = mapper.readTree(document);
            if (policy == null || !policy.isObject()) {
                return false;
            }
            JsonNode statements = policy.path("Statement");
            JsonNode statement = statements.isArray() && statements.size() == 1 ? statements.get(0) : statements;
            if (!statement.isObject() || !"Allow".equals(statement.path("Effect").asText())) {
                return false;
            }
            for (Iterator<String> keys = statement.fieldNames(); keys.hasNext();) {
                String key = keys.next();
                if (!Set.of("Sid", "Effect", "Principal", "Action", "Resource").contains(key)) {
                    return false;
                }
            }
            JsonNode principal = statement.path("Principal");
            if (principal.isObject() && principal.size() == 1 && principal.has("AWS")) {
                principal = principal.get("AWS");
            }
            return wildcard(principal) && wildcard(statement.path("Action")) && wildcard(statement.path("Resource"));
        } catch (JsonProcessingException ignored) {
            // A malformed stored policy cannot become a full-access gateway.
            return false;
        }
    }

    private static boolean wildcard(JsonNode node) {
        return node.isTextual() && "*".equals(node.asText())
                || node.isArray() && node.size() == 1 && node.get(0).isTextual() && "*".equals(node.get(0).asText());
    }

    private record NetworkContext(Map<String, List<String>> conditions) {}
}
