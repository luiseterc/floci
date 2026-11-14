package io.floci.aws.services.ec2;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.node.ArrayNode;
import com.fasterxml.jackson.databind.node.JsonNodeFactory;
import com.fasterxml.jackson.databind.node.ObjectNode;
import io.floci.aws.core.common.IamConditionContextResolver;
import io.floci.aws.core.common.PreparedRequest;
import io.floci.aws.core.common.RequestPreparation;
import io.floci.aws.services.ec2.model.Tag;
import jakarta.enterprise.context.ApplicationScoped;
import jakarta.inject.Inject;
import jakarta.ws.rs.container.ContainerRequestContext;
import jakarta.ws.rs.core.MultivaluedHashMap;
import jakarta.ws.rs.core.MultivaluedMap;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/** Resolves every instant-fleet alternative once, before authorization and execution. */
@ApplicationScoped
public class Ec2FleetPreparation implements RequestPreparation {
    private final Ec2QueryHandler handler;
    private final Ec2Service service;

    @Inject
    public Ec2FleetPreparation(Ec2QueryHandler handler, Ec2Service service) {
        this.handler = handler;
        this.service = service;
    }

    @Override
    public String operation() {
        return "ec2:CreateFleet";
    }

    @Override
    public PreparedRequest prepare(ContainerRequestContext context, String region) {
        MultivaluedMap<String, String> params = new MultivaluedHashMap<>();
        IamConditionContextResolver.formParameters(context).forEach(params::putSingle);
        List<Ec2QueryHandler.FleetLaunch> launches = handler.prepareFleetLaunches(params, region);
        List<Ec2LaunchPreparation.Launch> plans = new ArrayList<>();
        ObjectNode model = JsonNodeFactory.instance.objectNode();
        model.putObject("output").put("FleetId", "*");
        ArrayNode calls = model.putObject("calls").putArray("RunInstances");
        for (Ec2QueryHandler.FleetLaunch launch : launches) {
            Ec2RunInstancesRequest request = launch.request(false);
            Ec2Service.LaunchPreview preview = service.previewRunInstances(region, request, launch.availabilityZone());
            JsonNode projection = Ec2LaunchPreparation.projection(request, preview);
            plans.add(new Ec2LaunchPreparation.Launch(request, preview, projection,
                    Ec2LaunchPreparation.networkIdentity(preview.network())));
            calls.add(projection);
        }
        Map<String, String> tags = new LinkedHashMap<>();
        for (Tag tag : handler.parseTagsForResource(params, "fleet")) {
            tags.put(tag.getKey(), tag.getValue());
        }
        return new Fleet(launches, List.copyOf(plans), model, Map.copyOf(tags));
    }

    public record Fleet(List<Ec2QueryHandler.FleetLaunch> launches, List<Ec2LaunchPreparation.Launch> plans,
                         JsonNode model, Map<String, String> fleetTags) implements PreparedRequest {
        @Override
        public Map<String, Map<String, String>> tags() {
            return Map.of("fleet", fleetTags);
        }

        @Override
        public List<Map<String, Map<String, String>>> tagSets() {
            List<Map<String, Map<String, String>>> sets = new ArrayList<>();
            sets.add(tags());
            plans.forEach(plan -> sets.add(plan.tags()));
            return List.copyOf(sets);
        }

        @Override
        public Map<String, List<String>> context(String type, String resource) {
            return contexts(type, resource).getFirst();
        }

        @Override
        public List<Map<String, List<String>>> contexts(String type, String resource) {
            if ("fleet".equals(type)) {
                Map<String, List<String>> facts = new LinkedHashMap<>();
                fleetTags.forEach((key, value) -> facts.put("aws:RequestTag/" + key, List.of(value)));
                if (!fleetTags.isEmpty()) {
                    facts.put("aws:TagKeys", List.copyOf(fleetTags.keySet()));
                }
                return List.of(facts);
            }
            List<Map<String, List<String>>> facts = plans.stream()
                    .filter(plan -> !"image".equals(type) || resource.endsWith("/" + plan.request().imageId()))
                    .filter(plan -> !"volume".equals(type) || !plan.preview().volumes().isEmpty())
                    .map(plan -> plan.context(type, resource)).distinct().toList();
            return facts.isEmpty() ? List.of(Map.of()) : facts;
        }
    }
}
