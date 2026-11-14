package io.floci.aws.core.common;

import jakarta.ws.rs.container.ContainerRequestContext;

/** Resolves service-owned inputs without mutations before the generated IAM resource selectors run. */
public interface RequestPreparation {
    String operation();

    PreparedRequest prepare(ContainerRequestContext context, String region);
}
