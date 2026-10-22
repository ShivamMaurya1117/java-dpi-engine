package com.dpiengine.api;

import com.fasterxml.jackson.databind.DeserializationFeature;
import com.fasterxml.jackson.databind.cfg.CoercionAction;
import com.fasterxml.jackson.databind.cfg.CoercionInputShape;
import com.fasterxml.jackson.databind.type.LogicalType;
import org.springframework.boot.autoconfigure.jackson.Jackson2ObjectMapperBuilderCustomizer;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

@Configuration
class JsonOptionsConfiguration {
    @Bean
    Jackson2ObjectMapperBuilderCustomizer strictOptions() {
        return builder -> builder.featuresToDisable(DeserializationFeature.ACCEPT_FLOAT_AS_INT)
                .postConfigurer(mapper -> {
                    for (CoercionInputShape shape : new CoercionInputShape[]{CoercionInputShape.String,
                            CoercionInputShape.EmptyString, CoercionInputShape.Float, CoercionInputShape.Boolean}) {
                        mapper.coercionConfigFor(LogicalType.Integer).setCoercion(shape, CoercionAction.Fail);
                    }
                    for (CoercionInputShape shape : new CoercionInputShape[]{CoercionInputShape.Integer,
                            CoercionInputShape.Float, CoercionInputShape.Boolean}) {
                        mapper.coercionConfigFor(LogicalType.Textual).setCoercion(shape, CoercionAction.Fail);
                    }
                });
    }
}
