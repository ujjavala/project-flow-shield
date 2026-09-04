"""Low-friction local metrics and tracing with production-safe opt-in export."""

from __future__ import annotations

import logging

from fastapi import FastAPI
from prometheus_fastapi_instrumentator import Instrumentator

from app.config import settings

logger = logging.getLogger(__name__)


def configure_observability(app: FastAPI) -> None:
    """Expose Prometheus metrics and export traces when OTLP is configured."""
    Instrumentator(
        should_group_status_codes=False,
        excluded_handlers=["/metrics", "/health", "/health/ready"],
    ).instrument(app).expose(app, endpoint="/metrics", include_in_schema=False)

    endpoint = settings.OTEL_EXPORTER_OTLP_ENDPOINT.strip()
    if not endpoint:
        logger.info("OTLP tracing disabled; OTEL_EXPORTER_OTLP_ENDPOINT is not set")
        return

    from opentelemetry import trace
    from opentelemetry.exporter.otlp.proto.grpc.trace_exporter import OTLPSpanExporter
    from opentelemetry.instrumentation.fastapi import FastAPIInstrumentor
    from opentelemetry.sdk.resources import Resource
    from opentelemetry.sdk.trace import TracerProvider
    from opentelemetry.sdk.trace.export import BatchSpanProcessor

    provider = TracerProvider(
        resource=Resource.create(
            {
                "service.name": settings.SERVICE_NAME,
                "deployment.environment": settings.ENVIRONMENT,
            }
        )
    )
    provider.add_span_processor(
        BatchSpanProcessor(
            OTLPSpanExporter(
                endpoint=endpoint,
                insecure=settings.OTEL_EXPORTER_OTLP_INSECURE,
            )
        )
    )
    trace.set_tracer_provider(provider)
    FastAPIInstrumentor.instrument_app(
        app,
        tracer_provider=provider,
        excluded_urls="/metrics,/health,/health/ready",
    )
    logger.info("OTLP tracing enabled for %s via %s", settings.SERVICE_NAME, endpoint)