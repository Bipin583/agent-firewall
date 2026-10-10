"""FastAPI service exposing the engine over HTTP (optional ``[api]`` extra).

Endpoints:
  GET  /healthz              liveness + config summary (no auth)
  POST /v1/evaluate          evaluate a tool request, persist + audit the decision
  GET  /v1/decisions         list recent persisted decisions
  GET  /v1/audit/verify      verify the audit hash chain
  POST /v1/policy/validate   validate a policy YAML document

SECURITY: every /v1 endpoint requires a bearer token
(``AGENT_FIREWALL_API_TOKEN``). If no token is configured the service refuses
those requests with 503 (fail-closed) rather than serving them unauthenticated.
Terminate TLS in front of this app; it speaks plain HTTP.
"""

from __future__ import annotations

import secrets as _secrets
from collections.abc import AsyncIterator, Awaitable, Callable
from contextlib import asynccontextmanager, suppress
from datetime import UTC, datetime
from typing import Any

from fastapi import Depends, FastAPI, Header, HTTPException, Query
from sqlalchemy import select

from ..audit import AuditWriter, verify_chain
from ..config import CoreConfig, api_db_url, api_token
from ..detection.secrets import scrub
from ..engine import SecurityEngine
from ..models import NormalizedRequest, SecurityDecision, TrustLevel
from ..normalize import normalize
from ..policies import PolicyLoadError, load_policy_document
from ..policies.loader import load_policy_document_from_string
from .db import DecisionRecord, create_engine, init_models, make_sessionmaker
from .schemas import (
    EvaluateRequest,
    HealthResponse,
    PolicyValidateRequest,
    PolicyValidateResponse,
)


def _trust_from(value: str | None) -> TrustLevel:
    if not value:
        return TrustLevel.UNKNOWN
    try:
        return TrustLevel(value)
    except ValueError:
        return TrustLevel.UNKNOWN


def _summary_for(req: NormalizedRequest) -> str:
    bits = [req.tool_name]
    if req.resource:
        bits.append(scrub(req.resource)[:200])
    return " ".join(bits)[:300]


def create_app(
    *,
    policy_file: str | None = None,
    db_url: str | None = None,
    token: str | None = None,
) -> FastAPI:
    """Build the app. Arguments override env config (used by tests)."""
    config = CoreConfig.from_env()
    resolved_policy = policy_file or str(config.policy_file)
    resolved_db = db_url or api_db_url()
    # Resolve the token once at startup so auth behaviour is stable per process.
    resolved_token = token if token is not None else api_token()

    @asynccontextmanager
    async def lifespan(app: FastAPI) -> AsyncIterator[None]:
        engine = create_engine(resolved_db)
        await init_models(engine)
        doc = load_policy_document(resolved_policy)
        app.state.engine = engine
        app.state.sessionmaker = make_sessionmaker(engine)
        app.state.security = SecurityEngine(doc)
        app.state.policies_loaded = len(doc.policies)
        app.state.config = config
        app.state.token = resolved_token
        try:
            yield
        finally:
            await engine.dispose()

    app = FastAPI(title="Agent Firewall API", version="0.1.0", lifespan=lifespan)

    async def require_auth(authorization: str | None = Header(default=None)) -> None:
        expected = app.state.token
        if not expected:
            # No token configured -> do not serve protected endpoints unauthenticated.
            raise HTTPException(
                status_code=503,
                detail="API token not configured (set AGENT_FIREWALL_API_TOKEN).",
            )
        scheme, _, presented = (authorization or "").partition(" ")
        if scheme.lower() != "bearer" or not presented:
            raise HTTPException(status_code=401, detail="Missing bearer token.")
        if not _secrets.compare_digest(presented, expected):
            raise HTTPException(status_code=403, detail="Invalid token.")

    _register_routes(app, require_auth)
    return app


def _register_routes(app: FastAPI, require_auth: Callable[..., Awaitable[None]]) -> None:
    @app.get("/healthz", response_model=HealthResponse)
    async def healthz() -> HealthResponse:
        config: CoreConfig = app.state.config
        return HealthResponse(
            status="ok",
            policy_file=str(config.policy_file),
            policies_loaded=app.state.policies_loaded,
            audit_log=str(config.audit_log),
            auth_configured=bool(app.state.token),
        )

    @app.post("/v1/evaluate", dependencies=[Depends(require_auth)])
    async def evaluate(body: EvaluateRequest) -> dict[str, Any]:
        config: CoreConfig = app.state.config
        req = normalize(
            body.tool_name,
            body.tool_input,
            session_id=body.session_id,
            agent_id=body.agent_id,
            environment=body.environment or config.environment,
            project_root=str(config.project_root) if config.project_root else None,
            content_trust=_trust_from(body.content_trust),
        )
        decision: SecurityDecision = app.state.security.evaluate(req)

        # Best-effort tamper-evident audit (same chain the hook/CLI use). A
        # logging failure must never change or block the security decision.
        with suppress(Exception):
            AuditWriter(config.audit_log).record(req, decision)

        record = DecisionRecord(
            decision_id=decision.decision_id,
            request_id=decision.request_id,
            created_at=datetime.now(UTC),
            tool_name=req.tool_name,
            decision=decision.decision.value,
            risk_score=decision.risk_score,
            risk_level=decision.risk_level.value,
            agent_id=req.agent_id,
            session_id=req.session_id,
            environment=req.environment,
            matched_policies=decision.matched_policies,
            matched_rules=decision.matched_rules,
            explanation=decision.explanation,
            redacted_summary=_summary_for(req),
        )
        async with app.state.sessionmaker() as session:
            session.add(record)
            await session.commit()

        return decision.model_dump(mode="json")

    @app.get("/v1/decisions", dependencies=[Depends(require_auth)])
    async def list_decisions(
        limit: int = Query(default=50, ge=1, le=500),
        offset: int = Query(default=0, ge=0),
        decision: str | None = Query(default=None),
    ) -> dict[str, Any]:
        stmt = select(DecisionRecord).order_by(DecisionRecord.id.desc())
        if decision:
            stmt = stmt.where(DecisionRecord.decision == decision)
        stmt = stmt.offset(offset).limit(limit)
        async with app.state.sessionmaker() as session:
            rows = (await session.execute(stmt)).scalars().all()
        return {"count": len(rows), "decisions": [r.as_dict() for r in rows]}

    @app.get("/v1/audit/verify", dependencies=[Depends(require_auth)])
    async def audit_verify() -> dict[str, Any]:
        config: CoreConfig = app.state.config
        return verify_chain(config.audit_log).as_dict()

    @app.post(
        "/v1/policy/validate",
        response_model=PolicyValidateResponse,
        dependencies=[Depends(require_auth)],
    )
    async def policy_validate(body: PolicyValidateRequest) -> PolicyValidateResponse:
        try:
            doc = load_policy_document_from_string(body.document)
        except PolicyLoadError as exc:
            return PolicyValidateResponse(ok=False, error=str(exc))
        return PolicyValidateResponse(
            ok=True,
            policy_count=len(doc.policies),
            default_effect=doc.default_effect.value,
        )


