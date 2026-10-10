"""Strict schema for policy files.

A policy file is declarative YAML. We validate it with Pydantic so that a
malformed policy file is a *loud* error, never silently permissive behaviour
(Part 7 precedence rule #1 / Part 24 review item). Unknown keys are rejected.
"""

from __future__ import annotations

from enum import StrEnum

from pydantic import BaseModel, ConfigDict, Field


class Effect(StrEnum):
    DENY = "deny"
    ALLOW = "allow"
    APPROVAL = "approval"


class Policy(BaseModel):
    """One rule. A policy *matches* a request when every populated selector matches.

    Empty selector lists mean "no constraint on this dimension" (i.e. match any).
    A policy with no selectors at all matches every request -- useful for a
    catch-all default, but validated so it is at least intentional.
    """

    model_config = ConfigDict(extra="forbid")

    id: str
    effect: Effect
    enabled: bool = True
    description: str = ""

    # Selectors (AND across dimensions, OR within a dimension).
    tools: list[str] = Field(default_factory=list)
    agents: list[str] = Field(default_factory=list)
    action_types: list[str] = Field(default_factory=list)
    environments: list[str] = Field(default_factory=list)
    # Glob patterns matched against the request's resource (e.g. a file path).
    resource_patterns: list[str] = Field(default_factory=list)
    # Glob patterns matched against a network/transfer destination, when present.
    destination_patterns: list[str] = Field(default_factory=list)

    # For effect == approval: trigger ASK when risk_score >= threshold.
    risk_threshold: int | None = Field(default=None, ge=0, le=100)

    def is_pure_risk_gate(self) -> bool:
        """True when this policy only gates on risk, with no other selectors.

        Supported for ``deny`` and ``approval`` effects: it lets a policy file
        express "block anything scoring >= N" or "require approval at >= N"
        without enumerating tools.
        """
        return (
            self.effect in (Effect.DENY, Effect.APPROVAL)
            and self.risk_threshold is not None
            and not any(
                [
                    self.tools,
                    self.agents,
                    self.action_types,
                    self.environments,
                    self.resource_patterns,
                    self.destination_patterns,
                ]
            )
        )


class PolicyDocument(BaseModel):
    model_config = ConfigDict(extra="forbid")

    version: int = 1
    # Default effect when no policy matches. Deliberately NOT "allow" by default
    # could be too noisy; we default to "allow" for known tools but the engine
    # escalates unknown tools separately (see authorization). Configurable here.
    default_effect: Effect = Effect.ALLOW
    policies: list[Policy] = Field(default_factory=list)

    def enabled_policies(self) -> list[Policy]:
        return [p for p in self.policies if p.enabled]
