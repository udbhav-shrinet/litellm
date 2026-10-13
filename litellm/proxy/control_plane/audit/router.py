from typing import Annotated, Final

from fastapi import APIRouter, Depends, Query, Security

from litellm.proxy.control_plane.audit.dependencies import get_audit_log
from litellm.proxy.control_plane.audit.log import AuditLog
from litellm.proxy.control_plane.auth.dependencies import require_scopes
from litellm.proxy.control_plane.auth.rbac import Principal, Scope
from litellm.types.proxy.control_plane.audit import AuditEventResponse, AuditListResponse

router: Final = APIRouter(prefix="/audit", tags=["audit"])


@router.get("", response_model=AuditListResponse)
async def list_audit(
    _principal: Annotated[Principal, Security(require_scopes, scopes=[Scope.AUDIT_READ.value])],
    audit: Annotated[AuditLog, Depends(get_audit_log)],
    limit: Annotated[int, Query(ge=1, le=1000)] = 100,
    dataplane: Annotated[str | None, Query(description="Only events against this dataplane id.")] = None,
    actor: Annotated[str | None, Query(description="Only events by this control plane subject.")] = None,
) -> AuditListResponse:
    """Newest first, what every control plane caller did on which dataplane."""
    return AuditListResponse(
        items=tuple(
            AuditEventResponse(
                at=event.at,
                actor=event.actor,
                actor_email=event.actor_email,
                dataplane_id=event.dataplane_id,
                method=event.method,
                path=event.path,
                decision=event.decision,
                status=event.status,
                credential=event.credential,
                detail=event.detail,
            )
            for event in audit.recent(limit, dataplane, actor)
        )
    )
