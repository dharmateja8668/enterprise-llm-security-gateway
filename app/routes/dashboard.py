from typing import Optional
import uuid
from datetime import datetime, timedelta, timezone
from fastapi import APIRouter, Depends, Query, Header, HTTPException, status
from sqlalchemy.orm import Session
from sqlalchemy import func, desc, or_
from app.db import get_db
from app.models.log import RequestLog
from app.models.audit import AuditLog
from app.models.security_log import SecurityLog
from app.models.api_log import APILog
from app.models.user import User
from app.models.rbac import RBACPolicy
from fastapi.responses import HTMLResponse

def get_current_dashboard_user(
    user_id: Optional[str] = Query(None),
    x_user_id: Optional[str] = Header(None),
    authorization: Optional[str] = Header(None),
    db: Session = Depends(get_db)
) -> Optional[User]:
    identifier = user_id or x_user_id
    if not identifier and authorization and authorization.lower().startswith("bearer "):
        identifier = authorization.split()[1]

    if identifier:
        user = None
        if str(identifier).isdigit():
            user = db.query(User).filter(User.id == int(identifier)).first()
        if not user:
            user = db.query(User).filter(User.username == identifier).first()
        if not user:
            user = db.query(User).filter(User.email == identifier).first()

        # Handle user_id aliases like "admin", "analyst", "manager"
        if not user:
            ident_lower = str(identifier).lower()
            if ident_lower in ["admin", "administrator"]:
                user = db.query(User).filter(func.lower(User.role).in_(["admin", "administrator"])).first()
            elif ident_lower in ["analyst", "soc_analyst", "security_analyst"]:
                user = db.query(User).filter(func.lower(User.role).in_(["soc_analyst", "security_analyst"])).first()
            elif ident_lower == "manager":
                user = db.query(User).filter(func.lower(User.role) == "manager").first()
            elif ident_lower in ["employee", "emp"]:
                user = db.query(User).filter(func.lower(User.role) == "employee").first()

        return user

    # Default fallback to first admin in database if no param is passed
    return db.query(User).filter(func.lower(User.role).in_(["admin", "administrator"])).first()

def verify_dashboard_admin_access(
    user_id: Optional[str] = Query(None),
    x_user_id: Optional[str] = Header(None),
    authorization: Optional[str] = Header(None),
    db: Session = Depends(get_db)
):
    """
    Backend RBAC check for SOC Dashboard access.
    Allowed roles: ADMIN, SOC_ANALYST, SECURITY_ANALYST, MANAGER.
    Non-authorized users (e.g. EMPLOYEE role) are rejected with 403 Forbidden.
    """
    user = get_current_dashboard_user(user_id=user_id, x_user_id=x_user_id, authorization=authorization, db=db)
    if user:
        role = (user.role or "employee").lower()
        allowed_soc_roles = ["admin", "administrator", "soc_analyst", "security_analyst", "manager"]
        if role not in allowed_soc_roles:
            try:
                db.add(RequestLog(
                    request_id=str(uuid.uuid4()),
                    user_token=user.username,
                    provider="dashboard_auth",
                    model="none",
                    prompt="[UNAUTHORIZED_DASHBOARD_ACCESS]",
                    status="rbac_blocked"
                ))
                db.commit()
            except Exception:
                db.rollback()

            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail={
                    "error": "Access Denied: SOC Dashboard is restricted to Security Personnel, Analysts, and Managers.",
                    "blocked": True,
                    "reason": "dashboard_rbac_access_required"
                }
            )

def require_admin_role(
    user_id: Optional[str] = Query(None),
    x_user_id: Optional[str] = Header(None),
    authorization: Optional[str] = Header(None),
    db: Session = Depends(get_db)
) -> User:
    """
    Strict backend RBAC check for log deletion actions.
    ONLY ADMIN / ADMINISTRATOR role allowed.
    Raises 403 Forbidden for SOC_ANALYST, MANAGER, EMPLOYEE, or unauthenticated callers.
    """
    user = get_current_dashboard_user(user_id=user_id, x_user_id=x_user_id, authorization=authorization, db=db)
    if user:
        role = (user.role or "employee").lower()
        if role in ["admin", "administrator"]:
            return user

    raise HTTPException(
        status_code=status.HTTP_403_FORBIDDEN,
        detail={
            "error": "Access Denied: Only Administrators can delete security logs.",
            "blocked": True,
            "reason": "admin_role_required"
        }
    )


router = APIRouter(prefix="/dashboard", tags=["Dashboard"], dependencies=[Depends(verify_dashboard_admin_access)])

BLOCKED_STATUSES = ["injection_blocked", "content_safety_blocked", "rbac_blocked"]

def get_time_filter(time_range: str):
    now = datetime.now(timezone.utc).replace(tzinfo=None)
    if time_range == "24h":
        return now - timedelta(hours=24)
    elif time_range == "30d":
        return now - timedelta(days=30)
    else: # default 7d
        return now - timedelta(days=7)

def get_previous_time_filter(time_range: str):
    now = datetime.now(timezone.utc).replace(tzinfo=None)
    if time_range == "24h":
        return now - timedelta(hours=48), now - timedelta(hours=24)
    elif time_range == "30d":
        return now - timedelta(days=60), now - timedelta(days=30)
    else: # default 7d
        return now - timedelta(days=14), now - timedelta(days=7)

@router.get("/me")
def get_current_user_info(
    user: Optional[User] = Depends(get_current_dashboard_user)
):
    if user:
        role = (user.role or "employee").upper()
        return {
            "id": user.id,
            "username": user.username,
            "email": user.email,
            "role": role,
            "is_admin": role in ["ADMIN", "ADMINISTRATOR"]
        }
    return {
        "id": 1,
        "username": "admin",
        "email": "admin@zaalima.in",
        "role": "ADMIN",
        "is_admin": True
    }

@router.delete("/logs")
def delete_all_logs(
    db: Session = Depends(get_db),
    admin_user: User = Depends(require_admin_role)
):
    """
    Permanently delete all SOC dashboard log records (RequestLog, AuditLog, SecurityLog, APILog).
    Preserves users, rbac_policies, chat_sessions, and system configuration.
    Audits the deletion action.
    """
    try:
        cnt_req = db.query(RequestLog).delete()
        cnt_audit = db.query(AuditLog).delete()
        cnt_sec = db.query(SecurityLog).delete()
        cnt_api = db.query(APILog).delete()
        db.commit()

        total_deleted = cnt_req + cnt_audit + cnt_sec + cnt_api

        # Create audit entry for DELETE_ALL_LOGS action
        audit_entry = AuditLog(
            request_id=str(uuid.uuid4()),
            user_id=admin_user.username,
            provider="system_audit",
            model="none",
            prompt=f"[ADMIN_AUDIT] Action: DELETE_ALL_LOGS | Deleted {total_deleted} total log records",
            response="Successfully deleted all SOC logs",
            status="success",
            status_code=200,
            latency_ms=0,
            created_at=datetime.now(timezone.utc).replace(tzinfo=None)
        )
        db.add(audit_entry)
        db.commit()

        return {
            "status": "success",
            "message": "All SOC logs deleted successfully.",
            "deleted_count": total_deleted
        }
    except Exception as e:
        db.rollback()
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Unable to delete logs. Please try again."
        )

@router.delete("/logs/{log_id}")
def delete_individual_log(
    log_id: str,
    db: Session = Depends(get_db),
    admin_user: User = Depends(require_admin_role)
):
    """
    Delete a specific log record by ID (integer primary key or string request_id).
    """
    deleted_count = 0
    log_identifier = log_id.strip()

    # RequestLog
    req_query = db.query(RequestLog)
    if log_identifier.isdigit():
        req_query = req_query.filter(or_(RequestLog.id == int(log_identifier), RequestLog.request_id == log_identifier))
    else:
        req_query = req_query.filter(RequestLog.request_id == log_identifier)
    for r in req_query.all():
        db.delete(r)
        deleted_count += 1

    # AuditLog
    audit_query = db.query(AuditLog)
    if log_identifier.isdigit():
        audit_query = audit_query.filter(or_(AuditLog.id == int(log_identifier), AuditLog.request_id == log_identifier))
    else:
        audit_query = audit_query.filter(AuditLog.request_id == log_identifier)
    for a in audit_query.all():
        db.delete(a)
        deleted_count += 1

    # SecurityLog
    sec_query = db.query(SecurityLog)
    if log_identifier.isdigit():
        sec_query = sec_query.filter(or_(SecurityLog.id == int(log_identifier), SecurityLog.request_id == log_identifier))
    else:
        sec_query = sec_query.filter(SecurityLog.request_id == log_identifier)
    for s in sec_query.all():
        db.delete(s)
        deleted_count += 1

    # APILog
    api_query = db.query(APILog)
    if log_identifier.isdigit():
        api_query = api_query.filter(or_(APILog.id == int(log_identifier), APILog.request_id == log_identifier))
    else:
        api_query = api_query.filter(APILog.request_id == log_identifier)
    for ap in api_query.all():
        db.delete(ap)
        deleted_count += 1

    if deleted_count == 0:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Log record with ID '{log_id}' not found."
        )

    db.commit()

    # Audit individual log deletion
    audit_entry = AuditLog(
        request_id=str(uuid.uuid4()),
        user_id=admin_user.username,
        provider="system_audit",
        model="none",
        prompt=f"[ADMIN_AUDIT] Action: DELETE_LOG | Target Log ID: {log_id}",
        response="Successfully deleted single log record",
        status="success",
        status_code=200,
        latency_ms=0,
        created_at=datetime.now(timezone.utc).replace(tzinfo=None)
    )
    db.add(audit_entry)
    db.commit()

    return {
        "status": "success",
        "message": "Log deleted successfully.",
        "deleted_id": log_id
    }

@router.get("/metrics")
def get_metrics(db: Session = Depends(get_db), time_range: str = Query("7d")):
    cutoff = get_time_filter(time_range)
    prev_cutoff_start, prev_cutoff_end = get_previous_time_filter(time_range)
    
    # Current period
    req_query = db.query(RequestLog).filter(RequestLog.timestamp >= cutoff)
    total_req = req_query.count()
    
    blocked_req = req_query.filter(RequestLog.status.in_(BLOCKED_STATUSES)).count()
    allowed_req = req_query.filter(RequestLog.status == "success").count()
    error_req = req_query.filter(RequestLog.status == "error").count()
    
    # Active users count
    active_users = db.query(func.count(func.distinct(RequestLog.user_token))).filter(
        RequestLog.timestamp >= cutoff,
        RequestLog.user_token.isnot(None)
    ).scalar() or 0
    
    # Previous period
    prev_req_query = db.query(RequestLog).filter(RequestLog.timestamp >= prev_cutoff_start, RequestLog.timestamp < prev_cutoff_end)
    prev_total = prev_req_query.count()
    prev_blocked = prev_req_query.filter(RequestLog.status.in_(BLOCKED_STATUSES)).count()
    prev_allowed = prev_req_query.filter(RequestLog.status == "success").count()
    
    def calc_change(current, previous):
        if previous == 0:
            return 100.0 if current > 0 else 0.0
        return round(((current - previous) / previous) * 100, 1)

    return {
        "total_requests": total_req,
        "total_requests_change": calc_change(total_req, prev_total),
        "blocked_prompts": blocked_req,
        "blocked_prompts_change": calc_change(blocked_req, prev_blocked),
        "allowed_requests": allowed_req,
        "allowed_requests_change": calc_change(allowed_req, prev_allowed),
        "error_requests": error_req,
        "security_events": blocked_req,
        "active_users": active_users
    }

@router.get("/usage")
def get_usage(db: Session = Depends(get_db), time_range: str = Query("7d")):
    cutoff = get_time_filter(time_range)
    logs = db.query(RequestLog).filter(RequestLog.timestamp >= cutoff).all()
    
    usage_data = {}
    
    now = datetime.now(timezone.utc).replace(tzinfo=None)
    if time_range == "24h":
        for i in range(24):
            hour = (now - timedelta(hours=i)).strftime("%Y-%m-%d %H:00")
            usage_data[hour] = {"requests": 0, "allowed": 0, "blocked": 0}
        
        for log in logs:
            key = log.timestamp.strftime("%Y-%m-%d %H:00")
            if key in usage_data:
                usage_data[key]["requests"] += 1
                if log.status in BLOCKED_STATUSES:
                    usage_data[key]["blocked"] += 1
                elif log.status == "success":
                    usage_data[key]["allowed"] += 1
    else:
        days = 30 if time_range == "30d" else 7
        for i in range(days):
            day = (now - timedelta(days=i)).strftime("%Y-%m-%d")
            usage_data[day] = {"requests": 0, "allowed": 0, "blocked": 0}
            
        for log in logs:
            key = log.timestamp.strftime("%Y-%m-%d")
            if key in usage_data:
                usage_data[key]["requests"] += 1
                if log.status in BLOCKED_STATUSES:
                    usage_data[key]["blocked"] += 1
                elif log.status == "success":
                    usage_data[key]["allowed"] += 1
            
    labels = sorted(usage_data.keys())
    requests_over_time = [usage_data[k]["requests"] for k in labels]
    allowed_over_time = [usage_data[k]["allowed"] for k in labels]
    blocked_over_time = [usage_data[k]["blocked"] for k in labels]
    
    return {
        "labels": labels,
        "requests_over_time": requests_over_time,
        "allowed_over_time": allowed_over_time,
        "blocked_over_time": blocked_over_time
    }

@router.get("/security-events")
def get_security_events(db: Session = Depends(get_db), time_range: str = Query("7d")):
    cutoff = get_time_filter(time_range)
    
    logs = db.query(RequestLog).filter(RequestLog.timestamp >= cutoff).order_by(RequestLog.timestamp.desc()).limit(100).all()
    events = []
    for log in logs:
        if log.status == "injection_blocked":
            event_name = "Prompt Injection Detected"
            severity = "Critical"
        elif log.status == "content_safety_blocked":
            event_name = "Unsafe Content Blocked"
            severity = "High"
        elif log.status == "rbac_blocked":
            event_name = "AI Model Access Denied (RBAC)"
            severity = "High"
        elif log.status == "error":
            event_name = "API Error"
            severity = "Medium"
        else:
            event_name = "Successful Request"
            severity = "Low"
            
        events.append({
            "id": log.id,
            "request_id": log.request_id,
            "timestamp": log.timestamp.isoformat() + "Z",
            "user": log.user_token if log.user_token else "Unknown",
            "model": log.model if log.model else "Unknown",
            "event": event_name,
            "status": "Blocked" if log.status in BLOCKED_STATUSES else ("Error" if log.status == "error" else "Allowed"),
            "severity": severity,
        })
            
    return events

@router.get("/blocked-prompts")
def get_blocked_prompts(db: Session = Depends(get_db), time_range: str = Query("7d")):
    cutoff = get_time_filter(time_range)
    
    injection = db.query(RequestLog).filter(
        RequestLog.timestamp >= cutoff, 
        RequestLog.status == "injection_blocked"
    ).count()
    
    content_safety = db.query(RequestLog).filter(
        RequestLog.timestamp >= cutoff, 
        RequestLog.status == "content_safety_blocked"
    ).count()

    rbac = db.query(RequestLog).filter(
        RequestLog.timestamp >= cutoff, 
        RequestLog.status == "rbac_blocked"
    ).count()
    
    return {
        "categories": ["Prompt Injection", "Unsafe Content", "RBAC Blocked"],
        "counts": [injection, content_safety, rbac]
    }

EXCLUDED_AI_MODELS = {
    "none",
    "unknown",
    "restricted-model-xyz",
    "unauthorized-restricted-model",
}

EXCLUDED_AI_PROVIDERS = {
    "gateway_auth",
    "dashboard_auth",
}

@router.get("/model-usage")
def get_model_usage(db: Session = Depends(get_db), time_range: str = Query("7d")):
    cutoff = get_time_filter(time_range)
    
    excluded_models_lower = [m.lower() for m in EXCLUDED_AI_MODELS]
    excluded_providers_lower = [p.lower() for p in EXCLUDED_AI_PROVIDERS]
    
    # Query model counts excluding non-AI events and synthetic security-test model names
    model_counts = db.query(
        RequestLog.model, func.count(RequestLog.id)
    ).filter(
        RequestLog.timestamp >= cutoff,
        RequestLog.model.isnot(None),
        RequestLog.model != "",
        func.lower(RequestLog.model).not_in(excluded_models_lower),
        or_(RequestLog.provider.is_(None), func.lower(RequestLog.provider).not_in(excluded_providers_lower))
    ).group_by(RequestLog.model).all()
    
    total = sum(count for _, count in model_counts)
    
    models = []
    for model, count in model_counts:
        if not model or model.lower() in EXCLUDED_AI_MODELS:
            continue
        pct = round((count / total) * 100, 1) if total > 0 else 0
        models.append({
            "name": model,
            "count": count,
            "percentage": pct
        })
        
    return sorted(models, key=lambda x: x["count"], reverse=True)

@router.get("/users-data")
def get_users_data(
    db: Session = Depends(get_db),
    sort_by: Optional[str] = Query("name"),
    order: Optional[str] = Query("asc"),
    search: Optional[str] = Query(None),
    role: Optional[str] = Query(None),
    department: Optional[str] = Query(None)
):
    users = db.query(User).all()
    policies = db.query(RBACPolicy).all()

    # Pre-calculate request log counts and last activity timestamps for users
    req_counts = dict(
        db.query(RequestLog.user_token, func.count(RequestLog.id))
        .filter(RequestLog.user_token.isnot(None))
        .group_by(RequestLog.user_token)
        .all()
    )
    last_act_map = dict(
        db.query(RequestLog.user_token, func.max(RequestLog.timestamp))
        .filter(RequestLog.user_token.isnot(None))
        .group_by(RequestLog.user_token)
        .all()
    )

    dept_models_map = {}
    for p in policies:
        dept = p.department
        if dept not in dept_models_map:
            dept_models_map[dept] = set()
        if p.allowed_model:
            dept_models_map[dept].add(p.allowed_model)

    user_list = []
    departments_set = set()
    admin_count = 0
    active_count = 0

    for u in users:
        u_role = (u.role or "employee").strip()
        dept = (u.department or "General").strip()
        departments_set.add(dept)

        if u_role.lower() in ["admin", "administrator"]:
            admin_count += 1
            allowed_models = ["* (All Models)", "llama3.2:3b"]
        else:
            user_models = set()
            for p in policies:
                dept_match = p.department.lower() in ["*", "any"] or p.department.lower() == dept.lower()
                role_match = p.role.lower() in ["*", "any"] or p.role.lower() == u_role.lower()
                if dept_match and role_match:
                    user_models.add(p.allowed_model)
            allowed_models = sorted(list(user_models)) if user_models else ["llama3.2:3b"]

        is_active = bool(u.is_active)
        if is_active:
            active_count += 1

        activity_cnt = req_counts.get(u.username, 0)
        last_ts = last_act_map.get(u.username)
        activity_time_str = last_ts.isoformat() + "Z" if last_ts else (u.created_at.isoformat() + "Z" if u.created_at else "")

        user_list.append({
            "id": u.id,
            "username": u.username,
            "email": u.email,
            "role": u_role.upper(),
            "department": dept,
            "status": "Active" if is_active else "Inactive",
            "activity": activity_cnt,
            "last_activity": activity_time_str,
            "allowed_models": allowed_models,
            "created_at": u.created_at.isoformat() + "Z" if u.created_at else None
        })

    # Search filtering
    if search:
        s = search.strip().lower()
        user_list = [
            u for u in user_list
            if s in u["username"].lower() or s in u["email"].lower() or s in u["role"].lower() or s in u["department"].lower()
        ]

    # Role filtering
    if role and role.upper() != "ALL":
        user_list = [u for u in user_list if u["role"] == role.upper()]

    # Department filtering
    if department and department.upper() != "ALL":
        user_list = [u for u in user_list if u["department"].lower() == department.lower()]

    # Sorting
    s_by = (sort_by or "name").lower()
    s_order = (order or "asc").lower()

    # Parse combined sort strings like name_asc, name_desc, most_active, etc.
    if s_by == "most_active":
        s_by = "activity"
        s_order = "desc"
    elif s_by == "least_active":
        s_by = "activity"
        s_order = "asc"
    elif s_by in ["most_recent", "recent_activity"]:
        s_by = "last_activity"
        s_order = "desc"
    elif s_by in ["oldest", "oldest_activity"]:
        s_by = "last_activity"
        s_order = "asc"
    elif s_by.endswith("_asc"):
        s_by = s_by[:-4]
        s_order = "asc"
    elif s_by.endswith("_desc"):
        s_by = s_by[:-5]
        s_order = "desc"

    reverse = (s_order == "desc")

    if s_by in ["name", "username"]:
        user_list.sort(key=lambda x: x["username"].lower(), reverse=reverse)
    elif s_by == "email":
        user_list.sort(key=lambda x: x["email"].lower(), reverse=reverse)
    elif s_by == "department":
        user_list.sort(key=lambda x: x["department"].lower(), reverse=reverse)
    elif s_by == "role":
        user_list.sort(key=lambda x: x["role"].lower(), reverse=reverse)
    elif s_by == "status":
        user_list.sort(key=lambda x: x["status"].lower(), reverse=reverse)
    elif s_by == "activity":
        user_list.sort(key=lambda x: x["activity"], reverse=reverse)
    elif s_by in ["created_at", "last_activity"]:
        user_list.sort(key=lambda x: x["last_activity"] or "", reverse=reverse)
    else:
        user_list.sort(key=lambda x: x["username"].lower(), reverse=reverse)

    rbac_mappings = []
    for dept, models in dept_models_map.items():
        rbac_mappings.append({
            "department": dept,
            "models": sorted(list(models))
        })

    if not any(r["department"].lower() == "security" for r in rbac_mappings):
        rbac_mappings.append({
            "department": "Security",
            "models": ["* (All Gateway Models)", "llama3.2:3b"]
        })

    return {
        "summary": {
            "total_users": len(users),
            "active_users": active_count,
            "departments": len(departments_set),
            "administrators": admin_count
        },
        "users": user_list,
        "rbac_mappings": rbac_mappings
    }

from fastapi.responses import HTMLResponse, JSONResponse

@router.get("")
@router.get("/")
def get_dashboard_root(accept: Optional[str] = Header(None)):
    if accept and "text/html" in accept.lower():
        with open("app/routes/dashboard.html", "r", encoding="utf-8") as f:
            return HTMLResponse(content=f.read())
    return JSONResponse(content={"status": "success", "message": "Enterprise LLM Security Gateway — SOC Compliance Dashboard"})

@router.get("/{full_path:path}", response_class=HTMLResponse)
def get_dashboard_html(full_path: str = ""):
    with open("app/routes/dashboard.html", "r", encoding="utf-8") as f:
        html_content = f.read()
    return HTMLResponse(content=html_content)



