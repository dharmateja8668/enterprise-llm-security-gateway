from typing import Optional
from fastapi import APIRouter, Depends, Query, Header, HTTPException, status
from sqlalchemy.orm import Session
from sqlalchemy import func, desc
from app.db import get_db
from app.models.log import RequestLog
from app.models.audit import AuditLog
from app.models.user import User
from app.models.rbac import RBACPolicy
from fastapi.responses import HTMLResponse
from datetime import datetime, timedelta

def verify_dashboard_admin_access(
    user_id: Optional[str] = Query(None),
    x_user_id: Optional[str] = Header(None),
    authorization: Optional[str] = Header(None),
    db: Session = Depends(get_db)
):
    """
    Backend RBAC check for SOC Dashboard access.
    Non-admin users (e.g. employee role) are rejected with 403 Forbidden.
    """
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

        if user:
            role = (user.role or "employee").lower()
            if role not in ["admin", "administrator"]:
                try:
                    import uuid
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
                        "error": "Access Denied: SOC Dashboard is restricted to Administrators only",
                        "blocked": True,
                        "reason": "dashboard_admin_access_required"
                    }
                )

router = APIRouter(prefix="/dashboard", tags=["Dashboard"], dependencies=[Depends(verify_dashboard_admin_access)])

BLOCKED_STATUSES = ["injection_blocked", "content_safety_blocked", "rbac_blocked"]

def get_time_filter(time_range: str):
    now = datetime.utcnow()
    if time_range == "24h":
        return now - timedelta(hours=24)
    elif time_range == "30d":
        return now - timedelta(days=30)
    else: # default 7d
        return now - timedelta(days=7)

def get_previous_time_filter(time_range: str):
    now = datetime.utcnow()
    if time_range == "24h":
        return now - timedelta(hours=48), now - timedelta(hours=24)
    elif time_range == "30d":
        return now - timedelta(days=60), now - timedelta(days=30)
    else: # default 7d
        return now - timedelta(days=14), now - timedelta(days=7)

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
    active_users = req_query.filter(RequestLog.user_token.isnot(None)).distinct(RequestLog.user_token).count()
    
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
        "security_events": blocked_req, # Using blocked as security events proxy
        "active_users": active_users
    }

@router.get("/usage")
def get_usage(db: Session = Depends(get_db), time_range: str = Query("7d")):
    cutoff = get_time_filter(time_range)
    logs = db.query(RequestLog).filter(RequestLog.timestamp >= cutoff).all()
    
    usage_data = {}
    
    # Pre-fill usage data based on time range
    now = datetime.utcnow()
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
    
    logs = db.query(RequestLog).filter(RequestLog.timestamp >= cutoff).order_by(RequestLog.timestamp.desc()).limit(20).all()
    events = []
    for log in logs:
        # Determine severity and event name
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

@router.get("/model-usage")
def get_model_usage(db: Session = Depends(get_db), time_range: str = Query("7d")):
    cutoff = get_time_filter(time_range)
    
    model_counts = db.query(
        RequestLog.model, func.count(RequestLog.id)
    ).filter(
        RequestLog.timestamp >= cutoff
    ).group_by(RequestLog.model).all()
    
    total = sum(count for _, count in model_counts)
    
    models = []
    for model, count in model_counts:
        pct = round((count / total) * 100, 1) if total > 0 else 0
        models.append({
            "name": model if model else "Unknown",
            "count": count,
            "percentage": pct
        })
        
    return sorted(models, key=lambda x: x["count"], reverse=True)

@router.get("/users-data")
def get_users_data(db: Session = Depends(get_db)):
    users = db.query(User).order_by(User.id.asc()).all()
    policies = db.query(RBACPolicy).all()

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
        role = (u.role or "employee").strip()
        dept = (u.department or "General").strip()
        departments_set.add(dept)

        if role.lower() in ["admin", "administrator"]:
            admin_count += 1
            allowed_models = ["* (All Models)", "llama3.2:3b"]
        else:
            user_models = set()
            for p in policies:
                dept_match = p.department.lower() in ["*", "any"] or p.department.lower() == dept.lower()
                role_match = p.role.lower() in ["*", "any"] or p.role.lower() == role.lower()
                if dept_match and role_match:
                    user_models.add(p.allowed_model)
            allowed_models = sorted(list(user_models)) if user_models else ["llama3.2:3b"]

        is_active = bool(u.is_active)
        if is_active:
            active_count += 1

        user_list.append({
            "id": u.id,
            "username": u.username,
            "email": u.email,
            "role": role.upper(),
            "department": dept,
            "status": "Active" if is_active else "Inactive",
            "allowed_models": allowed_models,
            "created_at": u.created_at.isoformat() if u.created_at else None
        })

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

@router.get("/{full_path:path}", response_class=HTMLResponse)
def get_dashboard_html(full_path: str = ""):
    with open("app/routes/dashboard.html", "r", encoding="utf-8") as f:
        html_content = f.read()
    return HTMLResponse(content=html_content)
