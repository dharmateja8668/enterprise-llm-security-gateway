from fastapi import APIRouter, Depends, Query
from sqlalchemy.orm import Session
from sqlalchemy import func, desc
from app.db import get_db
from app.models.log import RequestLog
from app.models.audit import AuditLog
from fastapi.responses import HTMLResponse
from datetime import datetime, timedelta

router = APIRouter(prefix="/dashboard", tags=["Dashboard"])

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
    
    blocked_req = req_query.filter(RequestLog.status.in_(["injection_blocked", "content_safety_blocked"])).count()
    allowed_req = req_query.filter(RequestLog.status == "success").count()
    
    # Active users count
    active_users = req_query.filter(RequestLog.user_token.isnot(None)).distinct(RequestLog.user_token).count()
    
    # Previous period
    prev_req_query = db.query(RequestLog).filter(RequestLog.timestamp >= prev_cutoff_start, RequestLog.timestamp < prev_cutoff_end)
    prev_total = prev_req_query.count()
    prev_blocked = prev_req_query.filter(RequestLog.status.in_(["injection_blocked", "content_safety_blocked"])).count()
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
                if log.status in ["injection_blocked", "content_safety_blocked"]:
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
                if log.status in ["injection_blocked", "content_safety_blocked"]:
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
    
    # Get all logs to show a mix, or just blocked. Prompt asks for a mix including "Request Blocked" and others.
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
        elif log.status == "error":
            event_name = "API Error"
            severity = "Medium"
        else:
            event_name = "Successful Request"
            severity = "Low"
            
        if log.status != "success": # Filter to only show security relevant or all? I will show all for now since it asks for "recent security events in a table... Status"
            events.append({
                "timestamp": log.timestamp.isoformat() + "Z",
                "user": log.user_token if log.user_token else "Unknown",
                "model": log.model if log.model else "Unknown",
                "event": event_name,
                "status": "Blocked" if log.status in ["injection_blocked", "content_safety_blocked"] else ("Error" if log.status == "error" else "Allowed"),
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
    
    return {
        "categories": ["Prompt Injection", "Unsafe Content"],
        "counts": [injection, content_safety]
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

@router.get("/", response_class=HTMLResponse)
def get_dashboard_html():
    with open("app/routes/dashboard.html", "r", encoding="utf-8") as f:
        html_content = f.read()
    return HTMLResponse(content=html_content)
