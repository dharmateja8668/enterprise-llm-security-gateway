from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session
from app.db import get_db
from app.models.log import RequestLog
from app.models.audit import AuditLog
from fastapi.responses import HTMLResponse
from datetime import datetime, timedelta

router = APIRouter(prefix="/dashboard", tags=["Dashboard"])

@router.get("/metrics")
def get_metrics(db: Session = Depends(get_db)):
    # Retrieve metrics from RequestLog (the primary gateway log)
    total_req_logs = db.query(RequestLog).count()
    
    # Add legacy/other AuditLog if they exist
    total_audit_logs = db.query(AuditLog).count()
    
    total_requests = total_req_logs + total_audit_logs
    
    blocked_requests = db.query(RequestLog).filter(RequestLog.status.in_(["injection_blocked", "content_safety_blocked"])).count()
    allowed_requests_req = db.query(RequestLog).filter(RequestLog.status == "success").count()
    allowed_requests_audit = db.query(AuditLog).filter(AuditLog.status == "success").count()
    allowed_requests = allowed_requests_req + allowed_requests_audit
    
    error_requests_req = db.query(RequestLog).filter(RequestLog.status == "error").count()
    error_requests_audit = db.query(AuditLog).filter(AuditLog.status == "error").count()
    error_requests = error_requests_req + error_requests_audit
    
    return {
        "total_requests": total_requests,
        "total_prompts_processed": total_requests,
        "total_blocked_prompts": blocked_requests,
        "total_allowed_prompts": allowed_requests,
        "total_security_events": blocked_requests,
        "request_success_count": allowed_requests,
        "request_failure_count": error_requests
    }

@router.get("/usage")
def get_usage(db: Session = Depends(get_db)):
    seven_days_ago = datetime.utcnow() - timedelta(days=7)
    
    logs = db.query(RequestLog).filter(RequestLog.timestamp >= seven_days_ago).all()
    
    usage_data = {}
    for i in range(7):
        day = (datetime.utcnow() - timedelta(days=i)).strftime("%Y-%m-%d")
        usage_data[day] = {"requests": 0, "blocked": 0}
        
    for log in logs:
        day_str = log.timestamp.strftime("%Y-%m-%d")
        if day_str in usage_data:
            usage_data[day_str]["requests"] += 1
            if log.status in ["injection_blocked", "content_safety_blocked"]:
                usage_data[day_str]["blocked"] += 1
            
    labels = sorted(usage_data.keys())
    requests_over_time = [usage_data[day]["requests"] for day in labels]
    blocked_over_time = [usage_data[day]["blocked"] for day in labels]
    
    return {
        "labels": labels,
        "requests_over_time": requests_over_time,
        "blocked_over_time": blocked_over_time
    }

@router.get("/recent-events")
def get_recent_events(db: Session = Depends(get_db)):
    logs = db.query(RequestLog).order_by(RequestLog.timestamp.desc()).limit(20).all()
    events = []
    for log in logs:
        display_prompt = "***[REDACTED FOR SECURITY]***" if log.status == "success" else log.prompt
            
        events.append({
            "timestamp": log.timestamp.isoformat() + "Z",
            "request_id": log.request_id,
            "user": log.user_token if log.user_token else "Unknown",
            "model": log.model if log.model else "Unknown",
            "status": log.status,
            "blocked": log.status in ["injection_blocked", "content_safety_blocked"],
            "prompt": display_prompt,
        })
    return events

@router.get("/", response_class=HTMLResponse)
def get_dashboard_html():
    with open("app/routes/dashboard.html", "r", encoding="utf-8") as f:
        html_content = f.read()
    return HTMLResponse(content=html_content)
