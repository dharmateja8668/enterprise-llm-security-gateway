"""
app/routes/chat_sessions.py
REST endpoints for User-Isolated Chat Sessions and Messages.

Ensures every chat thread and message is owned and accessible ONLY by its creator.
"""

import json
import logging
from typing import List, Optional
from fastapi import APIRouter, Depends, HTTPException, Query, Header, status
from pydantic import BaseModel, ConfigDict
from sqlalchemy.orm import Session

from app.db import get_db
from app.models.chat_session import ChatThread, ChatMessageRecord
from app.models.user import User

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/chats", tags=["Chat Sessions"])


def get_authenticated_user_id(
    user_id: Optional[str] = Query(None),
    x_user_id: Optional[str] = Header(None),
    authorization: Optional[str] = Header(None),
    db: Session = Depends(get_db),
) -> str:
    """Helper to extract user identifier and verify active status."""
    identifier = user_id or x_user_id
    if not identifier and authorization and authorization.lower().startswith("bearer "):
        identifier = authorization.split()[1]

    if not identifier:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Authentication required",
        )

    # Optional lookup to sanitize identifier to username
    user = None
    if str(identifier).isdigit():
        user = db.query(User).filter(User.id == int(identifier)).first()
    if not user:
        user = db.query(User).filter(User.username == identifier).first()
    if not user:
        user = db.query(User).filter(User.email == identifier).first()

    return user.username if user else identifier


class MessageSchema(BaseModel):
    id: str
    role: str
    content: str
    timestamp: str
    isBlocked: bool = False
    blockType: Optional[str] = None
    piiSummary: Optional[dict] = None
    model: Optional[str] = None


class ThreadResponseSchema(BaseModel):
    id: str
    title: str
    createdAt: str
    messages: List[MessageSchema] = []


class CreateThreadRequest(BaseModel):
    title: Optional[str] = "New Security Chat"


@router.get("", response_model=List[ThreadResponseSchema])
def list_user_chats(
    user_id: str = Depends(get_authenticated_user_id),
    db: Session = Depends(get_db),
):
    """
    GET /chats — Return ONLY chat threads owned by the authenticated user.
    """
    threads = (
        db.query(ChatThread)
        .filter(ChatThread.user_id == user_id)
        .order_by(ChatThread.updated_at.desc())
        .all()
    )

    result = []
    for thread in threads:
        msg_list = []
        for msg in thread.messages:
            pii_data = json.loads(msg.pii_summary_json) if msg.pii_summary_json else None
            msg_list.append(
                MessageSchema(
                    id=msg.id,
                    role=msg.role,
                    content=msg.content,
                    timestamp=msg.timestamp.strftime("%I:%M %p"),
                    isBlocked=msg.is_blocked,
                    blockType=msg.block_type,
                    piiSummary=pii_data,
                    model=msg.model,
                )
            )

        result.append(
            ThreadResponseSchema(
                id=thread.id,
                title=thread.title,
                createdAt=thread.created_at.strftime("%I:%M %p"),
                messages=msg_list,
            )
        )

    return result


@router.get("/{chat_id}", response_model=ThreadResponseSchema)
def get_user_chat_by_id(
    chat_id: str,
    user_id: str = Depends(get_authenticated_user_id),
    db: Session = Depends(get_db),
):
    """
    GET /chats/{chat_id} — Retrieve specific chat.
    Enforces strict ownership: returns 403 Forbidden if user is not the owner.
    """
    thread = db.query(ChatThread).filter(ChatThread.id == chat_id).first()
    if not thread:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Chat thread not found",
        )

    if thread.user_id != user_id:
        logger.warning(
            "Unauthorized chat access attempt: user=%s requested thread owned by %s",
            user_id,
            thread.user_id,
        )
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail={
                "error": "Access Denied: You do not own this chat thread",
                "blocked": True,
                "reason": "chat_owner_mismatch",
            },
        )

    msg_list = []
    for msg in thread.messages:
        pii_data = json.loads(msg.pii_summary_json) if msg.pii_summary_json else None
        msg_list.append(
            MessageSchema(
                id=msg.id,
                role=msg.role,
                content=msg.content,
                timestamp=msg.timestamp.strftime("%I:%M %p"),
                isBlocked=msg.is_blocked,
                blockType=msg.block_type,
                piiSummary=pii_data,
                model=msg.model,
            )
        )

    return ThreadResponseSchema(
        id=thread.id,
        title=thread.title,
        createdAt=thread.created_at.strftime("%I:%M %p"),
        messages=msg_list,
    )


@router.post("", response_model=ThreadResponseSchema)
def create_user_chat(
    data: CreateThreadRequest,
    user_id: str = Depends(get_authenticated_user_id),
    db: Session = Depends(get_db),
):
    """
    POST /chats — Create a new chat thread associated with the authenticated user.
    """
    thread = ChatThread(
        user_id=user_id,
        title=data.title or "New Security Chat",
    )
    db.add(thread)
    db.commit()
    db.refresh(thread)

    return ThreadResponseSchema(
        id=thread.id,
        title=thread.title,
        createdAt=thread.created_at.strftime("%I:%M %p"),
        messages=[],
    )


@router.delete("/{chat_id}", status_code=status.HTTP_204_NO_CONTENT)
def delete_user_chat(
    chat_id: str,
    user_id: str = Depends(get_authenticated_user_id),
    db: Session = Depends(get_db),
):
    """
    DELETE /chats/{chat_id} — Delete chat thread. Enforces user ownership check.
    """
    thread = db.query(ChatThread).filter(ChatThread.id == chat_id).first()
    if not thread:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Chat thread not found",
        )

    if thread.user_id != user_id:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Access Denied: You do not own this chat thread",
        )

    db.delete(thread)
    db.commit()
    return None
