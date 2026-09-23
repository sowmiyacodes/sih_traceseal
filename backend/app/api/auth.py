from __future__ import annotations

from fastapi import APIRouter, Depends, Header, HTTPException, status
from pydantic import BaseModel

from app.services.auth_service import AuthService
from app.services.audit_service import AuditService

router = APIRouter(tags=["auth"])


class LoginRequest(BaseModel):
    username: str
    password: str


class UserCreateRequest(BaseModel):
    username: str
    password: str
    display_name: str
    role: str
    recipient_id: str | None = None


class UserStatusRequest(BaseModel):
    active: bool


class UserUpdateRequest(BaseModel):
    username: str
    display_name: str
    role: str
    recipient_id: str | None = None
    password: str | None = None


def current_user(authorization: str | None = Header(default=None)) -> dict:
    token = authorization.removeprefix("Bearer ").strip() if authorization else None
    user = AuthService.get_user_for_token(token)
    if user is None:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Authentication required")
    return user


def require_roles(*roles: str):
    def dependency(user: dict = Depends(current_user)) -> dict:
        if user["role"] not in roles:
            raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Insufficient role")
        return user
    return dependency


@router.post("/auth/login")
def login(payload: LoginRequest):
    result = AuthService.login(payload.username, payload.password)
    if result is None:
        AuditService.record('LOGIN', subject_id=payload.username, outcome='FAILURE')
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid username or password")
    AuditService.record('LOGIN', actor_id=result['user_id'], outcome='SUCCESS')
    return result


@router.post("/auth/logout")
def logout(authorization: str | None = Header(default=None), _: dict = Depends(current_user)):
    token = authorization.removeprefix("Bearer ").strip() if authorization else None
    AuthService.logout(token)
    AuditService.record('LOGOUT', actor_id=_["user_id"])
    return {"logged_out": True}


@router.get("/auth/me")
def me(user: dict = Depends(current_user)):
    return user


@router.get("/admin/users")
def list_users(_: dict = Depends(require_roles("ADMIN"))):
    return AuthService.list_users()


@router.post("/admin/users")
def create_user(payload: UserCreateRequest, _: dict = Depends(require_roles("ADMIN"))):
    try:
        return AuthService.create_user(payload.username, payload.password, payload.display_name, payload.role, payload.recipient_id)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc


@router.patch('/admin/users/{user_id}')
def set_user_status(user_id: str, payload: UserStatusRequest, _: dict = Depends(require_roles('ADMIN'))):
    try:
        return AuthService.set_user_active(user_id, payload.active)
    except ValueError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc


@router.patch('/admin/users/{user_id}/details')
def update_user(user_id: str, payload: UserUpdateRequest, _: dict = Depends(require_roles('ADMIN'))):
    try:
        return AuthService.update_user(user_id, payload.username, payload.display_name, payload.role, payload.recipient_id, payload.password)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc


@router.delete('/admin/users/{user_id}')
def delete_user(user_id: str, _: dict = Depends(require_roles('ADMIN'))):
    try:
        AuthService.delete_user(user_id)
        return {'user_id': user_id, 'deleted': True}
    except ValueError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
