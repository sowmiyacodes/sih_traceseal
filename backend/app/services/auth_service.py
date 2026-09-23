from __future__ import annotations

import base64
import hashlib
import hmac
import json
import os
import secrets
from datetime import datetime, timedelta, timezone
from pathlib import Path

from sqlalchemy.orm import Session

from app.models.database import SessionLocal
from app.models.user import User
from app.models.recipient import Recipient


class AuthService:
    SESSION_TTL = timedelta(hours=8)
    _sessions: dict[str, tuple[dict | int, datetime]] = {}
    JSON_AUTH_PATH = Path(__file__).resolve().parents[2] / 'config' / 'auth_users.json'

    @classmethod
    def json_auth_enabled(cls) -> bool:
        return os.environ.get('TRACESEAL_AUTH_JSON', '').lower() in {'1', 'true', 'yes'}

    @classmethod
    def json_users(cls) -> list[dict]:
        try:
            return json.loads(cls.JSON_AUTH_PATH.read_text(encoding='utf-8')).get('users', [])
        except (OSError, json.JSONDecodeError, AttributeError):
            return []

    @classmethod
    def save_json_users(cls, users: list[dict]) -> None:
        cls.JSON_AUTH_PATH.parent.mkdir(parents=True, exist_ok=True)
        cls.JSON_AUTH_PATH.write_text(json.dumps({'users': users}, indent=2) + '\n', encoding='utf-8')

    @staticmethod
    def hash_password(password: str) -> str:
        if not password or len(password) < 8:
            raise ValueError("Password must contain at least 8 characters")
        salt = secrets.token_bytes(16)
        digest = hashlib.scrypt(password.encode(), salt=salt, n=2**14, r=8, p=1)
        return "scrypt$16384$8$1$%s$%s" % (
            base64.urlsafe_b64encode(salt).decode(),
            base64.urlsafe_b64encode(digest).decode(),
        )

    @staticmethod
    def verify_password(password: str, encoded: str) -> bool:
        try:
            algorithm, n, r, p, salt_text, digest_text = encoded.split("$")
            if algorithm != "scrypt":
                return False
            salt = base64.urlsafe_b64decode(salt_text.encode())
            expected = base64.urlsafe_b64decode(digest_text.encode())
            actual = hashlib.scrypt(password.encode(), salt=salt, n=int(n), r=int(r), p=int(p))
            return hmac.compare_digest(actual, expected)
        except (ValueError, TypeError):
            return False

    @classmethod
    def seed_admin(cls) -> None:
        username = os.environ.get('TRACESEAL_DEMO_ADMIN_USERNAME')
        password = os.environ.get('TRACESEAL_DEMO_ADMIN_PASSWORD')
        if not username or not password:
            return
        db: Session = SessionLocal()
        try:
            if db.query(User).filter(User.username == username).first() is None:
                db.add(User(
                    user_id="USR-ADMIN",
                    username=username,
                    display_name="Local Administrator",
                    password_hash=cls.hash_password(password),
                    role="ADMIN",
                ))
                db.commit()
        finally:
            db.close()

    @classmethod
    def seed_demo_recipient(cls) -> None:
        username = os.environ.get('TRACESEAL_DEMO_RECIPIENT_USERNAME')
        password = os.environ.get('TRACESEAL_DEMO_RECIPIENT_PASSWORD')
        if not username or not password:
            return
        db: Session = SessionLocal()
        try:
            user = db.query(User).filter(User.username == username).first()
            if user is not None:
                return
            recipient = db.query(Recipient).filter(Recipient.recipient_id == 'REC-001').first()
        finally:
            db.close()

        if recipient is None:
            from app.services.recipient_service import RecipientService
            recipient = RecipientService.create_recipient('Alice Demo', 'Security')

        recipient_id = recipient['recipient_id'] if isinstance(recipient, dict) else recipient.recipient_id

        cls.create_user(
            username=username,
            password=password,
            display_name='Alice Demo',
            role='RECIPIENT',
            recipient_id=recipient_id,
        )

    @classmethod
    def login(cls, username: str, password: str) -> dict | None:
        if cls.json_auth_enabled():
            user = next((item for item in cls.json_users() if item.get('username') == username), None)
            if user is None or not user.get('active') or not cls.verify_password(password, user.get('password_hash', '')):
                return None
            token = secrets.token_urlsafe(32)
            expires_at = datetime.now(timezone.utc) + cls.SESSION_TTL
            profile = {key: value for key, value in user.items() if key != 'password_hash'}
            cls._sessions[token] = (profile, expires_at)
            return {"token": token, "expires_at": expires_at.isoformat(), **profile}
        db: Session = SessionLocal()
        try:
            user = db.query(User).filter(User.username == username).first()
            if user is None or not user.active or not cls.verify_password(password, user.password_hash):
                return None
            token = secrets.token_urlsafe(32)
            expires_at = datetime.now(timezone.utc) + cls.SESSION_TTL
            cls._sessions[token] = (user.id, expires_at)
            return {"token": token, "expires_at": expires_at.isoformat(), **cls.to_dict(user)}
        finally:
            db.close()

    @classmethod
    def get_user_for_token(cls, token: str | None) -> dict | None:
        if not token or token not in cls._sessions:
            return None
        user_ref, expires_at = cls._sessions[token]
        if expires_at <= datetime.now(timezone.utc):
            cls._sessions.pop(token, None)
            return None
        if isinstance(user_ref, dict):
            return user_ref
        user_id = user_ref
        db: Session = SessionLocal()
        try:
            user = db.query(User).filter(User.id == user_id, User.active.is_(True)).first()
            return None if user is None else cls.to_dict(user)
        finally:
            db.close()

    @classmethod
    def logout(cls, token: str | None) -> None:
        if token:
            cls._sessions.pop(token, None)

    @staticmethod
    def create_user(username: str, password: str, display_name: str, role: str, recipient_id: str | None = None) -> dict:
        if role not in {"ADMIN", "SENDER", "RECIPIENT", "FORENSIC_INVESTIGATOR"}:
            raise ValueError("Unsupported role")
        if role == "RECIPIENT" and not recipient_id:
            raise ValueError("Recipient accounts must be linked to a recipient ID")
        if AuthService.json_auth_enabled():
            users = AuthService.json_users()
            if any(item.get('username') == username for item in users):
                raise ValueError("Username already exists")
            if role == "RECIPIENT":
                db: Session = SessionLocal()
                try:
                    recipient = db.query(Recipient).filter(Recipient.recipient_id == recipient_id, Recipient.active.is_(True)).first()
                    if recipient is None:
                        raise ValueError("Linked recipient does not exist or is disabled")
                finally:
                    db.close()
            user = {
                'user_id': f"USR-JSON-{secrets.token_hex(4).upper()}",
                'username': username,
                'display_name': display_name,
                'role': role,
                'recipient_id': recipient_id if role == 'RECIPIENT' else None,
                'active': True,
                'password_hash': AuthService.hash_password(password),
            }
            AuthService.save_json_users([*users, user])
            return {key: value for key, value in user.items() if key != 'password_hash'}
        db: Session = SessionLocal()
        try:
            if role == "RECIPIENT":
                recipient = db.query(Recipient).filter(Recipient.recipient_id == recipient_id, Recipient.active.is_(True)).first()
                if recipient is None:
                    raise ValueError("Linked recipient does not exist or is disabled")
            if db.query(User).filter(User.username == username).first() is not None:
                raise ValueError("Username already exists")
            user = User(
                user_id=f"USR-{secrets.token_hex(4).upper()}",
                username=username,
                display_name=display_name,
                password_hash=AuthService.hash_password(password),
                role=role,
                recipient_id=recipient_id if role == 'RECIPIENT' else None,
            )
            db.add(user)
            db.commit()
            db.refresh(user)
            return AuthService.to_dict(user)
        finally:
            db.close()

    @staticmethod
    def list_users() -> list[dict]:
        if AuthService.json_auth_enabled():
            return [{key: value for key, value in user.items() if key != 'password_hash'} for user in AuthService.json_users()]
        db: Session = SessionLocal()
        try:
            return [AuthService.to_dict(user) for user in db.query(User).order_by(User.id).all()]
        finally:
            db.close()

    @staticmethod
    def set_user_active(user_id: str, active: bool) -> dict:
        if AuthService.json_auth_enabled():
            users = AuthService.json_users()
            for user in users:
                if user.get('user_id') == user_id:
                    user['active'] = active
                    AuthService.save_json_users(users)
                    return {key: value for key, value in user.items() if key != 'password_hash'}
            raise ValueError('User not found')
        db: Session = SessionLocal()
        try:
            user = db.query(User).filter(User.user_id == user_id).first()
            if user is None:
                raise ValueError('User not found')
            user.active = active
            db.commit()
            db.refresh(user)
            return AuthService.to_dict(user)
        finally:
            db.close()

    @staticmethod
    def update_user(user_id: str, username: str, display_name: str, role: str, recipient_id: str | None = None, password: str | None = None) -> dict:
        if role not in {"ADMIN", "SENDER", "RECIPIENT", "FORENSIC_INVESTIGATOR"}:
            raise ValueError('Unsupported role')
        if role == 'RECIPIENT' and not recipient_id:
            raise ValueError('Recipient accounts must be linked to a recipient ID')
        if AuthService.json_auth_enabled():
            users = AuthService.json_users()
            user = next((item for item in users if item.get('user_id') == user_id), None)
            if user is None:
                raise ValueError('User not found')
            if any(item.get('username') == username and item.get('user_id') != user_id for item in users):
                raise ValueError('Username already exists')
            user.update({'username': username, 'display_name': display_name, 'role': role, 'recipient_id': recipient_id if role == 'RECIPIENT' else None})
            if password:
                user['password_hash'] = AuthService.hash_password(password)
            AuthService.save_json_users(users)
            return {key: value for key, value in user.items() if key != 'password_hash'}
        db: Session = SessionLocal()
        try:
            user = db.query(User).filter(User.user_id == user_id).first()
            if user is None:
                raise ValueError('User not found')
            user.username = username
            user.display_name = display_name
            user.role = role
            user.recipient_id = recipient_id if role == 'RECIPIENT' else None
            if password:
                user.password_hash = AuthService.hash_password(password)
            db.commit()
            db.refresh(user)
            return AuthService.to_dict(user)
        finally:
            db.close()

    @staticmethod
    def delete_user(user_id: str) -> None:
        if AuthService.json_auth_enabled():
            users = AuthService.json_users()
            remaining = [user for user in users if user.get('user_id') != user_id]
            if len(remaining) == len(users):
                raise ValueError('User not found')
            AuthService.save_json_users(remaining)
            return
        db: Session = SessionLocal()
        try:
            user = db.query(User).filter(User.user_id == user_id).first()
            if user is None:
                raise ValueError('User not found')
            db.delete(user)
            db.commit()
        finally:
            db.close()

    @staticmethod
    def to_dict(user: User) -> dict:
        return {
            "user_id": user.user_id,
            "username": user.username,
            "display_name": user.display_name,
            "role": user.role,
            "recipient_id": user.recipient_id,
            "active": user.active,
            "created_at": user.created_at.isoformat() if user.created_at else None,
        }
