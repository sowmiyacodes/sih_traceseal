from __future__ import annotations

import os
from pathlib import Path
from typing import Generator

from sqlalchemy import create_engine, inspect, text
from sqlalchemy.orm import DeclarativeBase, Session, sessionmaker

BASE_DIR = Path(__file__).resolve().parents[2]
DB_PATH = BASE_DIR / "storage" / "forensic_system.db"
DATABASE_URL = os.getenv("DATABASE_URL", f"sqlite:///{DB_PATH}")


class Base(DeclarativeBase):
    pass


engine = create_engine(DATABASE_URL, connect_args={"check_same_thread": False}, future=True)
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)


def get_db() -> Generator[Session, None, None]:
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


def init_db() -> None:
    from app.models.document import Document
    from app.models.recipient import Recipient
    from app.models.watermark import Watermark
    from app.models.decryption_event import DecryptionEvent
    from app.models.user import User
    from app.models.recipient_package import RecipientPackage

    Base.metadata.create_all(bind=engine)
    inspector = inspect(engine)
    migrations = {
        'documents': {
            'decrypted_path': 'VARCHAR(512)',
            'watermarked_path': 'VARCHAR(512)',
        },
        'watermarks': {
            'algorithm': "VARCHAR(32) NOT NULL DEFAULT 'DCT'",
            'confidence': 'FLOAT NOT NULL DEFAULT 1.0',
        },
        'users': {
            'recipient_id': 'VARCHAR(32)',
        },
        'decryption_events': {
            'public_key_fingerprint': 'VARCHAR(128)',
        },
    }
    with engine.begin() as connection:
        for table, columns in migrations.items():
            existing = {column['name'] for column in inspector.get_columns(table)}
            for column, definition in columns.items():
                if column not in existing:
                    connection.execute(text(f'ALTER TABLE {table} ADD COLUMN {column} {definition}'))


init_db()
