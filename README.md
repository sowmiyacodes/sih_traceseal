# TraceSeal Forensic Attribution System

A local-first forensic document attribution prototype that combines document encryption, watermark detection, signed event metadata, and a local immutable ledger for attribution analysis.

## Overview

This project provides a complete offline workflow for:

- uploading suspected leaked files
- encrypting and storing documents locally
- decrypting documents with a supplied AES-256-GCM key
- detecting/extracting a watermark marker
- matching the watermark to a local ledger event
- validating the signed event payload and ledger chain
- attributing the document to a recipient only after cryptographic verification passes

The design preserves the Phase 1 crypto abstractions, while adding a working local forensic analysis flow and a professional monitoring UI for users.

## Core Flow

1. User uploads a suspected leaked document.
2. Backend stores the encrypted file and related metadata in SQLite.
3. User decrypts the file using the relevant AES-256-GCM key.
4. Backend detects the TraceSeal watermark marker.
5. Ledger lookup matches the watermark to a signed decryption event.
6. Event and chain verification are checked locally.
7. If all checks pass, the system reports the associated recipient.
8. A forensic case is created with evidence metadata and verification results.

## Architecture

- Backend: FastAPI, SQLAlchemy, SQLite, local JSON ledger, cryptographic services
- Frontend: React + Vite + TypeScript + MUI
- Storage: local filesystem and SQLite metadata database
- Offline mode: no Docker, no cloud, no external runtime dependency

## Cryptography and Security Model

- SHA3-256 for hashes and ledger integrity
- AES-256-GCM for document encryption/decryption
- ML-KEM-768 abstraction for key establishment where used
- ML-DSA-65 abstraction for signature verification and event signing

Security rules followed by the design:

- never return or log private keys
- never store private keys in plaintext in SQLite
- never claim attribution without cryptographic and ledger verification
- distinguish watermark detection from attribution
- do not put recipient identity directly in the watermark payload

## Watermarking

The system reuses the local transform-aware watermark design and extends it with a deterministic text-based TraceSeal marker for reliable local validation.

The marker contains:

- watermark_id
- document_id
- recipient_id
- session_id
- nonce

That ensures the watermark is traceable to a signed local event without exposing raw recipient identity in the watermark itself.

## Ledger

The local ledger is a JSON-based append-only hash chain stored under the project ledger_data folder.

Each block contains:

- block number
- timestamp
- previous hash
- transaction root
- block hash
- transaction entries

The chain is validated by recalculating the expected hash and checking previous_hash continuity.

## API Endpoints

### Documents
- POST /api/documents/upload
- GET /api/documents
- GET /api/documents/{document_id}
- POST /api/documents/decrypt

### Watermarks
- POST /api/watermark/detect
- POST /api/watermark/extract
- POST /api/watermark/embed

### Forensics
- POST /api/forensics/analyze
- GET /api/forensics/cases
- GET /api/forensics/cases/{case_id}

### Ledger
- GET /api/ledger/blocks
- GET /api/ledger/blocks/{block_number}
- GET /api/ledger/validate
- POST /api/ledger/verify
- GET /api/ledger/watermark/{watermark_id}
- GET /api/ledger/event/{event_id}

### Existing metadata endpoints
- GET /api/health
- GET /api/dashboard
- POST /api/recipients
- GET /api/recipients
- GET /api/events/{event_id}
- GET /api/watermarks/{watermark_id}

## Frontend Pages

The UI currently provides:

- Dashboard
- Documents
- Recipients
- Decryption
- Watermark Lab
- Ledger Explorer
- Forensic Investigation

These pages call the live local backend and display real values rather than mocked hardware state.

## How to Run

### Backend

```powershell
cd D:\sih_traceseal
.\.venv\Scripts\Activate.ps1
cd backend
python -m uvicorn app.main:app --host 127.0.0.1 --port 8000
```

### Frontend

```powershell
cd D:\sih_traceseal\frontend
npm install
npm run dev -- --host 127.0.0.1 --port 5173
```

Then open:

- http://127.0.0.1:5173
- http://127.0.0.1:8000/api/health

## Demo Flow

The backend seeds two local demo logins on startup. These accounts are for the offline demonstration only:

- Admin: `admin` / `traceseal-admin`
- Recipient: `alice` / `traceseal-alice` (linked to `REC-001`)

1. Sign in as admin and create/upload a document.
2. Assign the document to the seeded recipient or another active recipient.
3. Sign out and sign in as Alice.
4. Decrypt and download the protected copy. This creates a session watermark, signed event, and ledger record.
5. Sign in as an investigator-capable account and upload the leaked copy in Forensic Investigation.
6. Confirm the watermark, signature, ledger chain, and recipient attribution.

The demo recipient username and password can be overridden for local setup with `TRACESEAL_DEMO_RECIPIENT_USERNAME` and `TRACESEAL_DEMO_RECIPIENT_PASSWORD`.

## Tests

The backend suite includes validation for:

- hashing
- AES-GCM roundtrip
- ML-DSA signatures
- ML-KEM roundtrip
- session uniqueness
- watermark generation
- watermark detection
- ledger hashing
- chain validation
- event lookup
- recipient key roundtrip
- document encrypt/decrypt roundtrip

## Verification

Verified locally with:

```powershell
cd D:\sih_traceseal\backend
. ..\.venv\Scripts\Activate.ps1
pytest -q
```

Current result: 15 passed.

## Files Changed

- backend/app/api/documents.py
- backend/app/api/forensics.py
- backend/app/main.py
- backend/app/services/document_service.py
- backend/app/services/watermark_service.py
- backend/app/services/forensic_case_service.py
- backend/app/services/ledger_service.py
- frontend/src/App.tsx
- README.md

## Database and Schema Notes

The SQLite database is created automatically on startup via the model initialization in backend/app/models/database.py.

No migration framework is required for this local prototype, but table creation is handled automatically on app boot.

## Limitations

This is still a local prototype and not a distributed forensic platform. It is designed to run entirely offline with deterministic local verification and strong traceability for demonstration and validation work.
