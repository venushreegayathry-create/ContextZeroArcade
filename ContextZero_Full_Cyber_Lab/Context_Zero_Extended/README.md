# Context Zero Extended — B.Tech Information Security Mini-Project

## Features
- Neon cyberpunk dashboard with simulated terminal telemetry and decorative threat constellation
- Gamified analyst progression: XP, levels, mission board, achievement badges and local progress storage
- Interactive incident-investigation challenge about indirect prompt injection
- Login with PBKDF2-HMAC-SHA256 password hashing (demo credentials below)
- Prompt-injection heuristic scanner with risk scoring and SHA-256 fingerprints
- Controlled vulnerable-vs-defended mock assistant
- Caesar cipher encryption/decryption
- SHA-256 hash demonstration
- AES-256-GCM authenticated encryption
- HMAC-SHA256 message authentication
- RSA-OAEP public-key encryption and private-key decryption for short messages
- RSA-PSS digital signatures and public-key verification
- SQLite event log protected by HMAC tags, integrity verification, CSV export
- 10-case test suite with TP/FP/TN/FN, accuracy, precision, recall, F1

## Windows installation
1. Extract this ZIP.
2. Open the `Context_Zero_Extended` folder in File Explorer.
3. Click the address bar, type `cmd`, press Enter.
4. Run one command at a time:
   `py -m venv .venv`
   `.venv\\Scripts\\activate`
   `pip install -r requirements.txt`
   `py app.py`
5. Open http://127.0.0.1:5000

If `py` is not recognized, try `python`. Keep the terminal open while presenting; Ctrl+C stops the server.

## Demo login
Username: `admin`
Password: `ContextZero2026!`
Demo-only credential; do not use in production.

## New arcade features
- **Missions & XP:** complete scanner, defense, evaluation, cryptography, audit and incident tasks to earn XP.
- **Incident Game:** choose how to handle malicious instructions embedded in a fictional document.
- **Live system terminal / threat constellation:** animated simulated telemetry for presentation visuals only; these do not monitor real networks.
- **Progress storage:** game XP and mission progress are stored in the current browser using localStorage. They are separate from the server audit log.

## Suggested demo order
1. Scan a benign prompt and an instruction override.
2. Compare vulnerable and defended mock assistants.
3. Run the 10-case test suite and explain precision/recall.
4. Show Caesar, SHA-256, AES-GCM, HMAC, RSA-OAEP and RSA-PSS.
5. Show audit HMAC verification and export the CSV report.

## Syllabus mapping
- Classical ciphers: Caesar cipher.
- Symmetric-key/block ciphers/AES: AES-256-GCM.
- Asymmetric/public-key cryptography: RSA-OAEP.
- Cryptographic hashes: SHA-256.
- Message integrity/authentication: HMAC-SHA256 and AES-GCM authentication tag.
- Digital signatures: RSA-PSS sign and verify.
- Key management: local AES, HMAC and RSA key files (illustrative only).
- Entity authentication: login session and PBKDF2 password hash.
- Information security/application testing: prompt scanner, controlled simulation, test suite and audit log.

## Limitations
The terminal feed and threat constellation are simulated visual elements; XP/badges are client-side gamification and are not security evidence.
The detector is rule-based, can have false positives/negatives, and is not a real LLM. The vulnerable/defended assistants are deterministic mock fixtures. The test set is small and hand-labelled. Caesar is intentionally weak. Demo credentials and local key storage are not production-grade. Server binds to 127.0.0.1. Use only in authorized, controlled environments.


## Expanded visual learning modules
This edition includes an Attack Pattern Library with inline explanations, an OWASP LLM risk overview, an interactive Defense-in-Depth layer explorer, and a scripted Pen-Test Simulator for fictional local scenarios. Simulator outcomes are educational walkthroughs, not real target scans.
