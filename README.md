# compliance-flow-etl

## Overview
**compliance-flow-etl** is a production-grade data engineering pipeline designed to ingest high-sensitivity SEC Insider Trading disclosures while maintaining 100% PII security through automated masking and validation.

## Architecture
This system implements a "Defensive Anonymization" pattern:
1. **Extraction:** Real-time executive trading data is pulled from the Yahoo Finance API.
2. **Cryptographic Masking:** Identities are transformed using **Salted SHA-256 Hashing** at the point of ingestion to prevent rainbow table attacks.
3. **Automated Unit Testing:** A built-in integrity check scans the final dataset to ensure zero raw PII leakage.
4. **Data Quality Gate:** The CI/CD pipeline validates file size and presence before committing to the repository.

## Design Philosophy: The Zero-Trust Bridge
This project intentionally masks public SEC data to demonstrate a Production-Gate Architecture. In modern FinTech, data must be anonymized before it reaches the visualization layer to satisfy GDPR and CCPA requirements.
By treating public data as 'Sensitive,' this pipeline serves as a blueprint for handling internal proprietary data where:
1. Data Utility is preserved (we can still see patterns).
2. Legal Liability is eliminated (we don't store PII).
3. Audit Trails are automated (via GitHub Actions).

## Tech Stack
* **Language:** Python 3.10 (Pandas, Hashlib)
* **API:** yfinance
* **Orchestration:** GitHub Actions
* **License:** MIT
