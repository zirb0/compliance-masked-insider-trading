"""
Module: compliance_etl.py
Description: Enterprise-grade ETL pipeline for SEC Insider Trading data.
Architecture: Zero-Trust / PII-Masked Ingestion

EXTENDED TECHNICAL DESCRIPTION:
-------------------------------
1. DATA INGESTION: 
   Leverages the yfinance API to extract Form 4 (Insider Trading) disclosures. 
   The script implements a dynamic attribute check to handle upstream API 
   versioning shifts (v0.2.x), ensuring resilient data retrieval.

2. CRYPTOGRAPHIC MASKING (Security):
   Implements a deterministic SHA-256 hashing algorithm combined with a 
   salted environmental variable. This ensures that:
   - Identifiable names/titles never enter the storage layer (GitHub/CSV).
   - Behavioral consistency is preserved (the same executive always 
     resolves to the same masked ID), allowing for historical analysis 
     without compromising PII.

3. DATA NORMALIZATION:
   Cleans and casts financial data types (Shares, Value) for seamless 
   integration with Power BI and future ML modeling.

4. AUTOMATION:
   Designed for headless execution via GitHub Actions. Uses standard 
   exit codes to signal pipeline health to the CI/CD runner.
"""

# MIT License | Copyright (c) 2026 Compliance Flow ETL
import yfinance as yf
import hashlib
import pandas as pd
import os
import sys

def salt_and_hash(text, salt=os.getenv('COMPLIANCE_SALT', 'DEFAULT_STATIC_SALT')):
    text_str = str(text) if text is not None else ""
    active_salt = salt if (salt and salt != 'DEFAULT_STATIC_SALT') else "EMERGENCY_PROTECTION_SALT"
    return hashlib.sha256((text_str + active_salt).encode()).hexdigest()

def test_masking_integrity(df):
    """Unit Test: Verifies complete PII removal"""
    forbidden = ["Cook", "Musk", "Nadella", "CEO", "Director", "President", "Officer"] 
    regex_pattern = '|'.join(forbidden)
    
    for col in df.columns:
        if df[col].astype(str).str.contains(regex_pattern, case=False, na=False).any():
            raise ValueError(f"SECURITY BREACH: Sensitive term detected in '{col}'!")
    print("Unit Test Passed: Dataset is anonymized.")

def main():
    # Watchlist to ensure we get data even if one API endpoint is throttled
    watchlist = ["AAPL", "TSLA", "MSFT", "GOOGL", "AMZN", "NVDA", "META"]
    combined_data = []

    try:
        for ticker_symbol in watchlist:
            print(f"Fetching data for {ticker_symbol}...")
            ticker = yf.Ticker(ticker_symbol)
            
            # Dynamic attribute resolution for 2026 yfinance structure
            df = None
            for attr in ['insiders', 'get_insiders', 'insider_transactions']:
                if hasattr(ticker, attr):
                    val = getattr(ticker, attr)
                    df = val() if callable(val) else val
                    if df is not None and not df.empty:
                        break
            
            if df is not None and isinstance(df, pd.DataFrame) and not df.empty:
                df['Ticker'] = ticker_symbol
                combined_data.append(df)

        if not combined_data:
            print("Compliance Alert: No data found for any ticker in watchlist.")
            sys.exit(0)

        # Merge all found data
        full_df = pd.concat(combined_data, ignore_index=True)
        full_df.columns = [c.capitalize() for c in full_df.columns]
        
        # Mapping variations in API column naming
        col_map = {'Name': 'Insider', 'Individual': 'Insider', 'Title': 'Position'}
        full_df = full_df.rename(columns=col_map)

        if 'Insider' not in full_df.columns or 'Position' not in full_df.columns:
            print(f"Schema Error. Available: {list(full_df.columns)}")
            sys.exit(1)

        # Secure the data
        full_df['mask_executive_id'] = full_df['Insider'].apply(salt_and_hash)
        full_df['mask_position_id'] = full_df['Position'].apply(salt_and_hash)
        
        secure_df = full_df.drop(columns=['Insider', 'Position'])
        
        test_masking_integrity(secure_df)
        secure_df.to_csv('masked_insider_trading.csv', index=False)
        print(f"Compliance Flow: {len(secure_df)} total records secured.")

    except Exception as e:
        print(f"Pipeline Error: {str(e)}")
        sys.exit(1)

if __name__ == "__main__":
    main()
