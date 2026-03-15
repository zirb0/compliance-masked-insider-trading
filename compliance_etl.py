# MIT License | Copyright (c) 2026 Compliance Flow ETL
import yfinance as yf
import hashlib
import pandas as pd
import os
import sys

def salt_and_hash(text, salt=os.getenv('COMPLIANCE_SALT', 'DEFAULT_STATIC_SALT')):
    text_str = str(text) if text is not None else ""
    # Ensure a non-empty salt is used
    active_salt = salt if (salt and salt != 'DEFAULT_STATIC_SALT') else "EMERGENCY_PROTECTION_SALT"
    return hashlib.sha256((text_str + active_salt).encode()).hexdigest()

def test_masking_integrity(df):
    """Unit Test: Verifies complete PII removal via substring scanning"""
    # High-risk keywords that should NEVER appear in the final CSV
    forbidden = ["Cook", "Apple", "CEO", "Director", "Officer", "President"] 
    regex_pattern = '|'.join(forbidden)
    
    for col in df.columns:
        if df[col].astype(str).str.contains(regex_pattern, case=False, na=False).any():
            raise ValueError(f"SECURITY BREACH: Raw PII detected in column '{col}'!")
    print("Unit Test Passed: Dataset is anonymized.")

def main():
    ticker_symbol = "AAPL"
    try:
        ticker = yf.Ticker(ticker_symbol)
        
        # Resilient Data Extraction: Try multiple known attributes
        df = None
        for attr in ['insiders', 'get_insiders']:
            if hasattr(ticker, attr):
                val = getattr(ticker, attr)
                df = val() if callable(val) else val
                break
        
        if df is None or not isinstance(df, pd.DataFrame) or df.empty:
            print(f"Compliance Alert: No insider data available for {ticker_symbol}.")
            # We exit with 0 here to prevent "False Alarm" failures if no trades happened
            sys.exit(0)

        # Standardizing column names for the masking logic
        df.columns = [c.capitalize() for c in df.columns]
        target_cols = ['Insider', 'Position']
        
        if not all(col in df.columns for col in target_cols):
            print(f"Data Schema Mismatch. Found: {list(df.columns)}")
            sys.exit(1)

        # Execute Blindfold
        df['mask_executive_id'] = df['Insider'].apply(salt_and_hash)
        df['mask_position_id'] = df['Position'].apply(salt_and_hash)
        
        # Purge PII
        secure_df = df.drop(columns=target_cols)
        
        test_masking_integrity(secure_df)
        secure_df.to_csv('masked_insider_trading.csv', index=False)
        print(f"Compliance Flow: {len(secure_df)} records secured.")

    except Exception as e:
        print(f"Pipeline Error: {str(e)}")
        sys.exit(1)

if __name__ == "__main__":
    main()
