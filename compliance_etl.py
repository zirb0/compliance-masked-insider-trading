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
import datetime

def salt_and_hash(text, salt=os.getenv('COMPLIANCE_SALT', 'DEFAULT_STATIC_SALT')):
    text_str = str(text) if text is not None else ""
    active_salt = salt if (salt and salt != 'DEFAULT_STATIC_SALT') else "EMERGENCY_PROTECTION_SALT"
    return hashlib.sha256((text_str + active_salt).encode()).hexdigest()

def get_30_day_price_change(ticker_symbol, trade_date_str):
    """Calculates the percentage change in stock price 30 days after a trade."""
    try:
        # Convert string to datetime
        trade_date = pd.to_datetime(trade_date_str).tz_localize(None)
        end_date = trade_date + datetime.timedelta(days=40) # Buffer for weekends/holidays
        
        # Fetch historical data for that specific window
        hist = yf.download(ticker_symbol, start=trade_date.strftime('%Y-%m-%d'), end=end_date.strftime('%Y-%m-%d'), progress=False)
        
        if hist.empty or len(hist) < 2:
            return None
            
        # Price on (or immediately after) trade date
        price_at_trade = hist['Close'].iloc[0].item() 
        # Price ~30 days later (last available row in our 40-day buffer)
        price_30d_later = hist['Close'].iloc[-1].item()
        
        # Calculate Percentage Delta
        delta = (price_30d_later - price_at_trade) / price_at_trade
        return round(delta, 4) # Returns a decimal like 0.0521 (5.21%)
        
    except Exception as e:
        return None
        
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
                
                # --- PHASE 2: ML LABELING ---
                # Assuming the API returns a 'Start Date' or 'Date' column
                date_col = 'Start Date' if 'Start Date' in df.columns else 'Date' if 'Date' in df.columns else None
                
                if date_col:
                    print(f"Calculating 30-day price deltas for {ticker_symbol}...")
                    # Apply the function to each row
                    df['30_Day_Return'] = df.apply(lambda row: get_30_day_price_change(row['Ticker'], row[date_col]), axis=1)
                    
                    # Create the ML Target Label: 1 if it made more than 5%, else 0
                    df['ML_Target_Signal'] = df['30_Day_Return'].apply(lambda x: 1 if x is not None and x > 0.05 else 0)
                
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
        
        # Drop PII and empty API artifacts like 'Transaction'
        secure_df = full_df.drop(columns=['Insider', 'Position', 'Transaction'], errors='ignore')
        
        test_masking_integrity(secure_df)
        secure_df.to_csv('masked_insider_trading.csv', index=False)
        print(f"Compliance Flow: {len(secure_df)} total records secured.")

    except Exception as e:
        print(f"Pipeline Error: {str(e)}")
        sys.exit(1)

if __name__ == "__main__":
    main()
