#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Created on Fri May  2 14:21:01 2025

@author: yogeshkumarjain
"""

import requests
import pandas as pd
import ast
import time
from datetime import datetime, timedelta
import threading
from concurrent.futures import ThreadPoolExecutor, as_completed
from collections import deque

# Store timestamps of successful API calls (thread-safe)
call_timestamps = deque()
call_timestamps_lock = threading.Lock()

# ----------- CONFIGURATION -----------
BASE_URL = "https://caas-pilot-tdss.tookitaki.ai"
AUTH_ENDPOINT = "/api/v1/users/auth"
TXN_ENDPOINT = "/api/v1/realtime/5/fraud-alert"
FRAUD_ACK_ENDPOINT = "/api/v1/realtime/5/fraud-ack"

TENANT_ID = "5"
INPUT_CSV = "sample.csv"
OUTPUT_CSV = "output_responses.csv"
ack_run = 0

# ----------- DATA PREPROCESSING FUNCTION -----------
def read_and_preprocess_csv(csv_file_path):
    """
    Read CSV file and preprocess the data for API consumption.
    
    Args:
        csv_file_path (str): Path to the input CSV file
        
    Returns:
        pandas.DataFrame: Preprocessed DataFrame ready for API calls
    """
    # Read the CSV file
    df = pd.read_csv(csv_file_path)
    
    # Replace NaN with empty strings
    df = df.fillna("")
    
    # Enhanced datetime parsing to handle multiple formats
    def parse_datetime_flexible(date_str):
        """Parse datetime from multiple possible formats"""
        if not date_str or pd.isna(date_str) or date_str == "":
            return None
            
        # List of possible datetime formats
        formats = [
            "%Y-%m-%dT%H:%M:%S.%fZ",  # ISO format with milliseconds: 2025-07-01T00:10:00.000Z
            "%Y-%m-%dT%H:%M:%SZ",     # ISO format without milliseconds: 2025-07-01T00:10:00Z
            "%Y-%m-%dT%H:%M:%S",      # ISO format without Z: 2025-07-01T00:10:00
            "%m/%d/%Y %I:%M %p",      # Original format: 7/1/2025 12:10 AM
            "%Y-%m-%d %H:%M:%S",      # Standard format: 2025-07-01 00:10:00
            "%d/%m/%Y %H:%M:%S",      # European format: 01/07/2025 00:10:00
        ]
        
        for fmt in formats:
            try:
                return pd.to_datetime(date_str, format=fmt)
            except (ValueError, TypeError):
                continue
        
        # If none of the formats work, try pandas' flexible parsing
        try:
            return pd.to_datetime(date_str)
        except:
            print(f"Warning: Could not parse datetime: {date_str}")
            return None
    
    # Step 1: Convert to datetime using flexible parsing for sorting
    df["txn_date_time_sortable"] = df["txn_date_time"].apply(parse_datetime_flexible)
    
    # Step 2: Sort by the datetime (NaT values will be placed at the end)
    df = df.sort_values(by="txn_date_time_sortable", na_position='last').reset_index(drop=True)
    
    # Step 3: Drop the helper column after sorting
    df = df.drop(columns=["txn_date_time_sortable"])
    
    # Step 4: Handle duplicate column names (like receiver_incorporation_date appearing twice)
    # Remove duplicate columns by keeping the last occurrence
    df = df.loc[:, ~df.columns.duplicated(keep='last')]
    
    # Step 5: Strip whitespace from all string columns
    for col in df.select_dtypes(include=['object']).columns:
        df[col] = df[col].astype(str).str.strip()
    
    # Step 6: Replace empty strings back to actual empty strings (not "nan")
    df = df.replace(['nan', 'NaN', 'None'], '')
    
    print(f"Successfully preprocessed {len(df)} rows from {csv_file_path}")
    print(f"Columns found: {list(df.columns)}")
    
    return df

# ----------- AUTH FUNCTION -----------
def get_token():
    url = f"{BASE_URL}{AUTH_ENDPOINT}"
    headers = {
        "Accept-Language": "en-GB,en-US;q=0.9,en;q=0.8",
        "Authorization": "Basic dG9va2l0YWtpOnRvb2tpdGFraQ==",
        "Connection": "keep-alive",
        "Content-Type": "application/json;charset=UTF-8",
        "Origin": BASE_URL,
        "Referer": f"{BASE_URL}/",
        "User-Agent": "Mozilla/5.0",
    }
    params = {"tenantId": TENANT_ID}
    response = requests.post(url, headers=headers, json={}, params=params)
    response.raise_for_status()
    token = response.json().get("token")
    return token

# ----------- API CALL FUNCTION -----------
def send_transaction(payload, token):
    url = f"{BASE_URL}{TXN_ENDPOINT}"
    headers = {
        "Authorization": f"Token {token}",
        "Content-Type": "application/json"
    }
    formatted_payload = {
        "payload": payload,
        "format": "tt_json",
        "version": "1"
    }
    #print(formatted_payload)
    response = requests.post(url, headers=headers, json=formatted_payload)
    response.raise_for_status()
    return response.json()   # return dict, not status/text
#    return response.status_code, response.text

# ----------- Acknowledge API CALL FUNCTION -----------
def send_fraud_ack(payload, token):
    url = f"{BASE_URL}{FRAUD_ACK_ENDPOINT}"
    headers = {
        "Authorization": f"Token {token}",
        "Content-Type": "application/json"
    }
    formatted_payload = {
        "payload": payload,
        "format": "tt_json",
        "version": "1"
    }
    response = requests.post(url, headers=headers, json=formatted_payload)
    response.raise_for_status()
    return response.text.strip()  # Expected to be "request_fraud_transaction_pilot"

# Extract rule alerts
def process_framl_response(json_response):
    txn_info = json_response["alert"]["txn"]
    rules = json_response["alert"]["ruleAlert"]
    rows = []

    for rule in rules:
        row = {
            "transaction_id": txn_info.get("transaction_id"),
            "txn_date_time": txn_info.get("txn_date_time"),
            "txn_type": txn_info.get("txn_type"),
            "sender_hashcode": txn_info.get("sender_hashcode"),
            "sender_first_name": txn_info.get("sender_first_name"),
            "sender_last_name": txn_info.get("sender_last_name"),
            "sender_amount": txn_info.get("sender_amount"),
            "sender_msisdn": txn_info.get("sender_msisdn"),
            "sender_incorporation_date": txn_info.get("sender_incorporation_date"),
            "receiver_incorporation_date": txn_info.get("receiver_incorporation_date"),
            "receiver_hashcode": txn_info.get("receiver_hashcode"),
            "receiver_first_name": txn_info.get("receiver_first_name"),
            "receiver_last_name": txn_info.get("receiver_last_name"),
            "receiver_amount": txn_info.get("receiver_amount"),
            "receiver_msisdn": txn_info.get("receiver_msisdn"),
            "ruleId": rule.get("ruleId"),
            "ruleName": rule.get("ruleName"),
            "typologyId": rule.get("typologyId"),
            "typologyName": rule.get("typologyName"),
            "ruleTriggered": rule.get("ruleTriggered"),
            "messageType": rule.get("messageType")
        }

        # Flatten each functionValue
        for k, v in rule.get("functionValue", {}).items():
            if isinstance(v, dict):
                row[f"{k} (type)"] = v.get("type")
                row[f"{k} (value)"] = v.get("field")
            else:
                # fallback if v is not a dict
                row[f"{k} (value)"] = v

        rows.append(row)

    return rows

def process_single_row(row_dict, token):
    pre_fix = "rcbc01"
    #pre_fix = "UNO_June_Run_sample_June11_03"
    try:
        payload = row_dict.copy()
        
        # List of all fields from sample.csv that should be set to "NA" if missing/empty
        # (excluding transaction_id as specified)
        string_fields_to_check = [
            'source_of_funds', 'txn_type_code', 'txn_type', 'sender_currency',
            'sender_country', 'sender_city', 'receiver_type',
            'receiver_currency', 'receiver_country', 'external_id',
            'sender_advance_hashcode', 'txn_status', 'receiver_advance_hashcode', 'sender_first_name',
            'sender_last_name', 'sender_address', 'receiver_first_name', 'receiver_last_name',
            'receiver_address', 'external_code', 'sending_partner_code', 'receiving_partner_code',
            'receiver_msisdn', 'sender_msisdn'
        ]

        numerical_fields_to_check = [
            'sender_amount', 'sender_amount_usd', 'receiver_amount'
        ]
        
        # Handle missing data for all string fields (set to "NA" if empty/missing)
        for field in string_fields_to_check:
            if field not in payload or payload[field] == "" or payload[field] is None or str(payload[field]).strip() == "":
                payload[field] = "NA"

        # Handle missing data for all numerical fields (set to 0 if empty/missing)
        for field in numerical_fields_to_check:
            if field not in payload or payload[field] == "" or payload[field] is None or str(payload[field]).strip() == "":
                payload[field] = 0.0

        # Special handling for transaction_id and external_code (string conversion)
        for field in ["transaction_id", "external_code"]:
            if field in payload and payload[field] != "":
                payload[field] = f'{payload[field]}'

        # Handle transaction_id prefix
        if payload.get("transaction_id") and payload["transaction_id"] != "NA":
            payload["transaction_id"] = pre_fix + "Txn" + str(payload["transaction_id"])

        # Handle sender_hashcode with prefix or set to NA
        if payload.get("sender_hashcode") and payload["sender_hashcode"] != "NA" and payload["sender_hashcode"] != "":
            payload["sender_hashcode"] = payload["sender_hashcode"]
        else:
            payload["sender_hashcode"] = "NA"

        # Handle receiver_hashcode with prefix or set to NA
        if payload.get("receiver_hashcode") and payload["receiver_hashcode"] != "NA" and payload["receiver_hashcode"] != "":
            payload["receiver_hashcode"] = payload["receiver_hashcode"]
        else:
            payload["receiver_hashcode"] = "NA"
        
        # Handle datetime fields - set to "NA" if missing, otherwise parse and format
        incorporation_date = "NA"  # Default fallback
        
        if "txn_date_time" in payload and payload["txn_date_time"] != "NA" and payload["txn_date_time"] != "":
            # Enhanced datetime parsing for transaction datetime
            parsed_dt = None
            date_formats = [
                "%Y-%m-%dT%H:%M:%S.%fZ",  # ISO with milliseconds
                "%Y-%m-%dT%H:%M:%SZ",     # ISO without milliseconds
                "%Y-%m-%dT%H:%M:%S",      # ISO without Z
                "%m/%d/%Y %I:%M %p",      # Original format
                "%Y-%m-%d %H:%M:%S",      # Standard format
            ]
            
            for fmt in date_formats:
                try:
                    parsed_dt = datetime.strptime(payload["txn_date_time"], fmt)
                    break
                except ValueError:
                    continue
            
            if parsed_dt:
                payload["txn_date_time"] = parsed_dt.strftime("%Y-%m-%dT%H:%M:%SZ")
                incorporation_dt = parsed_dt - timedelta(days=7)
                incorporation_date = incorporation_dt.strftime("%Y-%m-%dT%H:%M:%SZ")
            else:
                print(f"Could not parse txn_date_time for transaction {payload.get('transaction_id')}: {payload['txn_date_time']}")
                payload["txn_date_time"] = "NA"
        else:
            payload["txn_date_time"] = "NA"
        
        # Handle sender_incorporation_date
        if "sender_incorporation_date" in payload and payload["sender_incorporation_date"] != "NA" and payload["sender_incorporation_date"] != "":
            parsed_dt = None
            for fmt in date_formats:
                try:
                    parsed_dt = datetime.strptime(payload["sender_incorporation_date"], fmt)
                    break
                except ValueError:
                    continue
            
            if parsed_dt:
                payload["sender_incorporation_date"] = parsed_dt.strftime("%Y-%m-%dT%H:%M:%SZ")
            else:
                print(f"Could not parse sender_incorporation_date for transaction {payload.get('transaction_id')}")
                payload["sender_incorporation_date"] = incorporation_date
        else:
            payload["sender_incorporation_date"] = incorporation_date
            
        # Handle receiver_incorporation_date
        if "receiver_incorporation_date" in payload and payload["receiver_incorporation_date"] != "NA" and payload["receiver_incorporation_date"] != "":
            parsed_dt = None
            for fmt in date_formats:
                try:
                    parsed_dt = datetime.strptime(payload["receiver_incorporation_date"], fmt)
                    break
                except ValueError:
                    continue
            
            if parsed_dt:
                payload["receiver_incorporation_date"] = parsed_dt.strftime("%Y-%m-%dT%H:%M:%SZ")
            else:
                print(f"Could not parse receiver_incorporation_date for transaction {payload.get('transaction_id')}")
                payload["receiver_incorporation_date"] = incorporation_date
        else:
            payload["receiver_incorporation_date"] = incorporation_date

        # Handle intermediary field - set to default structure if missing
        if "intermediary" not in payload or payload["intermediary"] == "NA" or payload["intermediary"] == "":
            payload["intermediary"] = [{"hashcode": ""}]
        elif isinstance(payload.get("intermediary"), str):
            try:
                payload["intermediary"] = ast.literal_eval(payload["intermediary"])
            except Exception as e:
                print(f"Error parsing intermediary for {payload.get('transaction_id')}: {e}")
                payload["intermediary"] = [{"hashcode": ""}]

        if ack_run == 1:
            # Call ACK API with the same payload
            ack_response = send_fraud_ack(payload, token)
            
            # Record timestamp of successful call
            with call_timestamps_lock:
                call_timestamps.append(time.time())
            
            return [{
                "transaction_id": payload.get("transaction_id"),
                "ack_status": ack_response
            }]
        else:
            response_json = send_transaction(payload, token)
            # Record timestamp of successful call
            with call_timestamps_lock:
                call_timestamps.append(time.time())
            return process_framl_response(response_json)
    
    except Exception as e:
        return [{
            "transaction_id": row_dict.get("transaction_id", "UNKNOWN"),
            "error": str(e)
        }]

stop_event = threading.Event()  # Move this to global scope
# ----------- MAIN EXECUTION -----------
def main():
    token = get_token()
    df = read_and_preprocess_csv(INPUT_CSV)

    total_calls = len(df)  # total number of rows/API calls
    
    responses = []
    max_workers = 50
    
    start_time = time.time()
    
    monitor_thread = start_tps_monitoring(stop_event)  # ✅ Start TPS tracking thread
    
    def wrapped_task(row_dict):
        if stop_event.is_set():
            return []
        return process_single_row(row_dict, token)
    try:
        with ThreadPoolExecutor(max_workers=max_workers) as executor:
            futures = {
                executor.submit(wrapped_task, row.to_dict()): idx
                for idx, row in df.iterrows()
            }
    
            for idx, future in enumerate(as_completed(futures)):
                if stop_event.is_set():
                    break

                try:
                    result = future.result()
                    responses.extend(result)
                except Exception as e:
                    responses.append({
                        "transaction_id": "UNKNOWN",
                        "error": f"Unhandled exception: {str(e)}"
                    })
    
                if (idx + 1) % 100 == 0 or (idx + 1) == total_calls:
                    done = idx + 1
                    remaining = total_calls - done
                    elapsed = time.time() - start_time
                    print(f"\U0001F552 API calls done: {done} | Remaining: {remaining} | Time elapsed: {elapsed:.2f} sec")
                    start_time = time.time()

    except KeyboardInterrupt:
        print("\n⛔ Interrupt received. Saving collected results so far...")
        stop_event.set()
    finally:
        output_df = pd.DataFrame(responses)
        output_df.to_csv(OUTPUT_CSV, index=False)
        print(f"\n✅ Done. Responses saved to '{OUTPUT_CSV}'.")
        with call_timestamps_lock:
            print(f"\n📊 Final TPS recorded (last second): {len(call_timestamps)}")
        stop_event.set()
        monitor_thread.join(timeout=2)  # ⏳ waits for TPS monitor to exit cleanly

def start_tps_monitoring(stop_event):
    def monitor():
        while not stop_event.is_set():
            now = time.time()
            one_sec_ago = now - 1
            with call_timestamps_lock:
                # Remove timestamps older than 1 second
                while call_timestamps and call_timestamps[0] < one_sec_ago:
                    call_timestamps.popleft()
                current_tps = len(call_timestamps)

            print(f"📈 Real-time TPS: {current_tps}")
            try:
                with open("tps_log.txt", "a") as log:
                    log.write(f"{datetime.now()} - TPS: {current_tps}\n")
            except Exception as e:
                print(f"⚠️ TPS log write failed: {e}")
            time.sleep(1)  # update every second

    thread = threading.Thread(target=monitor, daemon=True)
    thread.start()
    return thread  # return the thread object

if __name__ == "__main__":
    main()