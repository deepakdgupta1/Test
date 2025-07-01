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
INPUT_CSV = "Uno_11062025_sample.csv"
OUTPUT_CSV = "output_responses.csv"
ack_run = 0

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
    pre_fix = "UNO_Final_Run_1107_01"
    #pre_fix = "UNO_June_Run_sample_June11_03"
    try:
        payload = row_dict.copy()

        for field in ["transaction_id", "external_code"]:
            if field in payload and payload[field] != "":
                payload[field] = f'{payload[field]}'

        if payload.get("transaction_id"):
            payload["transaction_id"] = pre_fix + "Txn" + payload["transaction_id"]

        if not payload.get("sender_hashcode"):
            #payload["sender_hashcode"] = pre_fix + "C" + uuid.uuid4().hex[:12]
            payload["sender_hashcode"] = "NA"
        else:
            payload["sender_hashcode"] = pre_fix + "C" + payload["sender_hashcode"]

        if not payload.get("receiver_hashcode"):
            #payload["receiver_hashcode"] = pre_fix + "C" + uuid.uuid4().hex[:12]
            payload["receiver_hashcode"] = "NA"
        else:
            payload["receiver_hashcode"] = pre_fix + "C" + payload["receiver_hashcode"]
            
        if not payload.get("sender_address"):
            payload["sender_address"] = "NA"

        if not payload.get("receiver_address"):
            payload["receiver_address"] = "NA"
            
        if not payload.get("sender_msisdn"):
            payload["sender_msisdn"] = "NA"

        if not payload.get("receiver_msisdn"):
            payload["receiver_msisdn"] = "NA"
        
        #payload.pop('receiver_incorporation_date', None)
        #payload.pop('sender_incorporation_date', None)
        
        # Step 2: Rename the .1 keys to the original names
        #payload['receiver_incorporation_date'] = payload.pop('receiver_incorporation_date.1')
        #payload['sender_incorporation_date'] = payload.pop('sender_incorporation_date.1')
        
        incorporation_date = ""
        if "txn_date_time" in payload and payload["txn_date_time"] != "":
            try:
                dt = datetime.strptime(payload["txn_date_time"], "%m/%d/%Y %I:%M %p")
                payload["txn_date_time"] = dt.strftime("%Y-%m-%dT%H:%M:%SZ")
                incorporation_dt = dt - timedelta(days=7)
                incorporation_date = incorporation_dt.strftime("%Y-%m-%dT%H:%M:%SZ")
            except ValueError as e:
                print(f"Invalid date in row {payload.get('transaction_id')}: {e}")
                payload["txn_date_time"] = ""
        
        if "sender_incorporation_date" in payload and payload["sender_incorporation_date"] != "":
            try:
                dt = datetime.strptime(payload["sender_incorporation_date"], "%m/%d/%Y %I:%M %p")
                payload["sender_incorporation_date"] = dt.strftime("%Y-%m-%dT%H:%M:%SZ")
            except ValueError as e:
                print(f"Invalid date in row {payload.get('transaction_id')}: {e}")
                payload["sender_incorporation_date"] = incorporation_date
        else:
            payload["sender_incorporation_date"] = incorporation_date
            
        if "receiver_incorporation_date" in payload and payload["receiver_incorporation_date"] != "":
            try:
                dt = datetime.strptime(payload["receiver_incorporation_date"], "%m/%d/%Y %I:%M %p")
                payload["receiver_incorporation_date"] = dt.strftime("%Y-%m-%dT%H:%M:%SZ")
            except ValueError as e:
                print(f"Invalid date in row {payload.get('transaction_id')}: {e}")
                payload["receiver_incorporation_date"] = incorporation_date
        else:
            payload["receiver_incorporation_date"] = incorporation_date

        payload["intermediary"] = [{"hashcode": ""}]
        if isinstance(payload.get("intermediary"), str):
            try:
                payload["intermediary"] = ast.literal_eval(payload["intermediary"])
            except Exception as e:
                print(f"Error parsing intermediary for {payload.get('transaction_id')}: {e}")
                payload["intermediary"] = []

        for key in payload:
            value = payload[key]
            if isinstance(value, str) and value.endswith('***'):
                payload[key] = value.removesuffix('***')  # Use .rstrip if < Python 3.9

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
    df = pd.read_csv(INPUT_CSV)

    # Replace NaN with empty strings
    df = df.fillna("")
    
    # Step 1: Convert to datetime just for sorting
    df["txn_date_time_sortable"] = pd.to_datetime(df["txn_date_time"], format="%m/%d/%Y %I:%M %p", errors="coerce")
    
    # Step 2: Sort by the temporary sortable datetime
    df = df.sort_values(by="txn_date_time_sortable").reset_index(drop=True)
    
    # Step 3: Drop the helper column after sorting
    df = df.drop(columns=["txn_date_time_sortable"])

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