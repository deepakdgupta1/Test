#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Created on Fri May  2 14:21:01 2025

@author: yogeshkumarjain
"""

# ----------------------
# Import necessary modules
# ----------------------
import requests  # For HTTP API requests
import pandas as pd  # For reading and manipulating CSV data
import ast  # For safely evaluating string representations of Python literals
import time  # For timestamps and delays
from datetime import datetime, timedelta  # For handling and formatting dates
import threading  # For running concurrent monitoring threads
from concurrent.futures import ThreadPoolExecutor, as_completed  # For parallel execution
from collections import deque  # For a fast queue to store timestamps of API calls

# ----------------------
# Global variables and thread-safe deque for storing timestamps of API calls
# ----------------------
call_timestamps = deque()
call_timestamps_lock = threading.Lock()

# ----------------------
# Configuration constants
# ----------------------
BASE_URL = "https://caas-pilot-tdss.tookitaki.ai"
AUTH_ENDPOINT = "/api/v1/users/auth"
TXN_ENDPOINT = "/api/v1/realtime/5/fraud-alert"
FRAUD_ACK_ENDPOINT = "/api/v1/realtime/5/fraud-ack"

TENANT_ID = "5"
INPUT_CSV = "sample.csv"
OUTPUT_CSV = "output_responses.csv"
ack_run = 0  # toggle to switch between ACK or standard fraud alert

# ----------------------
# Function to get an authentication token from the server
# ----------------------
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
    response.raise_for_status()  # Raises an error if HTTP request failed
    token = response.json().get("token")
    return token

# ----------------------
# Function to send a transaction payload to the fraud alert API
# ----------------------
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
    response = requests.post(url, headers=headers, json=formatted_payload)
    response.raise_for_status()
    return response.json()  # Return the parsed JSON response

# ----------------------
# Function to send an ACK to the fraud acknowledge endpoint
# ----------------------
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
    return response.text.strip()  # The expected response is a simple string

# ----------------------
# Function to extract and flatten rule alerts from the JSON API response
# ----------------------
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

        # If the rule has functionValue fields, flatten them into separate columns
        for k, v in rule.get("functionValue", {}).items():
            if isinstance(v, dict):
                row[f"{k} (type)"] = v.get("type")
                row[f"{k} (value)"] = v.get("field")
            else:
                row[f"{k} (value)"] = v

        rows.append(row)

    return rows

# ----------------------
# Main function to drive the entire CSV reading, API calling, and output writing
# ----------------------
def main():
    token = get_token()  # Get the API authentication token
    df = pd.read_csv(INPUT_CSV).fillna("")  # Read CSV and replace NaN with empty strings

    # Sort transactions by parsed datetime to ensure correct order
    df["txn_date_time_sortable"] = pd.to_datetime(df["txn_date_time"], format="%m/%d/%Y %I:%M %p", errors="coerce")
    df = df.sort_values(by="txn_date_time_sortable").drop(columns=["txn_date_time_sortable"]).reset_index(drop=True)

    responses = []
    total_calls = len(df)
    max_workers = 50  # Thread pool size

    start_time = time.time()
    monitor_thread = start_tps_monitoring(stop_event)  # Start real-time TPS monitor

    def wrapped_task(row_dict):
        if stop_event.is_set():
            return []
        return process_single_row(row_dict, token)

    # Use ThreadPoolExecutor for parallel API calls
    try:
        with ThreadPoolExecutor(max_workers=max_workers) as executor:
            futures = {executor.submit(wrapped_task, row.to_dict()): idx for idx, row in df.iterrows()}

            for idx, future in enumerate(as_completed(futures)):
                if stop_event.is_set():
                    break

                try:
                    result = future.result()
                    responses.extend(result)
                except Exception as e:
                    responses.append({"transaction_id": "UNKNOWN", "error": f"Unhandled exception: {str(e)}"})

                # Progress feedback every 100 calls
                if (idx + 1) % 100 == 0 or (idx + 1) == total_calls:
                    elapsed = time.time() - start_time
                    print(f"\U0001F552 API calls done: {idx+1} | Remaining: {total_calls - (idx+1)} | Time elapsed: {elapsed:.2f} sec")
                    start_time = time.time()

    except KeyboardInterrupt:
        print("\n⛔ Interrupt received. Saving collected results so far...")
        stop_event.set()
    finally:
        pd.DataFrame(responses).to_csv(OUTPUT_CSV, index=False)
        print(f"\n✅ Done. Responses saved to '{OUTPUT_CSV}'.")
        with call_timestamps_lock:
            print(f"\n📊 Final TPS recorded (last second): {len(call_timestamps)}")
        stop_event.set()
        monitor_thread.join(timeout=2)  # Ensure monitoring thread exits

# ----------------------
# Helper function to monitor TPS (transactions per second) in real-time
# ----------------------
def start_tps_monitoring(stop_event):
    def monitor():
        while not stop_event.is_set():
            now = time.time()
            with call_timestamps_lock:
                while call_timestamps and call_timestamps[0] < now - 1:
                    call_timestamps.popleft()
                current_tps = len(call_timestamps)

            print(f"📈 Real-time TPS: {current_tps}")
            with open("tps_log.txt", "a") as log:
                log.write(f"{datetime.now()} - TPS: {current_tps}\n")

            time.sleep(1)  # Update every second

    thread = threading.Thread(target=monitor, daemon=True)
    thread.start()
    return thread

# ----------------------
# Global stop event for gracefully stopping threads
# ----------------------
stop_event = threading.Event()

# ----------------------
# Start the main program
# ----------------------
if __name__ == "__main__":
    main()
