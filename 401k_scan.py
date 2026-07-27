#!/usr/bin/env python3
"""
401k Scanner – Enterprise Red‑Team Edition
Author: Red Team
Version: 3.0
WARNING: Change BASE_URL below to your authorised sandbox target.
"""
import sys
import os
import csv
import random
import re
import time
import logging
import json
import hashlib
import base64
import shutil
import argparse
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor, as_completed
from collections import deque
from threading import Lock, Event

try:
    import requests
except ImportError:
    print("Missing 'requests'. Run: pip install requests")
    sys.exit(1)
try:
    from bs4 import BeautifulSoup
except ImportError:
    print("Missing 'beautifulsoup4'. Run: pip install beautifulsoup4")
    sys.exit(1)

# Optional cryptography for encryption
try:
    from cryptography.fernet import Fernet
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
    CRYPTO_AVAILABLE = True
except ImportError:
    CRYPTO_AVAILABLE = False
    print("Cryptography not installed; encryption features disabled.", file=sys.stderr)

# ---------- !!! EDIT THIS ONLY !!! ----------
BASE_URL = "https://www.pbgc.gov/workers-retirees/find-unclaimed-retirement-benefits/search-unclaimed"
# -------------------------------------------

# ANSI colours
RESET = "\033[0m"
BOLD = "\033[1m"
RED = "\033[91m"
GREEN = "\033[92m"
YELLOW = "\033[93m"
CYAN = "\033[96m"
GREY = "\033[90m"
CLEAR = "\033[2J\033[H"

def clear_screen():
    print(CLEAR, end='')

def print_banner():
    clear_screen()
    width = 60
    print(f"{CYAN}{'=' * width}{RESET}")
    print(f"{CYAN}  401k SCANNER  v3.0 (Enterprise){RESET}".center(width))
    print(f"{GREY}  Author: Red Team{RESET}".center(width))
    print(f"{GREY}  Target: {BASE_URL}{RESET}".center(width))
    print(f"{CYAN}{'=' * width}{RESET}\n")

def colored_input(prompt):
    return input(f"{CYAN}{prompt}{RESET}").strip()

def print_status(msg, colour=GREEN):
    print(f"{colour}{msg}{RESET}")

# ---------- Configuration Manager ----------
CONFIG_FILE = "config.json"
DEFAULT_CONFIG = {
    "threads": 5,
    "rate_limit": 5.0,          # requests per second (global)
    "delay_min": 0.5,
    "delay_max": 1.5,
    "timeout": 15,
    "retries": 3,
    "success_indicators": ["benefit", "pension", "unclaimed", "retirement"],
    "output_base": "results",
    "proxy": None,              # e.g., "http://user:pass@proxy:8080" or "socks5://..."
    "user_agents": [
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
        "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"
    ],
    "custom_headers": {
        "Accept-Language": "en-US,en;q=0.9",
        "Accept-Encoding": "gzip, deflate, br",
        "DNT": "1"
    },
    "captcha_service": None,    # e.g., "2captcha" or "anti-captcha"
    "captcha_api_key": "",
    "encryption_password": "",  # will be prompted if not set
    "secure_delete": False,
    "checkpoint_file": "checkpoint.txt",
    "dead_letter_file": "dead_letter.txt",
    "audit_log_file": "audit.log"
}

class ConfigManager:
    @staticmethod
    def load():
        if os.path.exists(CONFIG_FILE):
            try:
                with open(CONFIG_FILE, 'r') as f:
                    data = json.load(f)
                    for k, v in DEFAULT_CONFIG.items():
                        data.setdefault(k, v)
                    return data
            except Exception as e:
                print_status(f"Error loading config: {e}. Using defaults.", YELLOW)
        return DEFAULT_CONFIG.copy()

    @staticmethod
    def save(config):
        try:
            with open(CONFIG_FILE, 'w') as f:
                json.dump(config, f, indent=2)
            return True
        except Exception as e:
            print_status(f"Error saving config: {e}", RED)
            return False

    @staticmethod
    def configure():
        print_status("\n--- Current Configuration ---", CYAN)
        config = ConfigManager.load()
        # Show current values
        for key, val in config.items():
            if key in ("user_agents", "custom_headers", "success_indicators", "captcha_api_key", "encryption_password"):
                print(f"  {key}: <hidden or list>")
            else:
                print(f"  {key}: {val}")

        print_status("\nEnter new values (press Enter to keep current):", CYAN)
        new_config = {}
        for key, val in config.items():
            if key == "user_agents":
                print(f"Current user agents: {len(val)} agents.")
                inp = colored_input("Enter new user agents (comma-separated, or leave blank): ")
                if inp:
                    new_config[key] = [ua.strip() for ua in inp.split(',') if ua.strip()]
                else:
                    new_config[key] = val
            elif key == "custom_headers":
                print(f"Current custom headers: {val}")
                inp = colored_input("Enter custom headers as JSON (e.g., '{\"X-Forwarded-For\":\"1.2.3.4\"}') or blank: ")
                if inp:
                    try:
                        new_config[key] = json.loads(inp)
                    except:
                        print_status("Invalid JSON, keeping current.", RED)
                        new_config[key] = val
                else:
                    new_config[key] = val
            elif key == "success_indicators":
                prompt = f"Success keywords (comma-separated, current: {', '.join(val)}): "
                inp = colored_input(prompt)
                if inp:
                    new_config[key] = [kw.strip() for kw in inp.split(',') if kw.strip()]
                else:
                    new_config[key] = val
            elif key in ("encryption_password", "captcha_api_key"):
                # Sensitive, we don't show current
                inp = colored_input(f"{key} (leave blank to keep current): ")
                if inp:
                    new_config[key] = inp
                else:
                    new_config[key] = val
            else:
                prompt = f"{key} (current: {val}): "
                inp = colored_input(prompt)
                if inp:
                    if isinstance(val, bool):
                        new_config[key] = inp.lower() in ('true', 'yes', '1')
                    elif isinstance(val, int):
                        new_config[key] = int(inp)
                    elif isinstance(val, float):
                        new_config[key] = float(inp)
                    else:
                        new_config[key] = inp
                else:
                    new_config[key] = val
        if ConfigManager.save(new_config):
            print_status("Configuration saved.", GREEN)
        return new_config

# ---------- Rate Limiter (Token Bucket) ----------
class TokenBucket:
    def __init__(self, rate_per_sec):
        self.rate = rate_per_sec
        self.tokens = 1.0
        self.last_time = time.time()
        self.lock = Lock()

    def wait(self):
        with self.lock:
            now = time.time()
            elapsed = now - self.last_time
            self.tokens += elapsed * self.rate
            if self.tokens > 1.0:
                self.tokens = 1.0
            self.last_time = now
            if self.tokens < 0:
                self.tokens = 0
            if self.tokens < 1.0:
                sleep_time = (1.0 - self.tokens) / self.rate
                time.sleep(sleep_time)
                self.tokens = 1.0
                self.last_time = time.time()
            else:
                self.tokens -= 1.0

# ---------- Encryption ----------
def get_fernet_key(password, salt=None):
    if not CRYPTO_AVAILABLE:
        return None
    if salt is None:
        salt = b'salt_' + hashlib.sha256(os.urandom(16)).digest()[:16]
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100000,
    )
    key = base64.urlsafe_b64encode(kdf.derive(password.encode()))
    return key, salt

def encrypt_file(filepath, password):
    if not CRYPTO_AVAILABLE:
        return False
    try:
        with open(filepath, 'rb') as f:
            data = f.read()
        key, salt = get_fernet_key(password)
        fernet = Fernet(key)
        encrypted = fernet.encrypt(data)
        # Save salt and encrypted data
        with open(filepath + '.enc', 'wb') as f:
            f.write(salt + encrypted)
        os.remove(filepath)
        return True
    except Exception as e:
        logging.error(f"Encryption failed: {e}")
        return False

def decrypt_file(filepath, password):
    if not CRYPTO_AVAILABLE:
        return False
    try:
        with open(filepath, 'rb') as f:
            raw = f.read()
        salt = raw[:16]
        encrypted = raw[16:]
        key, _ = get_fernet_key(password, salt)
        fernet = Fernet(key)
        decrypted = fernet.decrypt(encrypted)
        orig = filepath.replace('.enc', '')
        with open(orig, 'wb') as f:
            f.write(decrypted)
        os.remove(filepath)
        return True
    except Exception as e:
        logging.error(f"Decryption failed: {e}")
        return False

# ---------- Secure Delete ----------
def secure_delete(filepath):
    if not os.path.exists(filepath):
        return
    try:
        with open(filepath, 'rb+') as f:
            length = f.seek(0, 2)
            f.seek(0)
            f.write(os.urandom(length))
            f.flush()
            os.fsync(f.fileno())
        os.remove(filepath)
    except Exception as e:
        logging.warning(f"Secure delete failed for {filepath}: {e}")

# ---------- Audit Logger ----------
class AuditLogger:
    def __init__(self, logfile):
        self.logfile = logfile
        self.lock = Lock()
        # ensure directory exists
        os.makedirs(os.path.dirname(logfile) or '.', exist_ok=True)

    def log(self, event_type, message, **kwargs):
        entry = {
            "timestamp": datetime.utcnow().isoformat() + 'Z',
            "event": event_type,
            "message": message,
            "details": kwargs
        }
        with self.lock:
            with open(self.logfile, 'a') as f:
                f.write(json.dumps(entry) + '\n')

# ---------- Core Agent (per worker) ----------
class PBGCAgent:
    def __init__(self, base_url, config, rate_limiter, audit_logger):
        self.base_url = base_url.rstrip('/')
        self.config = config
        self.rate_limiter = rate_limiter
        self.audit = audit_logger
        self.timeout = config['timeout']
        self.max_retries = config['retries']
        self.delay_min = config['delay_min']
        self.delay_max = config['delay_max']
        self.success_indicators = config['success_indicators']
        self.session = requests.Session()
        # Proxy
        if config.get('proxy'):
            self.session.proxies = {'http': config['proxy'], 'https': config['proxy']}
        # User-Agent rotation
        ua_list = config.get('user_agents', DEFAULT_CONFIG['user_agents'])
        self.session.headers['User-Agent'] = random.choice(ua_list)
        # Custom headers
        for k, v in config.get('custom_headers', {}).items():
            self.session.headers[k] = v
        self._cached_tokens = None
        self._cached_search_html = None
        self._token_lock = Lock()

    def _delay(self):
        time.sleep(random.uniform(self.delay_min, self.delay_max))

    def _fetch_search_page(self):
        # Use cached if available
        if self._cached_search_html is not None:
            return self._cached_search_html
        # Rate limit
        self.rate_limiter.wait()
        try:
            resp = self.session.get(self.base_url, timeout=self.timeout)
            resp.raise_for_status()
            self._cached_search_html = resp.text
            with self._token_lock:
                self._cached_tokens = self._extract_tokens(resp.text)
            self._delay()
            return self._cached_search_html
        except requests.exceptions.RequestException as e:
            logging.error(f"Failed to fetch search page: {e}")
            self.audit.log("FETCH_ERROR", f"Failed to fetch page: {e}", url=self.base_url)
            return None

    def _extract_tokens(self, html):
        soup = BeautifulSoup(html, 'html.parser')
        tokens = {}
        for form in soup.find_all('form'):
            for inp in form.find_all('input'):
                name = inp.get('name')
                value = inp.get('value', '')
                if name in ('form_build_id', 'form_id', 'op', 'form_token'):
                    tokens[name] = value
                if inp.get('type') == 'hidden' and name:
                    tokens[name] = value
        if 'op' not in tokens:
            tokens['op'] = 'Search'
        return tokens

    def _submit_search(self, last_name, ssn, tokens):
        data = {
            'last_name': last_name,
            'ssn': ssn,
        }
        data.update(tokens)
        # Rate limit
        self.rate_limiter.wait()
        try:
            resp = self.session.post(self.base_url, data=data, timeout=self.timeout)
            # Adaptive backoff on 429/503
            if resp.status_code in (429, 503):
                self.audit.log("RATE_LIMIT", f"Received {resp.status_code}, backing off", status=resp.status_code)
                time.sleep(2 ** (self.max_retries - 1))
                resp.raise_for_status()
            resp.raise_for_status()
            self._delay()
            return resp.text
        except requests.exceptions.RequestException as e:
            logging.warning(f"Submission error: {e}")
            self.audit.log("SUBMIT_ERROR", f"Submission failed: {e}", last_name=last_name)
            return None

    def _parse_result(self, html):
        if not html:
            return False, "Unknown", "Unknown"

        soup = BeautifulSoup(html, 'html.parser')
        text = soup.get_text(separator=' ')

        lower = text.lower()
        benefit = any(ind in lower for ind in self.success_indicators)

        # Institution - improved with CSS/XPath fallbacks
        inst = "Unknown"
        # Try XPath-like: find element containing "Plan" or "Institution" text, then grab following text
        # Use BeautifulSoup to find any tag with text containing these keywords
        for tag in soup.find_all(['p', 'div', 'span', 'td', 'th']):
            txt = tag.get_text(strip=True)
            if re.search(r'(plan|institution|provider|company)\s*:', txt, re.I):
                # Extract after colon
                match = re.search(r'(?:plan|institution|provider|company)\s*:\s*(.+)', txt, re.I)
                if match:
                    inst = match.group(1).strip()
                    break
        if inst == "Unknown":
            # Fallback: find any bold/strong with keyword
            for tag in soup.find_all(['strong', 'b', 'h2', 'h3']):
                txt = tag.get_text(strip=True)
                if re.search(r'(plan|institution|provider|company)', txt, re.I):
                    parent = tag.find_parent()
                    if parent:
                        sibling = parent.find_next_sibling()
                        if sibling:
                            inst = sibling.get_text(strip=True).split('.')[0]
                        else:
                            inst = parent.get_text(separator=' ').replace(txt, '').strip()
                        if inst:
                            break

        # Status - similar approach
        status = "Unknown"
        for tag in soup.find_all(['p', 'div', 'span', 'td', 'th']):
            txt = tag.get_text(strip=True)
            if re.search(r'status\s*:', txt, re.I):
                match = re.search(r'status\s*:\s*([A-Za-z]+)', txt, re.I)
                if match:
                    status = match.group(1).strip().capitalize()
                    break
        if status == "Unknown":
            for word in ['Active', 'Terminated', 'Inactive', 'Pending']:
                if re.search(rf'\b{word}\b', text, re.I):
                    status = word
                    break

        if re.search(r'no (results?|records?|benefits?|pensions?)', lower):
            benefit = False

        return benefit, inst, status

    def process(self, person):
        name_parts = person['full_name'].strip().split()
        last_name = name_parts[-1] if name_parts else 'Unknown'
        ssn = person.get('ssn', '')
        person_id = f"{last_name}_{ssn}"  # unique ID for checkpoint

        # Check checkpoint: skip if already processed
        if person_id in checkpoint_set:
            return {**person, 'benefit_found': 'SKIPPED', 'institution': 'N/A',
                    'account_status': 'N/A', 'status': 'Checkpoint'}

        self.audit.log("PROCESS_START", f"Processing {person['full_name']}", person_id=person_id)

        html = self._fetch_search_page()
        if not html:
            self.audit.log("PROCESS_ERROR", "Fetch page failed", person_id=person_id)
            return {**person, 'benefit_found': 'ERROR', 'institution': 'N/A',
                    'account_status': 'N/A', 'status': 'Fetch failed'}

        tokens = self._cached_tokens.copy()
        result_html = None
        for attempt in range(self.max_retries):
            result_html = self._submit_search(last_name, ssn, tokens)
            if result_html:
                lower_resp = result_html.lower()
                if 'please enter a valid' in lower_resp or 'invalid' in lower_resp:
                    # Refresh tokens
                    self._cached_search_html = None
                    self._cached_tokens = None
                    fresh = self._fetch_search_page()
                    if fresh:
                        tokens = self._cached_tokens.copy()
                    continue
                break
            time.sleep(1 * (attempt + 1))

        if not result_html:
            self.audit.log("PROCESS_ERROR", "No response after retries", person_id=person_id)
            return {**person, 'benefit_found': 'ERROR', 'institution': 'N/A',
                    'account_status': 'N/A', 'status': 'No response'}

        benefit, inst, acc_status = self._parse_result(result_html)
        result = {
            **person,
            'benefit_found': 'TRUE' if benefit else 'FALSE',
            'institution': inst,
            'account_status': acc_status,
            'status': 'Success'
        }
        self.audit.log("PROCESS_DONE", f"Completed {person['full_name']}", result=result)
        return result

# ---------- Checkpoint & Dead-letter ----------
checkpoint_set = set()
def load_checkpoint(checkpoint_file):
    global checkpoint_set
    if os.path.exists(checkpoint_file):
        with open(checkpoint_file, 'r') as f:
            checkpoint_set = set(line.strip() for line in f if line.strip())
    else:
        checkpoint_set = set()

def save_checkpoint(checkpoint_file, person_id):
    with open(checkpoint_file, 'a') as f:
        f.write(person_id + '\n')
    checkpoint_set.add(person_id)

def log_dead_letter(dead_letter_file, person, reason):
    with open(dead_letter_file, 'a') as f:
        f.write(f"{person.get('full_name')},{person.get('ssn')},{reason}\n")

# ---------- Input Parsing ----------
def parse_txt_line(line, delimiter, field_order):
    parts = [p.strip() for p in line.split(delimiter)]
    if len(parts) < 2:
        return None
    mapping = {}
    order = [f.strip() for f in field_order.split(',') if f.strip()]
    for idx, field in enumerate(order):
        if idx < len(parts):
            mapping[field] = parts[idx]
    if 'name' not in mapping or 'ssn' not in mapping:
        return None
    return {
        'full_name': mapping.get('name', ''),
        'ssn': mapping.get('ssn', ''),
        'dob': mapping.get('dob', ''),
        'address': mapping.get('address', '')
    }

def load_people(filepath, delimiter, field_order, password=None):
    people = []
    # Decrypt if needed
    if password and filepath.endswith('.enc'):
        if not decrypt_file(filepath, password):
            print_status("Decryption failed.", RED)
            return None
        filepath = filepath.replace('.enc', '')
    try:
        with open(filepath, 'r', encoding='utf-8') as f:
            for line_no, line in enumerate(f, 1):
                line = line.strip()
                if not line:
                    continue
                person = parse_txt_line(line, delimiter, field_order)
                if person:
                    people.append(person)
                else:
                    logging.warning(f"Line {line_no}: invalid format, skipped: {line}")
        return people
    except Exception as e:
        print_status(f"Load error: {e}", RED)
        return None

# ---------- Output Writing ----------
def write_results(output_file, results, append=False, encrypt=False, password=None):
    fieldnames = ['full_name', 'ssn', 'dob', 'address', 'benefit_found', 'institution', 'account_status', 'status']
    mode = 'a' if append else 'w'
    try:
        with open(output_file, mode, encoding='utf-8') as f:
            if not append or os.path.getsize(output_file) == 0:
                f.write('\t'.join(fieldnames) + '\n')
            for r in results:
                row = [str(r.get(k, '')) for k in fieldnames]
                f.write('\t'.join(row) + '\n')
        if encrypt and password:
            encrypt_file(output_file, password)
        return True
    except Exception as e:
        logging.error(f"Write error: {e}")
        return False

# ---------- Headless / Interactive ----------
def run_scan(config, input_file=None, output_prefix=None, delimiter=None, field_order=None, headless=False):
    # Load checkpoint
    load_checkpoint(config['checkpoint_file'])
    audit = AuditLogger(config['audit_log_file'])
    rate_limiter = TokenBucket(config['rate_limit'])

    if headless:
        # Parse input
        if not input_file or not delimiter or not field_order:
            print_status("Headless mode requires -i, --delimiter, --field-order", RED)
            return
        people = load_people(input_file, delimiter, field_order, config.get('encryption_password'))
        if not people:
            print_status("No valid records.", RED)
            return
        output_base = output_prefix or config['output_base']
    else:
        # Interactive: get input details
        print_status("\n--- Scan Mode ---", CYAN)
        mode = colored_input("Choose mode: [1] Single scan  [2] Batch scan from TXT: ")
        if mode == '1':
            name = colored_input("Full Name: ")
            ssn = colored_input("SSN: ")
            if not name or not ssn:
                print_status("Aborted.", RED)
                return
            people = [{'full_name': name, 'ssn': ssn, 'dob': '', 'address': ''}]
            output_base = config['output_base']
        elif mode == '2':
            filepath = colored_input("Path to TXT file (or .enc if encrypted): ")
            if not filepath:
                print_status("Aborted.", RED)
                return
            if filepath.endswith('.enc') and config.get('encryption_password'):
                passwd = config['encryption_password']
            else:
                passwd = None
            delimiter_choice = colored_input("Delimiter (comma, tab, space, or custom): ").lower()
            if delimiter_choice == 'comma':
                delimiter = ','
            elif delimiter_choice == 'tab':
                delimiter = '\t'
            elif delimiter_choice == 'space':
                delimiter = ' '
            else:
                delimiter = delimiter_choice
            field_order = colored_input("Field order (e.g., name,ssn or ssn,name,dob,address): ")
            if not field_order:
                print_status("Field order required.", RED)
                return
            if 'name' not in field_order or 'ssn' not in field_order:
                print_status("Must include 'name' and 'ssn'.", RED)
                return
            people = load_people(filepath, delimiter, field_order, passwd)
            if not people:
                print_status("No valid records.", RED)
                return
            output_base = config['output_base']
        else:
            print_status("Invalid choice.", RED)
            return

    # Prepare output
    timestamp = datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
    output_file = f"{output_base}_{timestamp}.txt"
    if config.get('encryption_password'):
        encrypt_out = True
        password = config['encryption_password']
    else:
        encrypt_out = False
        password = None

    # Clear output file
    write_results(output_file, [], append=False, encrypt=False)  # we encrypt later

    total = len(people)
    completed = 0
    results = []

    max_workers = 1 if total == 1 else config['threads']

    # Prepare dead-letter
    dead_file = config['dead_letter_file']

    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        future_to_person = {}
        for p in people:
            # Skip checkpointed
            person_id = f"{p['full_name'].split()[-1]}_{p['ssn']}"
            if person_id in checkpoint_set:
                completed += 1
                continue
            future = executor.submit(PBGCAgent(BASE_URL, config, rate_limiter, audit).process, p)
            future_to_person[future] = (p, person_id)

        for future in as_completed(future_to_person):
            person, person_id = future_to_person[future]
            try:
                result = future.result()
                # Check if error
                if result['benefit_found'] in ('ERROR', 'SKIPPED'):
                    # Log to dead letter
                    log_dead_letter(dead_file, result, result.get('status', 'Unknown'))
                else:
                    results.append(result)
                    # Save checkpoint
                    save_checkpoint(config['checkpoint_file'], person_id)
                completed += 1

                # Real-time output
                if result['benefit_found'] == 'TRUE':
                    colour = GREEN
                    status_text = "FOUND"
                elif result['benefit_found'] == 'FALSE':
                    colour = YELLOW
                    status_text = "NOT FOUND"
                elif result['benefit_found'] == 'SKIPPED':
                    colour = GREY
                    status_text = "SKIPPED"
                else:
                    colour = RED
                    status_text = "ERROR"
                print(f"[{completed}/{total}] {result['full_name']:<20} "
                      f"Benefit: {result['benefit_found']:<5} "
                      f"Inst: {result['institution']:<15} "
                      f"Status: {result['account_status']:<10} "
                      f"({result['status']})", colour)

                # Write in batches of 5
                if len(results) % 5 == 0:
                    write_results(output_file, results[-5:], append=True, encrypt=False)

            except Exception as e:
                logging.error(f"Failed to process {person.get('full_name')}: {e}")
                audit.log("PROCESS_EXCEPTION", str(e), person=person)
                log_dead_letter(dead_file, person, f"Exception: {e}")
                completed += 1

    # Write remaining
    if results:
        write_results(output_file, results, append=True, encrypt=False)

    # Encrypt final output if needed
    if encrypt_out and password:
        encrypt_file(output_file, password)

    # Secure delete input if encrypted and secure_delete enabled
    if config.get('secure_delete') and input_file and input_file.endswith('.enc'):
        secure_delete(input_file)

    print_status(f"\n[+] All done. Results saved to {output_file}", GREEN)
    if config.get('secure_delete'):
        print_status("Secure deletion enabled; sensitive files overwritten.", YELLOW)

    if not headless:
        input(f"{CYAN}Press Enter to return to menu...{RESET}")

# ---------- Main Menu ----------
def main():
    parser = argparse.ArgumentParser(description="401k Scanner Enterprise Edition")
    parser.add_argument("-i", "--input", help="Input TXT file (can be .enc encrypted)")
    parser.add_argument("-o", "--output-prefix", help="Output file prefix (timestamp appended)")
    parser.add_argument("-d", "--delimiter", help="Delimiter for input (comma, tab, space, or custom char)")
    parser.add_argument("-f", "--field-order", help="Field order (e.g., name,ssn,dob,address)")
    parser.add_argument("--headless", action="store_true", help="Run without interactive menu")
    parser.add_argument("--config", help="Path to config JSON (default config.json)")
    args = parser.parse_args()

    config = ConfigManager.load()
    if args.config:
        try:
            with open(args.config, 'r') as f:
                user_config = json.load(f)
                config.update(user_config)
        except Exception as e:
            print_status(f"Failed to load custom config: {e}", RED)

    # If encryption password not set, prompt if not headless
    if not config.get('encryption_password') and not args.headless:
        pwd = colored_input("Encryption password (optional, press Enter to skip): ")
        if pwd:
            config['encryption_password'] = pwd
            ConfigManager.save(config)

    if args.headless:
        # Must provide input, delimiter, field-order
        if not args.input or not args.delimiter or not args.field_order:
            print_status("Headless mode requires -i, -d, -f", RED)
            sys.exit(1)
        run_scan(config, input_file=args.input, output_prefix=args.output_prefix,
                 delimiter=args.delimiter, field_order=args.field_order, headless=True)
        return

    while True:
        clear_screen()
        print_banner()
        print_status("Main Menu", BOLD)
        print("  [1] Scan (use current configuration)")
        print("  [2] View / Edit Configuration")
        print("  [3] Exit")
        choice = colored_input("Select option: ")

        if choice == '1':
            run_scan(config)
        elif choice == '2':
            config = ConfigManager.configure()
            input(f"{CYAN}Press Enter to continue...{RESET}")
        elif choice == '3':
            # Secure delete if configured
            if config.get('secure_delete'):
                # Delete sensitive config if password present
                if config.get('encryption_password'):
                    # Overwrite the password in memory
                    config['encryption_password'] = ''
                    ConfigManager.save(config)
                    # Also delete any leftover .enc files? Not safe.
                    pass
            print_status("Goodbye.", GREEN)
            break
        else:
            print_status("Invalid choice. Try again.", RED)
            time.sleep(1)

if __name__ == '__main__':
    try:
        logging.basicConfig(level=logging.WARNING, format='%(asctime)s - %(levelname)s - %(message)s')
        main()
    except KeyboardInterrupt:
        print("\nInterrupted.")
        sys.exit(0)