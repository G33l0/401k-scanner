#!/usr/bin/env python3
"""
401k Scanner – Red‑Team Hardened
Author: Red Team
Version: 2.2
WARNING: Change BASE_URL below to your authorised sandbox target.
"""
import sys
import csv
import random
import re
import time
import logging
import os
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor, as_completed

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
CLEAR = "\033[2J\033[H"   # clear screen and move to top

def clear_screen():
    print(CLEAR, end='')

def print_banner():
    clear_screen()
    width = 60
    print(f"{CYAN}{'=' * width}{RESET}")
    print(f"{CYAN}  401k SCANNER  v2.2{RESET}".center(width))
    print(f"{GREY}  Author: Red Team{RESET}".center(width))
    print(f"{GREY}  Target: {BASE_URL}{RESET}".center(width))
    print(f"{CYAN}{'=' * width}{RESET}\n")

def colored_input(prompt):
    return input(f"{CYAN}{prompt}{RESET}").strip()

def print_status(msg, colour=GREEN):
    print(f"{colour}{msg}{RESET}")

# ---------- Configuration UI ----------
def configure():
    print_status("\n--- Configuration (press Enter to accept default) ---", CYAN)
    config = {}

    config['threads'] = int(colored_input(f"Max threads (default 5): ") or "5")
    config['delay_min'] = float(colored_input(f"Min delay (seconds, default 1.0): ") or "1.0")
    config['delay_max'] = float(colored_input(f"Max delay (seconds, default 3.0): ") or "3.0")
    config['timeout'] = int(colored_input(f"Request timeout (seconds, default 15): ") or "15")
    config['retries'] = int(colored_input(f"Max retries per submission (default 3): ") or "3")
    indicators = colored_input("Success keywords (comma-separated, default: benefit,pension,unclaimed,retirement): ") or "benefit,pension,unclaimed,retirement"
    config['success_indicators'] = [kw.strip() for kw in indicators.split(',') if kw.strip()]
    # Output file: base name, we'll add timestamp
    base_out = colored_input("Output file base name (without .txt, default: results): ") or "results"
    timestamp = datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
    config['output_file'] = f"{base_out}_{timestamp}.txt"

    print_status("\nConfiguration saved.", GREEN)
    return config

# ---------- Core Agent (per worker) ----------
class PBGCAgent:
    def __init__(self, base_url, config):
        self.base_url = base_url.rstrip('/')
        self.timeout = config['timeout']
        self.max_retries = config['retries']
        self.delay_min = config['delay_min']
        self.delay_max = config['delay_max']
        self.success_indicators = config['success_indicators']
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36',
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8'
        })
        self._cached_tokens = None
        self._cached_search_html = None

    def _delay(self):
        time.sleep(random.uniform(self.delay_min, self.delay_max))

    def _fetch_search_page(self):
        if self._cached_search_html is not None:
            return self._cached_search_html
        try:
            resp = self.session.get(self.base_url, timeout=self.timeout)
            resp.raise_for_status()
            self._cached_search_html = resp.text
            self._cached_tokens = self._extract_tokens(resp.text)
            self._delay()
            return self._cached_search_html
        except Exception as e:
            logging.error(f"Failed to fetch search page: {e}")
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
        try:
            resp = self.session.post(self.base_url, data=data, timeout=self.timeout)
            resp.raise_for_status()
            self._delay()
            return resp.text
        except Exception as e:
            logging.warning(f"Submission error: {e}")
            return None

    def _parse_result(self, html):
        if not html:
            return False, "Unknown", "Unknown"

        soup = BeautifulSoup(html, 'html.parser')
        text = soup.get_text(separator=' ')

        lower = text.lower()
        benefit = any(ind in lower for ind in self.success_indicators)

        # Institution
        inst = "Unknown"
        inst_patterns = [
            r'(?:Plan|Institution|Provider|Company)\s*:\s*([^\n\r<]+)',
            r'(?:Retirement Plan|Pension Plan)\s*:\s*([^\n\r<]+)',
            r'(?<=Plan\s+Name\s*:\s*)([^\n\r<]+)',
        ]
        for pat in inst_patterns:
            m = re.search(pat, text, re.I)
            if m:
                inst = m.group(1).strip()
                break
        if inst == "Unknown":
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

        # Status
        status = "Unknown"
        status_patterns = [
            r'(?:Status|Account Status)\s*:\s*([A-Za-z]+)',
            r'(?:Current Status)\s*:\s*([A-Za-z]+)',
        ]
        for pat in status_patterns:
            m = re.search(pat, text, re.I)
            if m:
                status = m.group(1).strip().capitalize()
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

        html = self._fetch_search_page()
        if not html:
            return {**person, 'benefit_found': 'ERROR', 'institution': 'N/A',
                    'account_status': 'N/A', 'status': 'Fetch failed'}

        tokens = self._cached_tokens.copy()
        result_html = None
        for attempt in range(self.max_retries):
            result_html = self._submit_search(last_name, ssn, tokens)
            if result_html:
                lower_resp = result_html.lower()
                if 'please enter a valid' in lower_resp or 'invalid' in lower_resp:
                    self._cached_search_html = None
                    self._cached_tokens = None
                    fresh = self._fetch_search_page()
                    if fresh:
                        tokens = self._cached_tokens.copy()
                    continue
                break
            time.sleep(1 * (attempt + 1))

        if not result_html:
            return {**person, 'benefit_found': 'ERROR', 'institution': 'N/A',
                    'account_status': 'N/A', 'status': 'No response'}

        benefit, inst, acc_status = self._parse_result(result_html)
        return {
            **person,
            'benefit_found': 'TRUE' if benefit else 'FALSE',
            'institution': inst,
            'account_status': acc_status,
            'status': 'Success'
        }

# ---------- Input Parsing (TXT) ----------
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

def load_people_from_txt(filepath, delimiter, field_order):
    people = []
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
        print_status(f"[!] Load error: {e}", RED)
        return None

def get_single_person():
    clear_screen()
    print_banner()
    print_status("\n--- Single Scan ---", CYAN)
    name = colored_input("Full Name: ")
    ssn = colored_input("SSN (e.g., 123-45-6789): ")
    if not name or not ssn:
        return None
    return [{'full_name': name, 'ssn': ssn, 'dob': '', 'address': ''}]

def get_batch_people():
    clear_screen()
    print_banner()
    print_status("\n--- Batch Scan from TXT ---", CYAN)
    filepath = colored_input("Path to TXT file: ")
    if not filepath:
        return None
    delimiter_choice = colored_input("Delimiter (comma, tab, space, or custom char): ").lower()
    if delimiter_choice == 'comma':
        delimiter = ','
    elif delimiter_choice == 'tab':
        delimiter = '\t'
    elif delimiter_choice == 'space':
        delimiter = ' '
    else:
        delimiter = delimiter_choice
    field_order = colored_input("Field order (comma-separated, e.g., name,ssn or ssn,name or name,ssn,dob,address): ")
    if not field_order:
        print_status("Field order required.", RED)
        return None
    fields = [f.strip() for f in field_order.split(',')]
    if 'name' not in fields or 'ssn' not in fields:
        print_status("Field order must include 'name' and 'ssn'.", RED)
        return None
    people = load_people_from_txt(filepath, delimiter, field_order)
    return people

# ---------- Output Writing (TXT) ----------
def write_results(output_file, results, append=False):
    """Write results as tab-separated TXT."""
    fieldnames = ['full_name', 'ssn', 'dob', 'address', 'benefit_found', 'institution', 'account_status', 'status']
    mode = 'a' if append else 'w'
    try:
        with open(output_file, mode, encoding='utf-8') as f:
            if not append or os.path.getsize(output_file) == 0:
                f.write('\t'.join(fieldnames) + '\n')
            for r in results:
                row = [r.get(k, '') for k in fieldnames]
                f.write('\t'.join(row) + '\n')
        return True
    except Exception as e:
        logging.error(f"Write error: {e}")
        return False

# ---------- Worker wrapper ----------
def process_worker(person, config):
    agent = PBGCAgent(BASE_URL, config)
    return agent.process(person)

# ---------- Main ----------
def main():
    print_banner()

    # Configuration
    config = configure()

    # Scan mode
    clear_screen()
    print_banner()
    print_status("\n--- Scan Mode ---", CYAN)
    mode = colored_input("Choose mode: [1] Single scan  [2] Batch scan from TXT: ")
    if mode == '1':
        people = get_single_person()
        if not people:
            print_status("Aborted.", RED)
            return
    elif mode == '2':
        people = get_batch_people()
        if not people:
            print_status("Aborted.", RED)
            return
    else:
        print_status("Invalid choice.", RED)
        return

    clear_screen()
    print_banner()
    print_status(f"[*] Loaded {len(people)} individual(s).", GREEN)
    print_status(f"[*] Output will be saved to: {config['output_file']}", CYAN)
    print_status("[*] Starting scan...\n", CYAN)

    # Prepare output file (overwrite with header)
    write_results(config['output_file'], [], append=False)

    total = len(people)
    completed = 0
    results = []

    # For single scan, use 1 worker
    max_workers = 1 if total == 1 else config['threads']

    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        future_to_person = {executor.submit(process_worker, p, config): p for p in people}
        for future in as_completed(future_to_person):
            person = future_to_person[future]
            try:
                result = future.result()
                results.append(result)
                completed += 1
                status_colour = GREEN if result['benefit_found'] == 'TRUE' else YELLOW
                # Real-time update
                print(f"[{completed}/{total}] {result['full_name']:<20} "
                      f"Benefit: {result['benefit_found']:<5} "
                      f"Inst: {result['institution']:<15} "
                      f"Status: {result['account_status']:<10} "
                      f"({result['status']})", status_colour)
                # Write every 5 records
                if len(results) % 5 == 0:
                    write_results(config['output_file'], results[-5:], append=True)
            except Exception as e:
                logging.error(f"Failed to process {person.get('full_name')}: {e}")
                completed += 1

    # Write remaining
    if results:
        write_results(config['output_file'], results, append=True)

    print_status(f"\n[+] All done. Results saved to {config['output_file']}", GREEN)

if __name__ == '__main__':
    try:
        logging.basicConfig(level=logging.WARNING, format='%(asctime)s - %(levelname)s - %(message)s')
        main()
    except KeyboardInterrupt:
        print("\nInterrupted.")
        sys.exit(0)
