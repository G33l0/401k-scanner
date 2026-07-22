#!/usr/bin/env python3
"""
401k Scanner – Hardened for Sandbox Testing
Author: Red Team
WARNING: For authorised use only. Change BASE_URL to your mock.
"""
import sys
import csv
import random
import re
import time
import logging
from concurrent.futures import ThreadPoolExecutor, as_completed
from urllib.parse import urljoin
from collections import defaultdict

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

# ---------- CONFIGURATION (EDIT THESE) ----------
BASE_URL = "https://www.pbgc.gov/workers-retirees/find-unclaimed-retirement-benefits/search-unclaimed"
LAST_NAME_FIELD = "last_name"
SSN_FIELD = "ssn"
SUCCESS_INDICATORS = ["benefit", "pension", "unclaimed", "retirement"]
REQUEST_TIMEOUT = 15
MAX_RETRIES = 3
THREADS = 5                # adjust based on target rate limits
DELAY_MIN = 1.0
DELAY_MAX = 3.0
OUTPUT_CSV = "results.csv"
# ------------------------------------------------

# Colours (ANSI)
RESET = "\033[0m"
BOLD = "\033[1m"
RED = "\033[91m"
GREEN = "\033[92m"
YELLOW = "\033[93m"
CYAN = "\033[96m"
GREY = "\033[90m"

def print_banner():
    try:
        from pyfiglet import Figlet
        f = Figlet(font='slant', width=80)
        print(f"{CYAN}{f.renderText('401k Scanner')}{RESET}")
    except:
        print(f"{CYAN}{'='*60}{RESET}")
        print(f"{CYAN}         401k SCANNER  -  Mock Pension Retrieval{RESET}")
        print(f"{CYAN}{'='*60}{RESET}")
    print(f"{YELLOW}╔{'═'*58}╗{RESET}")
    print(f"{YELLOW}║{RESET}  {BOLD}🔒 SANDBOX ONLY – Change BASE_URL in script{RESET}  {YELLOW}║{RESET}")
    print(f"{YELLOW}║{RESET}  {GREY}Target: {BASE_URL}{RESET}  {YELLOW}║{RESET}")
    print(f"{YELLOW}╚{'═'*58}╝{RESET}\n")

def colored_input(prompt):
    return input(f"{CYAN}{prompt}{RESET}").strip()

def print_status(msg, colour=GREEN):
    print(f"{colour}{msg}{RESET}")

# ---------- Core Agent (thread‑safe) ----------
class PBGCAgent:
    def __init__(self, base_url, timeout=REQUEST_TIMEOUT):
        self.base_url = base_url.rstrip('/')
        self.timeout = timeout
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36',
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8'
        })
        self._cached_tokens = None
        self._cached_search_html = None

    def _delay(self):
        time.sleep(random.uniform(DELAY_MIN, DELAY_MAX))

    def _fetch_search_page(self):
        """Fetch and cache the search page HTML and form tokens."""
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
        """Extract Drupal form tokens and any other hidden inputs."""
        soup = BeautifulSoup(html, 'html.parser')
        tokens = {}
        # Look for the form – if multiple, prefer one with our fields
        for form in soup.find_all('form'):
            inputs = form.find_all('input')
            for inp in inputs:
                name = inp.get('name')
                value = inp.get('value', '')
                if name in ('form_build_id', 'form_id', 'op', 'form_token'):
                    tokens[name] = value
                # Also collect any hidden input that might be needed
                if inp.get('type') == 'hidden' and name:
                    tokens[name] = value
        if 'op' not in tokens:
            tokens['op'] = 'Search'
        return tokens

    def _submit_search(self, last_name, ssn, tokens):
        """POST with last_name, ssn, and tokens."""
        url = self.base_url
        data = {
            LAST_NAME_FIELD: last_name,
            SSN_FIELD: ssn,
        }
        data.update(tokens)

        try:
            resp = self.session.post(url, data=data, timeout=self.timeout)
            resp.raise_for_status()
            self._delay()
            return resp.text
        except Exception as e:
            logging.warning(f"Submission error: {e}")
            return None

    def _parse_result(self, html):
        """Improved parsing with multiple fallbacks."""
        if not html:
            return False, "Unknown", "Unknown"

        soup = BeautifulSoup(html, 'html.parser')
        text = soup.get_text(separator=' ')

        # 1. Benefit found?
        lower = text.lower()
        benefit = any(ind in lower for ind in SUCCESS_INDICATORS)

        # 2. Institution – try several strategies
        inst = "Unknown"
        # Strategy A: regex patterns
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
        # Strategy B: look for bold/strong elements containing keywords
        if inst == "Unknown":
            for tag in soup.find_all(['strong', 'b', 'h2', 'h3']):
                txt = tag.get_text(strip=True)
                if re.search(r'(plan|institution|provider|company)', txt, re.I):
                    parent = tag.find_parent()
                    if parent:
                        # Try sibling text or next element
                        sibling = parent.find_next_sibling()
                        if sibling:
                            inst = sibling.get_text(strip=True).split('.')[0]
                        else:
                            inst = parent.get_text(separator=' ').replace(txt, '').strip()
                        if inst:
                            break

        # 3. Status
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

        # Bonus: if the response says "no records" or "not found", benefit should be False
        if re.search(r'no (results?|records?|benefits?|pensions?)', lower):
            benefit = False

        return benefit, inst, status

    def process(self, person):
        """Process one individual, returning enriched dict."""
        # Extract last name
        name_parts = person['full_name'].strip().split()
        last_name = name_parts[-1] if name_parts else 'Unknown'
        ssn = person.get('ssn', '')

        # 1. Get search page (cached)
        html = self._fetch_search_page()
        if not html:
            return {**person, 'benefit_found': 'ERROR', 'institution': 'N/A',
                    'account_status': 'N/A', 'status': 'Fetch failed'}

        tokens = self._cached_tokens.copy()  # copy to avoid mutation

        # 2. Submit with retries
        result_html = None
        for attempt in range(MAX_RETRIES):
            result_html = self._submit_search(last_name, ssn, tokens)
            if result_html:
                # Check for common validation errors
                lower_resp = result_html.lower()
                if 'please enter a valid' in lower_resp or 'invalid' in lower_resp:
                    # Refresh tokens (maybe session expired)
                    logging.debug(f"Invalid input, refreshing tokens (attempt {attempt+1})")
                    self._cached_search_html = None
                    self._cached_tokens = None
                    fresh = self._fetch_search_page()
                    if fresh:
                        tokens = self._cached_tokens.copy()
                    continue
                # If we got a proper response, break
                break
            time.sleep(1 * (attempt + 1))  # backoff

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

# ---------- CSV & I/O ----------
def detect_columns(reader):
    """Map input columns to our required fields."""
    fieldnames = reader.fieldnames
    mapping = {}
    for col in fieldnames:
        low = col.strip().lower()
        if low in ('full_name', 'name', 'fullname'):
            mapping['full_name'] = col
        elif low in ('ssn', 'social', 'social_security', 'ssn_number'):
            mapping['ssn'] = col
        elif low in ('dob', 'birthdate', 'date_of_birth'):
            mapping['dob'] = col
        elif low in ('address', 'addr', 'street'):
            mapping['address'] = col
    # Ensure we have at least full_name and ssn
    if 'full_name' not in mapping or 'ssn' not in mapping:
        return None
    return mapping

def load_people(input_file):
    people = []
    try:
        with open(input_file, 'r', newline='', encoding='utf-8') as f:
            reader = csv.DictReader(f)
            mapping = detect_columns(reader)
            if not mapping:
                print_status("[!] Input CSV must contain 'full_name' (or name) and 'ssn' columns.", RED)
                return None
            for row in reader:
                person = {
                    'full_name': row.get(mapping['full_name'], '').strip(),
                    'ssn': row.get(mapping['ssn'], '').strip(),
                    'dob': row.get(mapping.get('dob', ''), '').strip(),
                    'address': row.get(mapping.get('address', ''), '').strip()
                }
                if person['full_name'] and person['ssn']:
                    people.append(person)
                else:
                    logging.warning(f"Skipping row missing name or SSN: {row}")
        return people
    except Exception as e:
        print_status(f"[!] Load error: {e}", RED)
        return None

def write_results(output_file, results, append=False):
    """Write results incrementally; if append, we don't rewrite header."""
    fieldnames = ['full_name', 'ssn', 'dob', 'address', 'benefit_found', 'institution', 'account_status', 'status']
    mode = 'a' if append else 'w'
    try:
        with open(output_file, mode, newline='', encoding='utf-8') as f:
            writer = csv.DictWriter(f, fieldnames=fieldnames)
            if not append or f.tell() == 0:
                writer.writeheader()
            for r in results:
                writer.writerow({k: r.get(k, '') for k in fieldnames})
        return True
    except Exception as e:
        logging.error(f"Write error: {e}")
        return False

def generate_sample(output_file):
    sample = [
        {'full_name': 'John Doe', 'ssn': '123-45-6789', 'dob': '1980-01-15', 'address': '123 Main St'},
        {'full_name': 'Jane Smith', 'ssn': '987-65-4321', 'dob': '1975-12-10', 'address': '456 Oak Ave'},
    ]
    try:
        with open(output_file, 'w', newline='', encoding='utf-8') as f:
            writer = csv.DictWriter(f, fieldnames=['full_name', 'ssn', 'dob', 'address'])
            writer.writeheader()
            writer.writerows(sample)
        print_status(f"[+] Sample CSV generated: {output_file}", GREEN)
        return True
    except Exception as e:
        print_status(f"[!] Sample error: {e}", RED)
        return False

# ---------- Main ----------
def main():
    print_banner()
    print("Choose CSV option:")
    print("  [1] Use existing CSV")
    print("  [2] Generate sample CSV")
    choice = colored_input("Enter 1 or 2: ")
    if choice == '1':
        input_file = colored_input("Path to input CSV: ")
        if not input_file:
            print_status("Aborted.", RED)
            return
        output_file = colored_input(f"Output CSV (default: {OUTPUT_CSV}): ") or OUTPUT_CSV
    elif choice == '2':
        input_file = colored_input("Sample filename (default: people.csv): ") or "people.csv"
        if not generate_sample(input_file):
            return
        output_file = colored_input(f"Output CSV (default: {OUTPUT_CSV}): ") or OUTPUT_CSV
    else:
        print_status("Invalid choice.", RED)
        return

    people = load_people(input_file)
    if not people:
        print_status("[!] No valid records.", RED)
        return

    print_status(f"[*] Loaded {len(people)} individuals. Using {THREADS} threads.", GREEN)

    # Prepare output file (overwrite with header)
    write_results(output_file, [], append=False)

    agent = PBGCAgent(BASE_URL)
    results = []
    total = len(people)
    completed = 0

    # Use ThreadPoolExecutor for concurrency
    with ThreadPoolExecutor(max_workers=THREADS) as executor:
        future_to_person = {executor.submit(agent.process, p): p for p in people}
        for future in as_completed(future_to_person):
            person = future_to_person[future]
            try:
                result = future.result()
                results.append(result)
                completed += 1
                # Print real‑time summary
                status_colour = GREEN if result['benefit_found'] == 'TRUE' else YELLOW
                print(f"[{completed}/{total}] {result['full_name']:<20} "
                      f"Benefit: {result['benefit_found']:<5} "
                      f"Inst: {result['institution']:<15} "
                      f"Status: {result['account_status']:<10} "
                      f"({result['status']})", status_colour)
                # Write incrementally every 5 results to avoid losing progress
                if len(results) % 5 == 0:
                    write_results(output_file, results[-5:], append=True)
            except Exception as e:
                logging.error(f"Failed to process {person.get('full_name')}: {e}")
                completed += 1

    # Write any remaining results
    if results:
        write_results(output_file, results, append=True)
    print_status(f"\n[+] All done. Results saved to {output_file}", GREEN)

if __name__ == '__main__':
    try:
        logging.basicConfig(level=logging.WARNING, format='%(asctime)s - %(levelname)s - %(message)s')
        main()
    except KeyboardInterrupt:
        print("\nInterrupted.")
        sys.exit(0)
