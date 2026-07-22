#!/usr/bin/env python3
"""
Configuration Discovery Tool for 401k Scanner
Given a base URL and search page path, this script inspects the mock page
and prints all parameters needed to hardcode the scanner.
"""
import sys
import re
import json
from urllib.parse import urljoin, urlparse

try:
    import requests
except ImportError:
    print("Missing 'requests'. Install: pip install requests")
    sys.exit(1)

try:
    from bs4 import BeautifulSoup
except ImportError:
    print("Missing 'beautifulsoup4'. Install: pip install beautifulsoup4")
    sys.exit(1)

# ANSI colours
RESET = "\033[0m"
BOLD = "\033[1m"
GREEN = "\033[92m"
YELLOW = "\033[93m"
CYAN = "\033[96m"
RED = "\033[91m"

def colored_print(msg, colour=GREEN):
    print(f"{colour}{msg}{RESET}")

def get_input(prompt, colour=CYAN):
    return input(f"{colour}{prompt}{RESET}").strip()

def main():
    print(f"{BOLD}{CYAN}=== 401k Scanner – Configuration Discovery ==={RESET}\n")
    print("This tool will fetch your mock search page and auto-detect settings.\n")

    base_url = get_input("Enter base URL (e.g., https://mock-pbgc.local): ")
    if not base_url:
        print("Aborted.")
        return
    base_url = base_url.rstrip('/')

    search_path = get_input("Enter search page path (e.g., /pbgc/search-participant): ")
    if not search_path:
        print("Aborted.")
        return

    full_url = urljoin(base_url, search_path)
    colored_print(f"\n[*] Fetching: {full_url}", YELLOW)

    try:
        resp = requests.get(full_url, timeout=15, headers={"User-Agent": "Mozilla/5.0"})
        resp.raise_for_status()
    except Exception as e:
        colored_print(f"[!] Failed to fetch page: {e}", RED)
        return

    html = resp.text
    soup = BeautifulSoup(html, 'html.parser')

    # Find all forms
    forms = soup.find_all('form')
    if not forms:
        colored_print("[!] No forms found on the page.", RED)
        return

    # Assume the first form is the search form (or the one with method POST)
    search_form = None
    for form in forms:
        if form.get('method', '').lower() == 'post':
            search_form = form
            break
    if not search_form:
        search_form = forms[0]  # fallback

    # 1. Form action (submit endpoint)
    form_action = search_form.get('action', '')
    if form_action:
        submit_endpoint = urljoin(base_url, form_action)
    else:
        # If action is empty, it likely submits to the same URL
        submit_endpoint = full_url

    # 2. Input fields
    inputs = search_form.find_all('input')
    input_names = [inp.get('name') for inp in inputs if inp.get('name')]
    input_types = {inp.get('name'): inp.get('type', 'text') for inp in inputs if inp.get('name')}

    # Identify CSRF token: look for hidden input with names containing 'csrf', 'token', etc.
    csrf_candidates = [name for name in input_names if re.search(r'(csrf|token|_token|authenticity)', name, re.I)]
    csrf_field = csrf_candidates[0] if csrf_candidates else None

    # Identify likely fields for last name, SSN, DOB by name heuristics
    last_name_fields = [name for name in input_names if re.search(r'(last[_\-]?name|surname|family)', name, re.I)]
    ssn_fields = [name for name in input_names if re.search(r'(ssn|social|security|tax[_\-]?id)', name, re.I)]
    dob_fields = [name for name in input_names if re.search(r'(dob|birth|date[_\-]?of[_\-]?birth|birthday)', name, re.I)]

    # If multiple, pick the first or use manual guess
    last_name_field = last_name_fields[0] if last_name_fields else None
    ssn_field = ssn_fields[0] if ssn_fields else None
    dob_field = dob_fields[0] if dob_fields else None

    # 3. Detect CAPTCHA type
    captcha_type = 'c'  # default: none
    # Look for math text
    math_pattern = re.compile(r'(\d+)\s*([+\-*/])\s*(\d+)')
    if re.search(math_pattern, soup.get_text()):
        captcha_type = 'a'
    else:
        # Look for image with captcha in src or alt
        images = soup.find_all('img')
        for img in images:
            src = img.get('src', '').lower()
            alt = img.get('alt', '').lower()
            if 'captcha' in src or 'captcha' in alt:
                captcha_type = 'b'
                break

    # 4. Extract success indicator – look for text like "benefit", "account found", "pension"
    body_text = soup.get_text(separator=' ')
    success_indicators = []
    for keyword in ['benefit', 'account found', 'pension', 'eligible', 'entitled']:
        if keyword in body_text.lower():
            success_indicators.append(keyword)
    # If no specific, we can use a generic "found" or the user can specify later.

    # 5. Try to guess selectors for institution and status (if visible on result page?)
    # We cannot know from search page alone, so we ask the user to provide sample result HTML later.
    # We'll print a suggestion.

    # 6. Extra headers – check for any meta or script that might indicate requirements
    headers = {}
    # Not easily discovered – we'll leave blank.

    # Print discovered configuration
    print("\n" + "="*60)
    colored_print("DISCOVERED CONFIGURATION", BOLD)
    print("="*60)
    print(f"{BOLD}Base URL:{RESET} {base_url}")
    print(f"{BOLD}Search page path:{RESET} {search_path}")
    print(f"{BOLD}Submit endpoint:{RESET} {submit_endpoint}")
    print(f"{BOLD}CSRF field name:{RESET} {csrf_field if csrf_field else '[NOT FOUND]'}")
    print(f"{BOLD}Last name field:{RESET} {last_name_field if last_name_field else '[NOT FOUND]'}")
    print(f"{BOLD}SSN field:{RESET} {ssn_field if ssn_field else '[NOT FOUND]'}")
    print(f"{BOLD}DOB field:{RESET} {dob_field if dob_field else '[NOT FOUND]'}")
    print(f"{BOLD}CAPTCHA type:{RESET} {captcha_type} (a=math, b=image, c=none)")
    print(f"{BOLD}Success indicators found:{RESET} {success_indicators if success_indicators else '[None – you may specify]'}")
    print(f"{BOLD}Other input fields found:{RESET} {', '.join(input_names)}")

    # Now, we need to gather result page selectors – we can't discover from search page.
    print("\n" + "="*60)
    colored_print("For institution and status extraction, please provide the following:", YELLOW)
    print("  - CSS selector or XPath for the element containing the institution/plan name")
    print("  - CSS selector or XPath for the element containing the account status (Active/Terminated)")
    print("  - Or specify 'text' to use regex on plain text (then we'll try common patterns).")
    print("\nYou can also copy this output and feed it into the config wizard.")
    print("\nTo generate a hardcoded scanner now, run the config_wizard.py and paste these values.")

    # Optionally, we can generate a JSON dump for machine reading.
    config_json = {
        "base_url": base_url,
        "search_path": search_path,
        "submit_endpoint": submit_endpoint,
        "csrf_field": csrf_field,
        "last_name_field": last_name_field,
        "ssn_field": ssn_field,
        "dob_field": dob_field,
        "captcha_type": captcha_type,
        "success_indicators": success_indicators,
        "other_inputs": input_names,
        "institution_method": "text",   # default
        "institution_selector": "",
        "status_method": "text",
        "status_selector": "",
        "extra_headers": {}
    }
    print("\nJSON representation (for scripting):")
    print(json.dumps(config_json, indent=2))

    # Save to file? Not required, but we can mention.
    print("\n" + "="*60)
    colored_print("Discovery complete.", GREEN)

if __name__ == '__main__':
    try:
        main()
    except KeyboardInterrupt:
        print("\nInterrupted.")
        sys.exit(0)
