# 401k-scanner
Using this tool to learn how a scanner is built… This is as a result of a finding of similar activity going on. I will be making a report on how this can be mitigated... stay toned...

---

How to Use

1. Edit BASE_URL (line ~22) to your sandbox endpoint.
2. Install dependencies:
   ```bash
   pip install requests beautifulsoup4
   ```
3. Run:
   ```bash
   python 401k-scan.py
   ```
4. Follow the interactive prompts – all settings are asked upfront.
5. For batch mode, prepare a .txt file with one person per line, using a delimiter and field order you specify (e.g., name,ssn or ssn,name,dob,address).

---

Example TXT for Batch Mode

File people.txt (with comma delimiter, field order name,ssn,dob,address):

```
John Doe,123-45-6789,1980-01-15,123 Main St
Jane Smith,987-65-4321,1975-12-10,456 Oak Ave
```

Output file (e.g., results_2026-07-22_15-30-45.txt) will be tab‑separated with a header.

---
