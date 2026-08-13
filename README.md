# 🔐 Advanced Password Strength Checker

A **Python** CLI security tool that goes far beyond "8 characters, 1 number, 1 symbol." It analyzes real entropy, detects structural weaknesses (keyboard walks, sequences, leetspeak-disguised common passwords), estimates realistic crack times across multiple attack scenarios, checks for known data breaches, and can enforce a custom password policy — perfect for CI pipelines, signup form validation, or a personal security audit.

Built with a rich terminal UI (via [`rich`](https://github.com/Textualize/rich)) and zero heavyweight dependencies.

## ✨ Features

- **Entropy Analysis** — computes true character-pool-based entropy (bits), not just a length check
- **Pattern Detection Engine**
  - Keyboard walks (`qwerty`, `asdfgh`, `98765`)
  - Sequential characters (`abcd`, `4321`)
  - Repeated characters (`aaa`, `111`)
  - Date/year patterns (`1990`, `12/25/2000`)
  - Common password matches — **including leetspeak** (`P@ssw0rd` → detected as `password`)
- **Crack Time Estimation** across 4 real attack scenarios:
  - Online, rate-limited
  - Online, unthrottled
  - Offline, slow hash (bcrypt/argon2)
  - Offline, fast hash on GPU (MD5/SHA1)
- **Live Breach Check** — checks the password against [Have I Been Pwned](https://haveibeenpwned.com/) using the **k-Anonymity model** (only 5 characters of a SHA-1 hash are ever sent — your real password never leaves your machine)
- **Policy Compliance Mode** — validate against a custom JSON policy (min length, required character classes, minimum score) with proper exit codes for **CI/CD gating**
- **Secure Password Generator** — generates cryptographically secure passwords using Python's `secrets` module (not `random`)
- **Batch Mode** — audit an entire file of passwords at once
- **JSON Output** — for scripting, dashboards, or integration into other tools

## 🛠️ Tech Stack

- **Python 3.8+** (standard library: `hashlib`, `secrets`, `urllib`, `argparse`, `dataclasses`)
- **[rich](https://github.com/Textualize/rich)** — terminal UI rendering (gracefully degrades to plain text if not installed)

## 📂 Project Structure

```
password-strength-checker/
├── password_checker/
│   ├── __init__.py
│   ├── __main__.py       # enables `python -m password_checker`
│   ├── analyzer.py         # entropy + scoring engine
│   ├── patterns.py         # keyboard walks, sequences, leetspeak, common-password matching
│   ├── crack_time.py       # crack-time estimation across attack scenarios
│   ├── breach_check.py     # HaveIBeenPwned k-Anonymity API integration
│   ├── policy.py           # policy compliance checker
│   ├── generator.py        # secure password generator
│   ├── cli.py               # CLI + rich terminal rendering
│   └── data/
│       └── common_passwords.txt
├── tests/
│   └── test_analyzer.py    # 19 unit tests
├── requirements.txt
├── setup.py
├── README.md
└── .gitignore
```

## 🚀 Getting Started

### 1. Clone the repository
```bash
git clone https://github.com/ShyamD2/password-strength-checker.git
cd password-strength-checker
```

### 2. Install dependencies
```bash
pip install -r requirements.txt
```

### 3. Run it
```bash
# Check a password directly
python -m password_checker "MyP@ssw0rd123"

# Hidden prompt (recommended — doesn't leave the password in shell history)
python -m password_checker

# Skip the online breach check (fully offline)
python -m password_checker "MyPassword" --no-breach-check
```

### Optional: install as a CLI command
```bash
pip install -e .
pwcheck "MyP@ssw0rd123"
```

## 📖 Usage Examples

**Generate and audit a strong password:**
```bash
python -m password_checker --suggest --length 24
```

**Batch-check a list of passwords (e.g. exported from a breach dump for internal audit):**
```bash
python -m password_checker --file passwords.txt
```

**Enforce a minimum score in a CI pipeline (exits 1 if not met):**
```bash
python -m password_checker "$USER_PASSWORD" --min-score 70 --no-breach-check
```

**Enforce a full custom policy (see below):**
```bash
python -m password_checker "$USER_PASSWORD" --policy policy.json
```

**Get machine-readable JSON output:**
```bash
python -m password_checker "MyPassword123!" --json
```

## 📋 Custom Policy File

Create a `policy.json`:
```json
{
  "min_length": 14,
  "require_uppercase": true,
  "require_lowercase": true,
  "require_digit": true,
  "require_special": true,
  "disallow_common_passwords": true,
  "min_score": 65
}
```

Run:
```bash
python -m password_checker "CandidatePassword1!" --policy policy.json
```

Exits with code `0` if compliant, `1` if not — ideal for pre-commit hooks or signup validation pipelines.

## 🧪 Running Tests

```bash
python -m unittest discover -s tests -v
```

19 tests covering entropy calculation, pattern detection, crack-time math, the generator, and policy validation.

## 🔒 Privacy Note

The breach check uses HaveIBeenPwned's **k-Anonymity API**: only the first 5 characters of your password's SHA-1 hash are sent over the network. The full password and full hash never leave your machine. You can disable this check entirely with `--no-breach-check` for a fully offline audit.

## 🗺️ Roadmap / Ideas for Contribution

- [ ] Support for NIST-recommended dictionary/passphrase strength scoring
- [ ] Web UI (Flask, server-rendered, no JS)
- [ ] Support for custom common-password wordlists (e.g. RockYou)
- [ ] Multi-language dictionary support
- [ ] Integration as a `pre-commit` hook package

## 📄 License

MIT — free to use and modify.

---

If you found this useful, consider giving the repo a ⭐!
