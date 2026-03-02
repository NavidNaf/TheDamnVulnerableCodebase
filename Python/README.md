# Vulnerable Python Application

This application is intentionally vulnerable and contains the following issues:
- Plaintext secrets in `config.py`
- SQL Injection vulnerability in the `/sqli` endpoint
- Cross-Site Scripting (XSS) vulnerability in the `/xss` endpoint
- Command injection vulnerability in the `/command` endpoint
- Cryptographic issues in `insecure_crypto.py`
- Timing side-channel cryptographic weakness in `homomorphic.py`

## Installation

Run `pip install -r requirements.txt` to install dependencies.

## Running the Application

Use `python app.py` to run the application.

### Cryptography Samples

- Run `python homomorphic.py` to execute the intentionally vulnerable homomorphic-style scheme.
- `decrypt_vulnerable()` contains data-dependent branching and extra work, which can leak information through timing.
- `decrypt_masked()` is included as a fixed-time comparison version.

### Accessing the Application

1. Navigate to `http://localhost:6789` in your web browser.
2. Use the following endpoints to test vulnerabilities:
   - **SQL Injection**: `/sqli?user_id=<payload>`
   - **Cross-Site Scripting (XSS)**: `/xss?name=<script>alert('XSS');</script>`
   - **Command Injection**: `/command?command=<your_command>`
