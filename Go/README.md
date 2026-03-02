# Vulnerable Go Application

This application is intentionally vulnerable and contains the following issues:
- Plaintext secrets in `config.go`
- SQL Injection vulnerability in the `/user` endpoint
- Cross-Site Scripting (XSS) vulnerability in the `/greet` endpoint
- Command injection vulnerability in the `/run` endpoint
- Directory traversal vulnerability in the `/file` endpoint
- Weak randomness usage in the `/random` endpoint
- Hostname validation bypass issue in the `/hostname` endpoint
- Timing side-channel risk in the `/compare` endpoint
- ZIP Slip vulnerability in the `/extract` endpoint

## Installation

Run `go mod tidy` to install dependencies.

## Running the Application

Use `go run .` to run the application.
