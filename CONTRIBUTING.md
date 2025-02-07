# Contributing to CyberShield AI

Thank you for your interest in contributing!

## Security Contribution Guidelines

- All contributions must be for **defensive** security purposes
- Do not add attack tools, exploit code, or offensive capabilities
- New vulnerability patterns must include test cases with benign samples

## Getting Started

1. Fork the repository
2. Create a feature branch: `git checkout -b feature/my-feature`
3. Add tests for new scanner patterns
4. Run tests: `pytest`
5. Run linter: `ruff check . && ruff format .`
6. Open a Pull Request

## Adding New Detection Patterns

To add a new secret or vulnerability pattern:
1. Add regex to `backend/scanners/secret_scanner.py` or `code_scanner.py`
2. Add test cases in `backend/tests/`
3. Ensure no false positives on common benign code

## Reporting Vulnerabilities

To report a security issue in CyberShield itself, email maintainers directly. Do not open a public issue.
