# Contributing to Audit Vault

Thank you for your interest in contributing to Audit Vault.

## Code of Conduct

Please maintain a respectful and constructive atmosphere in all interactions and contributions.

## Development Workflow

1. Fork the repository on GitHub.
2. Clone your fork locally:
   ```bash
   git clone https://github.com/YOUR_USERNAME/audit-vault.git
   cd audit-vault
   ```
3. Set up a virtual environment and install dependencies:
   ```bash
   python -m venv .venv
   source .venv/bin/activate
   pip install -r requirements.txt
   pip install -e .
   ```
4. Create a feature branch for your changes:
   ```bash
   git checkout -b feature/your-feature-name
   ```

## Testing

Ensure all tests pass before submitting your changes:

```bash
pytest tests/
```

Or with Python's built-in test runner:

```bash
python -m unittest discover -s tests
```

## Pull Request Guidelines

- Keep pull requests focused on a single change or fix.
- Add relevant unit or integration tests for new features.
- Update documentation and docstrings when modifying functionality.
- Write clear, concise commit messages.
- Open a pull request against the `main` branch.
