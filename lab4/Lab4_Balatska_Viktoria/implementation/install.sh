#!/usr/bin/env bash
set -e

PYTHON_BIN=python3
VENV_DIR=.venv

echo "== Secure Crypto Demo installer =="

if ! command -v $PYTHON_BIN >/dev/null 2>&1; then
  echo "Error: Python3 not found."
  exit 1
fi

if [ ! -d "$VENV_DIR" ]; then
  echo "Creating virtual environment..."
  $PYTHON_BIN -m venv "$VENV_DIR"
fi

source "$VENV_DIR/bin/activate"
pip install --upgrade pip setuptools wheel >/dev/null

if [ -f "secure_crypto_demo.py" ]; then
  chmod +x secure_crypto_demo.py
  echo "secure_crypto_demo.py made executable."
fi

echo "Installation complete."
echo "Run with:"
echo "  sudo ./secure_crypto_demo.py"
