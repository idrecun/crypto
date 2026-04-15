.PHONY: setup reinstall clean

VENV ?= .venv
PYTHON ?= python3
PIP := $(VENV)/bin/pip

setup:
	@echo "[setup] Creating virtual environment at $(VENV)"
	$(PYTHON) -m venv $(VENV)
	@echo "[setup] Installing build backend (setuptools)"
	$(PIP) install --progress-bar on --disable-pip-version-check "setuptools>=68"
	@echo "[setup] Installing course runtime dependencies"
	$(PIP) install --progress-bar on --disable-pip-version-check pycryptodome pillow
	@echo "[setup] Installing project in editable mode"
	$(PIP) install --progress-bar on --disable-pip-version-check --no-build-isolation -e .

reinstall: clean setup

clean:
	rm -rf $(VENV)
	find . -type d -name "__pycache__" -prune -exec rm -rf {} +
	find . -type f -name "*.pyc" -delete
