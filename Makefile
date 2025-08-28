# Makefile for plsyaycheckyay

.PHONY: install clean test config help

help:
	@echo "Available commands:"
	@echo "  install  - Install the utility"
	@echo "  config   - Run configuration setup"
	@echo "  test     - Run test example"
	@echo "  clean    - Clean temporary files"
	@echo "  help     - Show this help"

install:
	@echo "🚀 Installing plsyaycheckyay..."
	./install.sh

config:
	@echo "🛠️ Running configuration setup..."
	python3 config.py

test:
	@echo "🧪 Running test example..."
	python3 test_example.py

clean:
	@echo "🧹 Cleaning temporary files..."
	find . -name "__pycache__" -type d -exec rm -rf {} + 2>/dev/null || true
	find . -name "*.pyc" -delete 2>/dev/null || true
	rm -rf /tmp/plsyay_* 2>/dev/null || true

lint:
	@if command -v flake8 >/dev/null 2>&1; then \
		echo "🔍 Running code linting..."; \
		flake8 *.py --max-line-length=100; \
	else \
		echo "⚠️  flake8 not installed, skipping lint"; \
	fi