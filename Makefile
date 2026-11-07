.PHONY: validate schema restricted test lint

validate: schema restricted test lint ## Run every local check

schema:
	kubeconform -strict -summary manifests/*.yaml

restricted:
	scripts/check_restricted.py

test:
	python3 -m unittest discover -s scripts -p 'test_*.py'

lint:
	actionlint
