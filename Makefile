.PHONY: setup test fmt validate seed-secret security alarm-test

setup:
	python3 -m pip install -r requirements-dev.txt

test:
	python3 -m unittest discover -s tests -t . -v

fmt:
	terraform fmt -recursive terraform

validate:
	cd terraform && terraform init -backend=false -input=false && terraform validate

# Push the AbuseIPDB key from your shell into Secrets Manager. The value is
# never written to Terraform configuration, state, or the repository.
seed-secret:
	@if [ -z "$$ABUSEIPDB_API_KEY" ]; then \
		echo "ABUSEIPDB_API_KEY is not set"; \
		exit 1; \
	fi
	AWS_ACCESS_KEY_ID=mock AWS_SECRET_ACCESS_KEY=mock \
	AWS_DEFAULT_REGION=$${AWS_DEFAULT_REGION:-us-east-1} \
	aws --endpoint-url=$${AWS_ENDPOINT_URL:-http://localhost:4566} \
		secretsmanager put-secret-value \
		--secret-id ot-telemetry/abuseipdb \
		--secret-string "{\"api_key\":\"$$ABUSEIPDB_API_KEY\"}"

security:
	bandit -q -r src/aggregator_lambda src/parser_lambda/handler.py src/parser_lambda/log_parser_toolkit
	pip-audit -r requirements-dev.txt
	checkov -d terraform --config-file .checkov.yaml --compact

# Prove an alarm state change reaches the operations SNS topic. The subscribed
# sink queue is the local stand-in for a real paging integration.
alarm-test:
	AWS_ACCESS_KEY_ID=mock AWS_SECRET_ACCESS_KEY=mock \
	AWS_DEFAULT_REGION=$${AWS_DEFAULT_REGION:-us-east-1} \
	aws --endpoint-url=$${AWS_ENDPOINT_URL:-http://localhost:4566} \
		cloudwatch set-alarm-state --alarm-name ot-ingest-dlq-depth \
		--state-value ALARM --state-reason "local verification"
	AWS_ACCESS_KEY_ID=mock AWS_SECRET_ACCESS_KEY=mock \
	AWS_DEFAULT_REGION=$${AWS_DEFAULT_REGION:-us-east-1} \
	aws --endpoint-url=$${AWS_ENDPOINT_URL:-http://localhost:4566} \
		sqs receive-message \
		--queue-url $${AWS_ENDPOINT_URL:-http://localhost:4566}/000000000000/ot-ops-alerts-sink \
		--max-number-of-messages 1
