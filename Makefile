PYTHON ?= $(shell if [ -x .venv/bin/python ]; then echo .venv/bin/python; else echo python3; fi)

.PHONY: setup test fmt validate seed-secret security alarm-test identity-demo k8s-demo vuln-demo vuln-report

setup:
	$(PYTHON) -m pip install -r requirements-dev.txt

test:
	$(PYTHON) -m unittest discover -s tests -t . -v

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
	bandit -q -r src/aggregator_lambda src/parser_lambda/handler.py src/parser_lambda/identity_handler.py src/parser_lambda/kubernetes_handler.py src/parser_lambda/vulnerability_handler.py src/parser_lambda/vulnerability_report_handler.py src/parser_lambda/log_parser_toolkit src/identity_fixture src/kubernetes_fixture src/vulnerability_cli src/vulnerability_fixture
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

# Exercise the identity plane: CloudTrail fixtures through S3->SQS->Lambda and
# a GuardDuty finding through EventBridge->SQS->Lambda.
identity-demo:
	$(PYTHON) src/identity_fixture/upload_identity_fixtures.py \
		--endpoint-url $${AWS_ENDPOINT_URL:-http://localhost:4566}

# Exercise the Kubernetes plane with an audit EventList and a Falco event.
k8s-demo:
	$(PYTHON) src/kubernetes_fixture/upload_kubernetes_fixtures.py \
		--endpoint-url $${AWS_ENDPOINT_URL:-http://localhost:4566}

# Upload the asset inventory and Nessus/Qualys fixtures. The S3 notification
# drives the vulnerability processor; run `make vuln-report` after it settles.
vuln-demo:
	$(PYTHON) src/vulnerability_fixture/upload_vulnerability_fixtures.py \
		--endpoint-url $${AWS_ENDPOINT_URL:-http://localhost:4566}

# Build JSON/CSV/Markdown remediation reports from the open findings.
vuln-report:
	$(PYTHON) src/vulnerability_cli/report.py \
		--endpoint-url $${AWS_ENDPOINT_URL:-http://localhost:4566} \
		--output-dir $${VULN_REPORT_DIR:-/tmp/opencode/vuln-report}
