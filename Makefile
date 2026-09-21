.PHONY: setup test fmt validate

setup:
	python3 -m pip install -r requirements-dev.txt

test:
	python3 -m unittest discover -s tests -t . -v

fmt:
	terraform fmt -recursive terraform

validate:
	cd terraform && terraform init -backend=false -input=false && terraform validate
