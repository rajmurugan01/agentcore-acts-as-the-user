# Region is pinned: the shell's AWS_REGION can silently override AWS_DEFAULT_REGION for CLI calls.
export AWS_REGION ?= us-east-1
export AWS_DEFAULT_REGION ?= us-east-1
export CDK_DEFAULT_ACCOUNT ?= $(shell aws sts get-caller-identity --query Account --output text)

install:
	cd cdk && npm install
	python3 -m pip install --quiet boto3

deploy: install
	cd cdk && npx cdk deploy --require-approval never --outputs-file cdk.outputs.json

demo:
	python3 demo/demo.py | tee docs/transcript.txt

destroy:
	cd cdk && npx cdk destroy --force

.PHONY: install deploy demo destroy
