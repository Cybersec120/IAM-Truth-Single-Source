.PHONY: help install lint typecheck security-scan \
        tf-init-entra tf-plan-entra tf-apply-entra tf-destroy-entra \
        tf-init-waf tf-plan-waf tf-apply-waf tf-destroy-waf \
        tf-fmt tf-validate \
        onboard-oidc onboard-saml onboard-proxy \
        onboard-user offboard-user \
        kv-replicate-dry kv-replicate \
        mfa-audit migrate-export migrate-import \
        pre-commit-install pre-commit-run \
        package clean

PYTHON  := python3
TF_ENTRA := terraform/entra-id
TF_WAF   := terraform/waf

# ── Help ──────────────────────────────────────────────────────────────────────
help:
	@printf "\n  enterprise-iam-platform\n\n"
	@printf "  \033[1mSetup\033[0m\n"
	@printf "    install              Install Python dependencies\n"
	@printf "    pre-commit-install   Install pre-commit hooks\n\n"
	@printf "  \033[1mCode quality\033[0m\n"
	@printf "    lint                 Ruff lint all Python scripts\n"
	@printf "    typecheck            Mypy strict type check\n"
	@printf "    security-scan        Bandit + detect-secrets\n"
	@printf "    tf-fmt               Terraform format check (recursive)\n"
	@printf "    tf-validate          Terraform validate both modules\n"
	@printf "    pre-commit-run       Run all pre-commit hooks on staged files\n\n"
	@printf "  \033[1mTerraform — WAF (deploy first)\033[0m\n"
	@printf "    tf-init-waf          terraform init\n"
	@printf "    tf-plan-waf          terraform plan\n"
	@printf "    tf-apply-waf         terraform apply\n\n"
	@printf "  \033[1mTerraform — entra-id\033[0m\n"
	@printf "    tf-init-entra        terraform init\n"
	@printf "    tf-plan-entra        terraform plan\n"
	@printf "    tf-apply-entra       terraform apply\n\n"
	@printf "  \033[1mApp onboarding\033[0m\n"
	@printf "    onboard-oidc         Onboard OIDC app (set CONFIG=configs/examples/hr-portal-oidc.json)\n"
	@printf "    onboard-saml         Onboard SAML app (set CONFIG=configs/examples/salesforce-saml.json)\n"
	@printf "    onboard-proxy        Onboard App Proxy app (set CONFIG=configs/examples/proxy-intranet.json)\n\n"
	@printf "  \033[1mUser lifecycle\033[0m\n"
	@printf "    onboard-user         Onboard user (set CONFIG=configs/examples/user-onboard.json)\n"
	@printf "    offboard-user        Offboard user (set UPN=user@contoso.com REASON=voluntary)\n\n"
	@printf "  \033[1mOperations\033[0m\n"
	@printf "    kv-replicate-dry     Dry-run KV replication to DR vault\n"
	@printf "    kv-replicate         Replicate secrets to DR vault\n"
	@printf "    mfa-audit            Generate MFA coverage report\n"
	@printf "    migrate-export       Export apps from source IdP (set SOURCE=okta)\n"
	@printf "    migrate-import       Import apps to Entra (set INPUT=migration/export.json)\n\n"
	@printf "  \033[1mPackaging\033[0m\n"
	@printf "    package              Create deployable zip archive\n"
	@printf "    clean                Remove build artifacts\n\n"

# ── Setup ─────────────────────────────────────────────────────────────────────
install:
	$(PYTHON) -m pip install --upgrade pip
	$(PYTHON) -m pip install -r requirements.txt
	$(PYTHON) -m pip install ruff mypy bandit detect-secrets pytest pytest-mock

pre-commit-install:
	$(PYTHON) -m pip install pre-commit
	pre-commit install
	pre-commit install --hook-type commit-msg
	@echo "Pre-commit hooks installed."

# ── Code quality ──────────────────────────────────────────────────────────────
lint:
	ruff check scripts/
	@echo "Lint: PASSED"

typecheck:
	mypy scripts/ --ignore-missing-imports --strict
	@echo "Type check: PASSED"

security-scan:
	bandit -r scripts/ -ll -ii -x scripts/tests/
	detect-secrets scan --baseline .secrets.baseline
	@echo "Security scan: PASSED"

tf-fmt:
	terraform -chdir=$(TF_ENTRA) fmt -check -recursive
	terraform -chdir=$(TF_WAF)   fmt -check -recursive
	@echo "Terraform fmt: PASSED"

tf-validate:
	terraform -chdir=$(TF_ENTRA) init -backend=false -input=false
	terraform -chdir=$(TF_ENTRA) validate
	terraform -chdir=$(TF_WAF)   init -backend=false -input=false
	terraform -chdir=$(TF_WAF)   validate
	@echo "Terraform validate: PASSED"

pre-commit-run:
	pre-commit run --all-files

# ── Terraform — WAF ───────────────────────────────────────────────────────────
tf-init-waf:
	terraform -chdir=$(TF_WAF) init

tf-plan-waf:
	terraform -chdir=$(TF_WAF) plan -out=waf.tfplan

tf-apply-waf:
	terraform -chdir=$(TF_WAF) apply waf.tfplan

tf-destroy-waf:
	@echo "WARNING: This will destroy all WAF infrastructure. Type 'yes' to confirm:"
	@read confirm && [ "$$confirm" = "yes" ] || (echo "Aborted."; exit 1)
	terraform -chdir=$(TF_WAF) destroy

# ── Terraform — entra-id ──────────────────────────────────────────────────────
tf-init-entra:
	terraform -chdir=$(TF_ENTRA) init

tf-plan-entra:
	terraform -chdir=$(TF_ENTRA) plan -out=entra.tfplan

tf-apply-entra:
	terraform -chdir=$(TF_ENTRA) apply entra.tfplan

tf-destroy-entra:
	@echo "WARNING: This will destroy all Entra ID resources. Type 'yes' to confirm:"
	@read confirm && [ "$$confirm" = "yes" ] || (echo "Aborted."; exit 1)
	terraform -chdir=$(TF_ENTRA) destroy

# ── App onboarding ────────────────────────────────────────────────────────────
CONFIG ?= configs/examples/hr-portal-oidc.json

onboard-oidc:
	$(PYTHON) scripts/onboarding/onboard_app.py --type oidc --config $(CONFIG) --dry-run
	@echo ""
	@echo "Dry run complete. To apply: make onboard-oidc-apply CONFIG=$(CONFIG)"

onboard-oidc-apply:
	$(PYTHON) scripts/onboarding/onboard_app.py --type oidc --config $(CONFIG) \
		--output manifests/$$(basename $(CONFIG) .json)-manifest.json

onboard-saml:
	$(PYTHON) scripts/onboarding/onboard_app.py --type saml \
		--config configs/examples/salesforce-saml.json --dry-run

onboard-proxy:
	$(PYTHON) scripts/onboarding/onboard_app.py --type proxy \
		--config configs/examples/proxy-intranet.json --dry-run

# ── User lifecycle ────────────────────────────────────────────────────────────
onboard-user:
	$(PYTHON) scripts/onboarding/user_lifecycle.py onboard \
		--config configs/examples/user-onboard.json --dry-run

UPN    ?= user@contoso.com
REASON ?= voluntary-termination

offboard-user:
	$(PYTHON) scripts/onboarding/user_lifecycle.py offboard \
		--upn $(UPN) --reason $(REASON) --dry-run

# ── Operations ────────────────────────────────────────────────────────────────
PRIMARY_KV   ?= kv-contoso-iam-prod-pri
SECONDARY_KV ?= kv-contoso-iam-prod-sec

kv-replicate-dry:
	$(PYTHON) scripts/onboarding/kv_replication.py \
		--primary $(PRIMARY_KV) --secondary $(SECONDARY_KV) --dry-run

kv-replicate:
	$(PYTHON) scripts/onboarding/kv_replication.py \
		--primary $(PRIMARY_KV) --secondary $(SECONDARY_KV) \
		--output reports/kv-replication-$$(date +%Y%m%d).json

mfa-audit:
	mkdir -p reports
	$(PYTHON) scripts/audit/mfa_audit.py \
		--output reports/mfa-audit-$$(date +%Y%m%d).json

SOURCE ?= okta
INPUT  ?= migration/export.json

migrate-export:
	mkdir -p migration
	$(PYTHON) scripts/migration/idp_migration.py export \
		--source $(SOURCE) --output migration/$(SOURCE)-export-$$(date +%Y%m%d).json

migrate-import:
	$(PYTHON) scripts/migration/idp_migration.py import \
		--input $(INPUT) --target entra --dry-run

migrate-import-apply:
	$(PYTHON) scripts/migration/idp_migration.py import \
		--input $(INPUT) --target entra \
		--output migration/import-report-$$(date +%Y%m%d).json

# ── Packaging ─────────────────────────────────────────────────────────────────
package:
	mkdir -p dist
	zip -r dist/enterprise-iam-platform-$$(date +%Y%m%d).zip . \
		--exclude "*.tfstate*" \
		--exclude "*/.terraform/*" \
		--exclude "*.tfplan" \
		--exclude "**/__pycache__/*" \
		--exclude "*.pyc" \
		--exclude "manifests/*" \
		--exclude "dist/*" \
		--exclude ".git/*"
	@echo "Package created: dist/enterprise-iam-platform-$$(date +%Y%m%d).zip"

clean:
	find . -type f -name "*.tfplan"    -delete
	find . -type f -name "*.pyc"       -delete
	find . -type d -name "__pycache__" -exec rm -rf {} + 2>/dev/null || true
	find . -type d -name ".terraform"  -exec rm -rf {} + 2>/dev/null || true
	rm -rf dist/ reports/ htmlcov/ .coverage .mypy_cache .ruff_cache
	@echo "Clean complete."
