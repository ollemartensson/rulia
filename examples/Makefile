SHELL := /bin/bash

ENV_FILE ?= .env
COMPOSE ?= podman-compose --env-file $(ENV_FILE)
WORKFLOW_BASE ?= http://localhost:$${TRAEFIK_HTTP_PORT:-8080}

.PHONY: up down logs seed verify export replay replay-negative ps ui bankid-smoke mainframe-smoke canon-check-julia canon-check-java canon-check sdk-js-example sdk-julia-example sdk-jvm-example sdk-examples test-ui test-flow test-ui-watch test-all

up:
	@test -f $(ENV_FILE) || cp env.example $(ENV_FILE)
	$(COMPOSE) up -d --build

down:
	$(COMPOSE) down --remove-orphans

logs:
	$(COMPOSE) logs -f --tail=200

ps:
	$(COMPOSE) ps

ui:
	@echo "Dialog UI: $(WORKFLOW_BASE)/ui/"

bankid-smoke:
	@curl -fsS "$(WORKFLOW_BASE)/bankid/health"
	@echo

mainframe-smoke:
	@curl -fsS "$(WORKFLOW_BASE)/mainframe/health"
	@echo

seed:
	mkdir -p volumes/tk4/outbox
	cp mainframe/outbox-spec/example_records/sample1.dat volumes/tk4/outbox/seed-$$(date +%s).dat
	@echo "seeded demo/volumes/tk4/outbox/"

verify:
	@python3 -c "import json,os,sys,urllib.request; base=os.environ.get('WORKFLOW_BASE','http://localhost:8080'); runs=json.loads(urllib.request.urlopen(base+'/workflow/runs').read().decode('utf-8')); \
	(runs or (_ for _ in ()).throw(SystemExit('no runs available'))); run=sorted(runs,key=lambda x:x['run_id'])[-1]; \
	print('run_id='+run['run_id']); print('final_pass_digest='+run['final_digest']); print('status='+run['status']); \
	sys.exit(0 if run['status']=='PASS' else 1)"

export:
	@python3 -c "import json,os,urllib.request; base=os.environ.get('WORKFLOW_BASE','http://localhost:8080'); runs=json.loads(urllib.request.urlopen(base+'/workflow/runs').read().decode('utf-8')); \
	run=sorted(runs,key=lambda x:x['run_id'])[-1]; body=json.loads(urllib.request.urlopen(base+'/workflow/bundles/'+run['run_id']+'/export').read().decode('utf-8')); \
	print('run_id='+run['run_id']); print('bundle_path='+body['bundle_path']); print('manifest_digest='+body['manifest_digest'])"

replay:
	@if [ -z "$(BUNDLE)" ]; then echo "BUNDLE is required (e.g. BUNDLE=volumes/bundles/<id>)"; exit 1; fi
	@if [[ "$(BUNDLE)" = /* ]]; then \
		BUNDLE_PATH="$(BUNDLE)"; \
	else \
		BUNDLE_PATH="/app/$(BUNDLE)"; \
	fi; \
	$(COMPOSE) run --rm workflow-host-julia julia --project=. src/replay.jl "$${BUNDLE_PATH}"

replay-negative:
	@if [ -z "$(BUNDLE)" ]; then echo "BUNDLE is required (e.g. BUNDLE=volumes/bundles/<id>)"; exit 1; fi
	@set -euo pipefail; \
	BUNDLE_SRC="$(BUNDLE)"; \
	if [[ "$${BUNDLE_SRC}" != /* ]]; then BUNDLE_SRC="$(CURDIR)/$${BUNDLE_SRC}"; fi; \
	if [[ ! -d "$${BUNDLE_SRC}" ]]; then echo "bundle not found: $${BUNDLE_SRC}"; exit 1; fi; \
	NEG_DIR="$(CURDIR)/volumes/bundles/replay-negative-work"; \
	rm -rf "$${NEG_DIR}"; \
	cp -R "$${BUNDLE_SRC}" "$${NEG_DIR}"; \
	python3 -c "import json,pathlib,sys; bundle=pathlib.Path(sys.argv[1]); manifest=json.loads((bundle/'manifest.json').read_text(encoding='utf-8')); \
chain_rel=manifest.get('ledger_chain_file'); \
(chain_rel or (_ for _ in ()).throw(SystemExit('ledger_chain_file missing in manifest; run audited PII reveal before export'))); \
target=bundle/chain_rel; data=bytearray(target.read_bytes()); \
(data or (_ for _ in ()).throw(SystemExit(f'ledger chain file is empty: {target}'))); data[0] ^= 0x01; target.write_bytes(bytes(data)); print(f'tampered_ledger_chain={target}')" "$${NEG_DIR}"
	@set -euo pipefail; \
	NEG_OUTPUT="$$(mktemp)"; \
	if $(MAKE) replay BUNDLE=volumes/bundles/replay-negative-work >"$${NEG_OUTPUT}" 2>&1; then \
		cat "$${NEG_OUTPUT}"; \
		rm -f "$${NEG_OUTPUT}"; \
		echo "replay-negative failed: replay unexpectedly succeeded"; \
		exit 1; \
	else \
		cat "$${NEG_OUTPUT}"; \
		grep -q "step_id=PII-AUDIT step_type=pii_audit_chain_verify" "$${NEG_OUTPUT}" || { rm -f "$${NEG_OUTPUT}"; echo "expected failure at PII-AUDIT pii_audit_chain_verify"; exit 1; }; \
		rm -f "$${NEG_OUTPUT}"; \
		echo "expected failure: tampering detected at PII-AUDIT pii_audit_chain_verify"; \
	fi

canon-check-julia:
	cd services/workflow-host-julia && julia --project=. src/canon_verify.jl

canon-check-java:
	cd services/java-services/audit-ledger && gradle --no-daemon canonVerify

sdk-js-example:
	@if [ ! -f ../sdk/javascript/rulia-js/dist/index.js ]; then \
		cd ../sdk/javascript/rulia-js && npm ci && npm run build; \
	fi
	node sdk/javascript/surface-demo.cjs

sdk-julia-example:
	@if [ -z "$$RULIA_LIB_PATH" ] && [ -z "$$RULIA_MANIFEST_URL" ]; then \
		echo "skipping Julia SDK example: set RULIA_LIB_PATH or RULIA_MANIFEST_URL"; \
	else \
		cd ../sdk/julia/Rulia.jl && julia --project=. -e 'using Pkg; Pkg.instantiate()'; \
		julia --project=../sdk/julia/Rulia.jl sdk/julia/surface_demo.jl; \
	fi

sdk-jvm-example:
	@if [ -z "$$RULIA_LIB_PATH" ] && [ -z "$$RULIA_MANIFEST_URL" ]; then \
		echo "skipping JVM SDK example: set RULIA_LIB_PATH or RULIA_MANIFEST_URL"; \
	else \
		cd sdk/jvm && ../../../sdk/jvm/gradlew --no-daemon -p . run; \
	fi

sdk-examples: sdk-js-example sdk-julia-example sdk-jvm-example

canon-check: canon-check-julia canon-check-java sdk-examples
test-ui:
	cd tests/playwright && npm ci
	cd tests/playwright && npx playwright install chromium
	cd tests/playwright && npx playwright test

test-flow:
	cd tests/playwright && npm ci
	cd tests/playwright && npx playwright install chromium
	cd tests/playwright && npx playwright test flow/shared-account-flow.mock.spec.ts

test-ui-watch:
	cd tests/playwright && npm ci
	cd tests/playwright && npx playwright install chromium
	cd tests/playwright && npx playwright test --ui

test-all: canon-check bankid-smoke test-ui test-flow
