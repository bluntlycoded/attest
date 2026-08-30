# One command per thing you might actually want to do.
.PHONY: help install test bench frontier delegation api console demo clean

# Not every system has a bare `python`; plenty only have `python3`. Resolving
# it here rather than assuming is the difference between this working on
# someone else's machine and not.
PYTHON   ?= $(shell command -v python3 || command -v python)
PIP      ?= $(PYTHON) -m pip
PORT     ?= 8317
CURL     := curl -s -H "Authorization: Bearer $(ATTEST_BOOTSTRAP_KEY)"

help:
	@echo "install     install the library, service and dev extras"
	@echo "test        run the full suite"
	@echo "bench       compare the four policies on generated sessions"
	@echo "frontier    the budget-exposure sweep"
	@echo "delegation  chain-aware against chain-blind scheduling"
	@echo "api         run the service (set ATTEST_BOOTSTRAP_KEY first)"
	@echo "console     run the dashboard"
	@echo "demo        seed a running service with live traffic and two holds"

install:
	$(PIP) install -e ".[dev]"
	cd console && npm ci

test:
	$(PYTHON) -m pytest tests -q

bench:
	$(PYTHON) -m attest.cli bench --sessions 400 --ci

frontier:
	$(PYTHON) -m attest.cli frontier --sessions 400

delegation:
	$(PYTHON) -m attest.cli delegation

api:
	@test -n "$(ATTEST_BOOTSTRAP_KEY)" || \
	  (echo "ATTEST_BOOTSTRAP_KEY is unset. The service refuses every request without it." && \
	   echo "  export ATTEST_BOOTSTRAP_KEY=\"$$(openssl rand -base64 32)\"" && exit 1)
	$(PYTHON) -m uvicorn service.app:app --port $(PORT)

console:
	cd console && npm run dev

# Seeds a service that is already running. Wall-clock timestamps throughout,
# so nothing in the queue reads as already expired.
demo:
	@test -n "$(ATTEST_BOOTSTRAP_KEY)" || (echo "set ATTEST_BOOTSTRAP_KEY to the key the service was started with" && exit 1)
	@$(CURL) -X POST localhost:$(PORT)/reset > /dev/null
	@$(CURL) -X POST localhost:$(PORT)/feed/start -H 'Content-Type: application/json' \
	  -d '{"agents":14,"steps_per_second":40,"seed":7,"auto_tune":true}' > /dev/null
	@$(PYTHON) -c "import time; print(time.time())" > /tmp/.attest_t0
	@for i in $$(seq 0 55); do \
	  $(CURL) -X POST localhost:$(PORT)/gateway/evaluate -H 'Content-Type: application/json' \
	    -d "{\"agent_id\":\"svc-billing\",\"tool\":\"search\",\"resource\":\"docs/api\",\"timestamp\":$$($(PYTHON) -c "print($$(cat /tmp/.attest_t0)+$$i)")}" > /dev/null; \
	done
	@$(CURL) -X POST localhost:$(PORT)/gateway/evaluate -H 'Content-Type: application/json' \
	  -d "{\"agent_id\":\"svc-billing\",\"tool\":\"wire_transfer\",\"resource\":\"acct-9912\",\"arguments\":{\"amount\":50000},\"intent\":\"pay_invoice\",\"timestamp\":$$($(PYTHON) -c "print($$(cat /tmp/.attest_t0)+100)")}" > /dev/null
	@$(CURL) -X POST localhost:$(PORT)/gateway/evaluate -H 'Content-Type: application/json' \
	  -d "{\"agent_id\":\"svc-reporting\",\"tool\":\"undeclared_tool\",\"timestamp\":$$($(PYTHON) -c "print($$(cat /tmp/.attest_t0)+101)")}" > /dev/null
	@echo "seeded. live traffic running, two actions held for a person."
	@echo "open http://localhost:3317/approvals"

clean:
	rm -f attest.db attest.db-wal attest.db-shm
	rm -rf console/.next .pytest_cache
	find . -name __pycache__ -type d -prune -exec rm -rf {} +
