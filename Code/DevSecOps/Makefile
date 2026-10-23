SHELL := /bin/bash
.DEFAULT_GOAL := help

PYTHON ?= python3
VENV ?= .venv
VENV_BIN := $(abspath $(VENV))/bin
VENV_PYTHON := $(VENV_BIN)/python
RUNS ?= 3
PHASE ?= baseline
INCLUDE_IMAGE ?= 0
PROJECT_ROOT := $(CURDIR)
REPOSITORY_ROOT := $(abspath ../..)
IMAGE_FLAG := $(if $(filter 1 true yes,$(INCLUDE_IMAGE)),--include-image,)
EXCEPTION_DATA := $(if $(wildcard policy/exceptions.json),--data policy/exceptions.json,)

export PATH := $(VENV_BIN):$(PATH)

.PHONY: help bootstrap check-tools scan-all summarize gate fix measure benchmark

help:
	@printf '%s\n' \
	  'bootstrap   Create .venv and install pinned Semgrep/Checkov CLIs' \
	  'check-tools Check external scanner and container prerequisites' \
	  'scan-all    Run the local scanner pipeline and write reports' \
	  'summarize   Normalize scanner JSON into reports/summary.json' \
	  'gate        Evaluate g0, g1, and g2 against the normalized report' \
	  'fix         Apply all ground-truth remediation patches' \
	  'measure     Repeat scanner timings (PHASE=baseline|after-fix RUNS=3)' \
	  'benchmark   Compare sequential and GNU Parallel scans (RUNS=3)'

bootstrap:
	$(PYTHON) -m venv $(VENV)
	"$(VENV_PYTHON)" -m pip install --disable-pip-version-check --upgrade pip
	"$(VENV_PYTHON)" -m pip install --disable-pip-version-check semgrep==1.179.0 checkov==3.3.30

check-tools:
	@for tool in docker gitleaks trivy conftest syft cosign parallel; do \
	  command -v "$$tool" >/dev/null 2>&1 || { echo "Missing required CLI: $$tool" >&2; exit 1; }; \
	done
	@"$(VENV_PYTHON)" -c 'import sys; print("Python", sys.version.split()[0])'

scan-all:
	bash tools/test/run_pipeline_metrics.sh

summarize:
	$(PYTHON) tools/test/summarize.py --results tests/results/raw --output-dir reports \
	  --exceptions policy/exceptions.json

gate:
	conftest test reports/summary.json --policy policy/g0 --all-namespaces
	conftest test reports/summary.json --policy policy/g1 --policy rules/conftest \
	  $(EXCEPTION_DATA) --all-namespaces
	conftest test reports/summary.json --policy policy/g2 --policy rules/conftest \
	  $(EXCEPTION_DATA) --all-namespaces

fix:
	git -C "$(REPOSITORY_ROOT)" apply --check "$(PROJECT_ROOT)/ground_truth/patches/fix_sast.patch"
	git -C "$(REPOSITORY_ROOT)" apply --check "$(PROJECT_ROOT)/ground_truth/patches/fix_secret.patch"
	git -C "$(REPOSITORY_ROOT)" apply --check "$(PROJECT_ROOT)/ground_truth/patches/fix_docker.patch"
	git -C "$(REPOSITORY_ROOT)" apply --check "$(PROJECT_ROOT)/ground_truth/patches/fix_infra.patch"
	git -C "$(REPOSITORY_ROOT)" apply "$(PROJECT_ROOT)/ground_truth/patches/fix_sast.patch"
	git -C "$(REPOSITORY_ROOT)" apply "$(PROJECT_ROOT)/ground_truth/patches/fix_secret.patch"
	git -C "$(REPOSITORY_ROOT)" apply "$(PROJECT_ROOT)/ground_truth/patches/fix_docker.patch"
	git -C "$(REPOSITORY_ROOT)" apply "$(PROJECT_ROOT)/ground_truth/patches/fix_infra.patch"

measure:
	$(PYTHON) tools/test/measure_pipeline.py --$(PHASE) --runs $(RUNS) $(IMAGE_FLAG)

benchmark:
	bash tools/test/benchmark_parallel.sh --$(PHASE) --runs $(RUNS)
