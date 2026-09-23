.PHONY: fmt vet test lint sec eval eval-agentdojo eval-pairs sweep corpus scores

fmt:
	gofmt -w .

vet:
	go vet ./...

test:
	go test -race -cover ./...

lint:
	@test -z "$$(gofmt -l .)" || (echo "gofmt needed:"; gofmt -l .; exit 1)
	go vet ./...
	@command -v golangci-lint >/dev/null 2>&1 && golangci-lint run || echo "golangci-lint not installed; ran gofmt + vet only"

sec:
	@command -v gosec >/dev/null 2>&1 && gosec ./... || echo "gosec not installed; skipping"

eval:
	go run ./cmd/deveval

eval-agentdojo:
	go run ./cmd/deveval -corpus agentdojo

eval-pairs:
	go run ./cmd/deveval -corpus pairs

sweep:
	go run ./cmd/deveval -corpus agentdojo -sweep

corpus:
	pip install -r tools/agentdojo-export/requirements.txt
	cd tools/agentdojo-export && python3 export.py ../../sources/agentdojo/agentdojo-v1.2.json
	cd tools/agentdojo-export && python3 pairs.py ../../sources/agentdojo/agentdojo-v1.2-pairs.json

# Needs torch 2.14.0 (CPU wheel) and tools/classifier-score/requirements.txt. MODEL and LABEL select the classifier.
MODEL ?= protectai/deberta-v3-base-prompt-injection-v2
LABEL ?= INJECTION
scores:
	python3 tools/classifier-score/score.py --corpus sources/agentdojo/agentdojo-v1.2-pairs.json \
		--model $(MODEL) --positive-label $(LABEL) --out scores.json
	go run ./cmd/deveval -corpus pairs -scores scores.json
