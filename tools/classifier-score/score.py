"""Score a paired corpus's texts with a prompt-injection classifier.

Collects every text a Classifier defense can judge: each distinct tool output
that some call reads as context, and each call's arguments joined by newlines. Each text is split into
overlapping token windows the model can accept; its score is the maximum
probability of the positive label across windows. Empty texts score 0.

Writes a score table keyed by the hex SHA-256 of each text, with the model's
commit hash, the positive label, the chunking parameters, and library versions.
"""

import argparse
import hashlib
import json
import os
import platform
import sys
import time

REGISTRY = os.path.join(os.path.dirname(os.path.abspath(__file__)), "models.json")


def key(text):
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def collect_texts(corpus, benign_only=False):
    """Return {key: text} for every tool output some call reads as context, and
    every call's argument text. With benign_only, only benign scenarios count."""
    texts = {}
    outputs = corpus["outputs"]
    for scenario in corpus["scenarios"]:
        if benign_only and scenario.get("kind") != "benign":
            continue
        for step in scenario["trace"]:
            for h in step["context"]:
                texts[key(outputs[h])] = outputs[h]
            if step["args"]:
                text = "\n".join(a["text"] for a in step["args"])
                texts[key(text)] = text
    return texts


def windows(text, tokenizer, size, stride):
    """Split text into windows of at most `size` tokens, advancing by `stride`."""
    enc = tokenizer(text, add_special_tokens=False, return_offsets_mapping=True)
    offsets = enc["offset_mapping"]
    if len(offsets) <= size:
        return [text]
    out = []
    start = 0
    while True:
        span = offsets[start:start + size]
        out.append(text[span[0][0]:span[-1][1]])
        if start + size >= len(offsets):
            return out
        start += stride


def registry_entry(key, path=REGISTRY):
    """Return the registry's model id, positive label, and revision for a key.
    An empty revision loads the model's default branch."""
    with open(path) as f:
        registry = json.load(f)
    if key not in registry:
        raise SystemExit(f"unknown model key {key!r}; known keys are {sorted(registry)}")
    entry = registry[key]
    return entry["model"], entry["positive_label"], entry.get("revision", "")


def load_texts(corpus_path, benign_corpus_path=None):
    """Collect the texts to score from a corpus, plus the benign scenarios of a
    second corpus when given."""
    with open(corpus_path) as f:
        texts = collect_texts(json.load(f))
    if benign_corpus_path:
        with open(benign_corpus_path) as f:
            texts.update(collect_texts(json.load(f), benign_only=True))
    return texts


def window_limit(model_max_length, max_positions, special_tokens, cap=None):
    """Return the window size in tokens: the smallest of the tokenizer's declared
    limit, the model's position embeddings, and the cap, less the special tokens.
    A tokenizer that declares no limit reports a very large placeholder, so values
    outside a plausible range are ignored."""
    limits = [x for x in (model_max_length, max_positions, cap) if isinstance(x, int) and 0 < x <= 100_000]
    if not limits:
        raise SystemExit("cannot determine the model's input limit from its tokenizer or config")
    return min(limits) - special_tokens


def positive_score(result, label):
    for item in result:
        if item["label"] == label:
            return item["score"]
    labels = sorted(item["label"] for item in result)
    raise SystemExit(f"positive label {label!r} not produced by the model; its labels are {labels}")


def score_texts(texts, classify, tokenizer, label, size, stride, batch):
    scores = {}
    pending = []  # (key, window text)
    for k, text in texts.items():
        if text == "":
            scores[k] = 0.0
            continue
        for w in windows(text, tokenizer, size, stride):
            pending.append((k, w))
    print(f"{len(texts)} texts, {len(pending)} windows of at most {size} tokens",
          file=sys.stderr, flush=True)
    start = time.monotonic()
    for i in range(0, len(pending), batch):
        chunk = pending[i:i + batch]
        results = classify([w for _, w in chunk])
        for (k, _), result in zip(chunk, results):
            scores[k] = max(scores.get(k, 0.0), positive_score(result, label))
        done = i + len(chunk)
        if done == len(pending) or (i // batch) % 10 == 0:
            print(f"scored {done}/{len(pending)} windows, {time.monotonic() - start:.0f}s",
                  file=sys.stderr, flush=True)
    return scores


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--corpus", required=True)
    ap.add_argument("--benign-corpus",
                    help="a corpus whose benign scenarios are scored too, for corpora that reuse its benign tasks")
    ap.add_argument("--list-keys", action="store_true",
                    help="print the sorted keys of the texts to score, then exit")
    ap.add_argument("--model-key", help="a key in models.json; sets --model, --positive-label, and --revision")
    ap.add_argument("--model", help="Hugging Face model id")
    ap.add_argument("--positive-label", help="label meaning injection")
    ap.add_argument("--out")
    ap.add_argument("--revision", default="",
                    help="model commit, branch, or tag to load; empty loads the default branch")
    ap.add_argument("--max-window", type=int, default=512,
                    help="cap on window length in tokens, including special tokens")
    ap.add_argument("--stride", type=int, default=256, help="window advance in tokens")
    ap.add_argument("--batch", type=int, default=16)
    args = ap.parse_args(argv)

    if args.list_keys:
        print("\n".join(sorted(load_texts(args.corpus, args.benign_corpus))))
        return
    if args.model_key:
        args.model, args.positive_label, args.revision = registry_entry(args.model_key)
    if not (args.model and args.positive_label and args.out):
        ap.error("--model-key or --model and --positive-label, plus --out, are required unless --list-keys is given")

    import torch
    import transformers
    from transformers import AutoModelForSequenceClassification, AutoTokenizer, pipeline

    # Weights load only from safetensors, and no repository code runs: pickle
    # weights and remote code can execute during loading.
    load = {"revision": args.revision or None, "trust_remote_code": False}
    tokenizer = AutoTokenizer.from_pretrained(args.model, **load)
    model = AutoModelForSequenceClassification.from_pretrained(args.model, use_safetensors=True, **load)
    print(f"model labels: {model.config.id2label}", file=sys.stderr, flush=True)
    special = tokenizer.num_special_tokens_to_add()
    size = window_limit(tokenizer.model_max_length,
                        getattr(model.config, "max_position_embeddings", None), special,
                        cap=args.max_window)
    classify = pipeline("text-classification", model=model, tokenizer=tokenizer,
                        top_k=None, truncation=True, max_length=size + special, device=-1)

    texts = load_texts(args.corpus, args.benign_corpus)
    print(f"scoring {len(texts)} distinct texts with {args.model}", file=sys.stderr)
    scores = score_texts(texts, classify, tokenizer, args.positive_label, size, args.stride, args.batch)

    table = {
        "model": args.model,
        "revision": getattr(model.config, "_commit_hash", "") or "",
        "requested_revision": args.revision,
        "positive_label": args.positive_label,
        "chunking": {"window_tokens": size, "stride_tokens": args.stride},
        "runtime": {"python": platform.python_version(), "torch": torch.__version__,
                    "transformers": transformers.__version__},
        "scores": scores,
    }
    with open(args.out, "w") as f:
        json.dump(table, f, sort_keys=True, indent=1)
    print(f"wrote {len(scores)} scores to {args.out}", file=sys.stderr)


if __name__ == "__main__":
    main()
