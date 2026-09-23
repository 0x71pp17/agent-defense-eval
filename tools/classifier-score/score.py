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
import platform
import sys


def key(text):
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def collect_texts(corpus):
    """Return {key: text} for every tool output some call reads as context, and
    every call's argument text."""
    texts = {}
    outputs = corpus["outputs"]
    for scenario in corpus["scenarios"]:
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
    for i in range(0, len(pending), batch):
        chunk = pending[i:i + batch]
        results = classify([w for _, w in chunk])
        for (k, _), result in zip(chunk, results):
            scores[k] = max(scores.get(k, 0.0), positive_score(result, label))
    return scores


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--corpus", required=True)
    ap.add_argument("--list-keys", action="store_true",
                    help="print the sorted keys of the texts to score, then exit")
    ap.add_argument("--model", help="Hugging Face model id")
    ap.add_argument("--positive-label", help="label meaning injection")
    ap.add_argument("--out")
    ap.add_argument("--stride", type=int, default=256, help="window advance in tokens")
    ap.add_argument("--batch", type=int, default=16)
    args = ap.parse_args(argv)

    if args.list_keys:
        with open(args.corpus) as f:
            print("\n".join(sorted(collect_texts(json.load(f)))))
        return
    if not (args.model and args.positive_label and args.out):
        ap.error("--model, --positive-label and --out are required unless --list-keys is given")

    import torch
    import transformers
    from transformers import AutoModelForSequenceClassification, AutoTokenizer, pipeline

    tokenizer = AutoTokenizer.from_pretrained(args.model)
    model = AutoModelForSequenceClassification.from_pretrained(args.model)
    size = tokenizer.model_max_length - tokenizer.num_special_tokens_to_add()
    classify = pipeline("text-classification", model=model, tokenizer=tokenizer,
                        top_k=None, truncation=True, device=-1)

    with open(args.corpus) as f:
        corpus = json.load(f)
    texts = collect_texts(corpus)
    print(f"scoring {len(texts)} distinct texts with {args.model}", file=sys.stderr)
    scores = score_texts(texts, classify, tokenizer, args.positive_label, size, args.stride, args.batch)

    table = {
        "model": args.model,
        "revision": getattr(model.config, "_commit_hash", "") or "",
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
