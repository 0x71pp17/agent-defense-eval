import unittest

import os

from score import REGISTRY, collect_texts, key, positive_score, registry_entry, score_texts, window_limit, windows


class WordTokenizer:
    """Stand-in tokenizer: one token per whitespace-separated word."""

    def __call__(self, text, add_special_tokens=False, return_offsets_mapping=True):
        offsets, pos = [], 0
        for word in text.split():
            start = text.index(word, pos)
            offsets.append((start, start + len(word)))
            pos = start + len(word)
        return {"offset_mapping": offsets}


class ScoreTests(unittest.TestCase):
    def test_short_text_is_one_window(self):
        self.assertEqual(windows("a b c", WordTokenizer(), 5, 2), ["a b c"])

    def test_windows_overlap_and_cover_the_end(self):
        w = windows("a b c d e f g", WordTokenizer(), 3, 2)
        self.assertEqual(w, ["a b c", "c d e", "e f g"])

    def test_collect_matches_go_args_text(self):
        corpus = {"outputs": {"h": "tool output", "u": "never read"},
                  "scenarios": [{"trace": [
                      {"context": [], "args": [{"text": "US13"}, {"text": "0.01"}]},
                      {"context": ["h"], "args": []}]}]}
        texts = collect_texts(corpus)
        self.assertIn(key("US13\n0.01"), texts)
        self.assertIn(key("tool output"), texts)
        self.assertNotIn(key("never read"), texts)
        self.assertEqual(len(texts), 2)

    def test_benign_only_skips_injection_scenarios(self):
        corpus = {"outputs": {"b": "benign read", "i": "injected read"},
                  "scenarios": [
                      {"kind": "benign", "trace": [{"context": ["b"], "args": []}]},
                      {"kind": "injection", "trace": [{"context": ["i"], "args": []}]}]}
        self.assertEqual(set(collect_texts(corpus, benign_only=True)), {key("benign read")})
        self.assertEqual(len(collect_texts(corpus)), 2)

    def test_score_is_max_over_windows_and_empty_is_zero(self):
        def classify(batch):
            return [[{"label": "INJECTION", "score": 0.9 if "x" in w else 0.1},
                     {"label": "SAFE", "score": 0.0}] for w in batch]
        texts = {"k1": "a b x d e", "k2": ""}
        s = score_texts(texts, classify, WordTokenizer(), "INJECTION", 2, 2, 4)
        self.assertEqual(s["k1"], 0.9)
        self.assertEqual(s["k2"], 0.0)

    def test_wrong_label_fails_loudly(self):
        with self.assertRaises(SystemExit):
            positive_score([{"label": "SAFE", "score": 1.0}], "INJECTION")


class LimitTests(unittest.TestCase):
    def test_placeholder_tokenizer_limit_falls_back_to_model_positions(self):
        self.assertEqual(window_limit(1000000000000000019884624838656, 512, 2), 510)

    def test_smaller_of_declared_limits_wins(self):
        self.assertEqual(window_limit(256, 512, 2), 254)

    def test_cap_limits_long_context_models(self):
        self.assertEqual(window_limit(8192, 8192, 2, cap=512), 510)

    def test_cap_above_model_limit_has_no_effect(self):
        self.assertEqual(window_limit(512, 512, 2, cap=8192), 510)

    def test_no_usable_limit_fails_loudly(self):
        with self.assertRaises(SystemExit):
            window_limit(10**30, None, 2)


class RegistryTests(unittest.TestCase):
    def test_entry_resolves_model_label_and_revision(self):
        model, label, revision = registry_entry("protectai")
        self.assertEqual(model, "protectai/deberta-v3-base-prompt-injection-v2")
        self.assertEqual(label, "INJECTION")
        self.assertEqual(revision, "90c9989b1a342275dd0d1a95aad283c04e075671")

    def test_unknown_key_fails_loudly(self):
        with self.assertRaises(SystemExit):
            registry_entry("no-such-model")

    def test_workflow_choices_match_registry(self):
        import json

        import yaml
        with open(REGISTRY) as f:
            registry = sorted(json.load(f))
        workflows = os.path.join(os.path.dirname(REGISTRY), "..", "..", ".github", "workflows")
        for name in ("classifier-baseline.yml", "classifier-coverage.yml"):
            with open(os.path.join(workflows, name)) as f:
                doc = yaml.safe_load(f)
            # PyYAML reads the bare key "on" as True.
            triggers = doc.get("on", doc.get(True))
            choices = triggers["workflow_dispatch"]["inputs"]["model"]["options"]
            self.assertEqual(sorted(choices), registry, name)


if __name__ == "__main__":
    unittest.main()
