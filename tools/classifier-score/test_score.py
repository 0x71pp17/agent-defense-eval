import unittest

from score import collect_texts, key, positive_score, score_texts, windows


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


if __name__ == "__main__":
    unittest.main()
