"""
Dataset loader and tokenizer for BERT sentiment analysis benchmark (P4).
Implements offline vocabulary mapping, WordPiece-style tokenization, and padding.
"""

import json
import re
from pathlib import Path
from typing import List, Dict, Tuple, Any

try:
    import torch
    from torch.utils.data import Dataset, DataLoader
    _HAS_TORCH = True
except ImportError:
    torch = None
    Dataset = object
    DataLoader = None
    _HAS_TORCH = False


def load_vocabulary(vocab_file: str) -> Dict[str, int]:
    """Load token-to-index mapping from vocab.txt."""
    token_to_idx = {}
    with open(vocab_file, "r", encoding="utf-8") as f:
        for idx, line in enumerate(f):
            token = line.strip()
            if token:
                token_to_idx[token] = idx
    return token_to_idx


def tokenize_sequence(
    text: str,
    vocab_map: Dict[str, int],
    max_len: int = 32,
) -> Tuple[List[int], List[int]]:
    """Tokenize raw text, add special tokens [CLS]/[SEP], and pad to fixed length.

    Returns:
        token_ids: List of integer vocabulary indices.
        attention_mask: Binary mask indicating valid tokens (1) vs padding (0).
    """
    pad_id = vocab_map.get("[PAD]", 0)
    unk_id = vocab_map.get("[UNK]", 1)
    cls_id = vocab_map.get("[CLS]", 2)
    sep_id = vocab_map.get("[SEP]", 3)

    # Clean and split into lower-case words
    cleaned_words = re.findall(r"\b\w+\b", text.lower())
    token_ids = [cls_id]

    for word in cleaned_words:
        if len(token_ids) >= max_len - 1:
            break
        token_ids.append(vocab_map.get(word, unk_id))

    token_ids.append(sep_id)
    seq_len = len(token_ids)

    # Create attention mask
    attention_mask = [1] * seq_len + [0] * (max_len - seq_len)
    # Pad sequence
    token_ids = token_ids + [pad_id] * (max_len - seq_len)

    return token_ids[:max_len], attention_mask[:max_len]


class SentimentReviewDataset(Dataset):
    """Text classification dataset for movie/product reviews."""

    def __init__(self, data_dir: str, max_seq_len: int = 32):
        self.data_dir = Path(data_dir)
        self.max_seq_len = max_seq_len
        self.vocab_map = load_vocabulary(str(self.data_dir / "vocab.txt"))

        self.review_entries = []
        reviews_file = self.data_dir / "reviews.jsonl"
        with open(reviews_file, "r", encoding="utf-8") as f:
            for line in f:
                line_str = line.strip()
                if line_str:
                    self.review_entries.append(json.loads(line_str))

    def __len__(self) -> int:
        return len(self.review_entries)

    def __getitem__(self, index: int) -> Tuple[Any, Any, int]:
        entry = self.review_entries[index]
        text = entry.get("text", "")
        target_label = int(entry.get("label", 0))

        token_ids, mask = tokenize_sequence(text, self.vocab_map, self.max_seq_len)

        if _HAS_TORCH:
            return (
                torch.tensor(token_ids, dtype=torch.long),
                torch.tensor(mask, dtype=torch.float32),
                target_label,
            )
        return token_ids, mask, target_label


def get_sentiment_loader(data_dir: str, batch_size: int = 4, shuffle: bool = True):
    """Factory helper to construct iterable sentiment dataset loader."""
    dataset_inst = SentimentReviewDataset(data_dir=data_dir)
    if _HAS_TORCH and DataLoader is not None:
        return DataLoader(dataset_inst, batch_size=batch_size, shuffle=shuffle)
    return dataset_inst
