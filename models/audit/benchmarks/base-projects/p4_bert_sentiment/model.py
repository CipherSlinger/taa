"""
Transformer sentiment classification model (P4).
Implements token embeddings, positional encodings, bidirectional Transformer
encoder layers, and pooled sequence classification head.
"""

import math
from typing import Dict, Any, Optional

try:
    import torch
    import torch.nn as nn
    _HAS_TORCH = True
except ImportError:
    torch = None
    nn = None
    _HAS_TORCH = False


if _HAS_TORCH:
    class PositionalEncoding(nn.Module):
        """Sinusoidal positional encoding for sequence tokens."""

        def __init__(self, d_model: int, max_len: int = 128):
            super().__init__()
            pe = torch.zeros(max_len, d_model)
            position = torch.arange(0, max_len, dtype=torch.float).unsqueeze(1)
            div_term = torch.exp(torch.arange(0, d_model, 2).float() * (-math.log(10000.0) / d_model))
            pe[:, 0::2] = torch.sin(position * div_term)
            pe[:, 1::2] = torch.cos(position * div_term)
            self.register_buffer("pe", pe.unsqueeze(0))

        def forward(self, x):
            return x + self.pe[:, :x.size(1), :]

    class TransformerSentimentClassifier(nn.Module):
        """Miniature BERT-style Transformer for binary sentiment classification."""

        def __init__(
            self,
            vocab_size: int = 2000,
            hidden_dim: int = 64,
            num_heads: int = 4,
            num_layers: int = 2,
            num_classes: int = 2,
            max_seq_len: int = 64,
            dropout_rate: float = 0.1,
        ):
            super().__init__()
            self.token_embeddings = nn.Embedding(vocab_size, hidden_dim, padding_idx=0)
            self.pos_encoder = PositionalEncoding(hidden_dim, max_len=max_seq_len)

            encoder_layer = nn.TransformerEncoderLayer(
                d_model=hidden_dim,
                nhead=num_heads,
                dim_feedforward=hidden_dim * 4,
                dropout=dropout_rate,
                batch_first=True,
            )
            self.transformer_encoder = nn.TransformerEncoder(encoder_layer, num_layers=num_layers)
            self.layer_norm = nn.LayerNorm(hidden_dim)

            # Sequence classifier pooling head
            self.classifier_head = nn.Sequential(
                nn.Linear(hidden_dim, hidden_dim),
                nn.Tanh(),
                nn.Dropout(dropout_rate),
                nn.Linear(hidden_dim, num_classes),
            )

        def forward(self, input_token_ids, attention_mask=None):
            x = self.token_embeddings(input_token_ids)
            x = self.pos_encoder(x)

            # Build attention mask for padding if provided
            src_key_padding_mask = None
            if attention_mask is not None:
                src_key_padding_mask = (attention_mask == 0)

            encoded = self.transformer_encoder(x, src_key_padding_mask=src_key_padding_mask)
            encoded = self.layer_norm(encoded)

            # Pool at the [CLS] representation (index 0)
            cls_repr = encoded[:, 0, :]
            logits = self.classifier_head(cls_repr)
            return logits

else:
    class TransformerSentimentClassifier:
        """Standalone fallback classifier for dependency-free environments."""

        def __init__(self, vocab_size: int = 2000, hidden_dim: int = 64, num_classes: int = 2):
            self.vocab_size = vocab_size
            self.num_classes = num_classes

        def set_eval_mode(self):
            return self

        def set_train_mode(self, mode: bool = True):
            return self

        def forward(self, input_token_ids, attention_mask=None):
            batch_len = len(input_token_ids)
            return [[0.5, 0.5] for _ in range(batch_len)]

        def state_dict(self) -> Dict[str, Any]:
            return {"architecture": "TransformerSentimentClassifier", "vocab_size": self.vocab_size}

        def load_state_dict(self, state_dict: Dict[str, Any]):
            pass


def build_sentiment_transformer(vocab_size: int = 5000, num_classes: int = 2) -> Any:
    """Build sentiment transformer model instance."""
    return TransformerSentimentClassifier(vocab_size=vocab_size, num_classes=num_classes)
