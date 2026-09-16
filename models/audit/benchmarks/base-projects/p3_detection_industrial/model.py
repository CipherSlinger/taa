"""
Industrial defect detector architecture (P3).
Implements a lightweight single-stage feature extraction backbone with decoupled
classification and bounding box regression heads.
Permissive Apache-2.0 license (completely free of AGPL dependencies).
"""

from typing import Dict, Any, Tuple, Optional, List

try:
    import torch
    import torch.nn as nn
    _HAS_TORCH = True
except ImportError:
    torch = None
    nn = None
    _HAS_TORCH = False


if _HAS_TORCH:
    class ConvBlock(nn.Module):
        """Standard Conv-BatchNorm-LeakyReLU module."""

        def __init__(self, in_c: int, out_c: int, stride: int = 1):
            super().__init__()
            self.conv = nn.Conv2d(in_c, out_c, kernel_size=3, stride=stride, padding=1, bias=False)
            self.bn = nn.BatchNorm2d(out_c)
            self.act = nn.LeakyReLU(0.1, inplace=True)

        def forward(self, x):
            return self.act(self.bn(self.conv(x)))

    class IndustrialDefectDetector(nn.Module):
        """Lightweight fully-convolutional surface defect detector.

        Features decoupled heads for multi-class classification and offset regression.
        """

        def __init__(self, num_classes: int = 3, in_channels: int = 3):
            super().__init__()
            self.num_classes = num_classes

            # Backbone feature extractor
            self.stem = ConvBlock(in_channels, 16, stride=1)
            self.stage1 = ConvBlock(16, 32, stride=2)
            self.stage2 = ConvBlock(32, 64, stride=2)

            # Decoupled detection heads
            self.cls_head = nn.Sequential(
                ConvBlock(64, 32, stride=1),
                nn.Conv2d(32, num_classes, kernel_size=1),
            )
            self.reg_head = nn.Sequential(
                ConvBlock(64, 32, stride=1),
                nn.Conv2d(32, 4, kernel_size=1),
            )

        def forward(self, x) -> Tuple[Any, Any]:
            feat = self.stage2(self.stage1(self.stem(x)))
            cls_scores = self.cls_head(feat)
            reg_offsets = self.reg_head(feat)
            return cls_scores, reg_offsets

else:
    class IndustrialDefectDetector:
        """Fallback detector stub for pure Python environments without PyTorch."""

        def __init__(self, num_classes: int = 3, in_channels: int = 3):
            self.num_classes = num_classes
            self.in_channels = in_channels

        def set_eval_mode(self):
            return self

        def set_train_mode(self, mode: bool = True):
            return self

        def forward(self, x):
            return {"cls_scores": [[0.0] * self.num_classes], "reg_offsets": [[0.0, 0.0, 1.0, 1.0]]}

        def state_dict(self) -> Dict[str, Any]:
            return {"architecture": "IndustrialDefectDetector", "num_classes": self.num_classes}

        def load_state_dict(self, state_dict: Dict[str, Any]):
            pass


def build_defect_detector(num_classes: int = 3) -> Any:
    """Build defect detection model instance."""
    return IndustrialDefectDetector(num_classes=num_classes)
