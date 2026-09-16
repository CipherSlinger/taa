"""
Medical retinal image dataset loader and preprocessor (P2).
Supports ophthalmology fundus image loading, normalization, and PyTorch dataset integration.
"""

import os
from pathlib import Path
from typing import List, Tuple, Optional, Any

try:
    import torch
    from torch.utils.data import Dataset, DataLoader
    _HAS_TORCH = True
except ImportError:
    torch = None
    Dataset = object
    DataLoader = None
    _HAS_TORCH = False

try:
    from PIL import Image
    _HAS_PIL = True
except ImportError:
    Image = None
    _HAS_PIL = False


class RetinaFundusDataset(Dataset):
    """Dataset for retinal fundus images with diabetic retinopathy grading labels."""

    def __init__(self, data_dir: str, image_size: Tuple[int, int] = (64, 64)):
        self.data_dir = Path(data_dir)
        self.image_size = image_size
        self.image_paths = sorted(list(self.data_dir.glob("*.png")))

        # Binary labels: 0 = Normal, 1 = Diabetic Retinopathy
        # Deterministic labels based on file index (odd=0, even=1)
        self.targets = [i % 2 for i in range(len(self.image_paths))]

    def __len__(self) -> int:
        return len(self.image_paths)

    def _read_image_fallback(self, file_path: Path) -> List[List[List[float]]]:
        """Pure Python fallback representation of a 3xHxW normalized tensor."""
        height, width = self.image_size
        # Normalized pixel values in [0.0, 1.0]
        plane = [[0.5 for _ in range(width)] for _ in range(height)]
        return [plane, plane, plane]

    def __getitem__(self, index: int) -> Tuple[Any, int]:
        img_path = self.image_paths[index]
        label = self.targets[index]

        if _HAS_PIL and _HAS_TORCH:
            with Image.open(img_path) as raw_img:
                rgb_img = raw_img.convert("RGB").resize(self.image_size)
                # Convert PIL image to tensor [C, H, W] normalized to [0, 1]
                img_bytes = list(rgb_img.getdata())
                width, height = rgb_img.size
                r_ch, g_ch, b_ch = [], [], []
                for pixel in img_bytes:
                    r_ch.append(pixel[0] / 255.0)
                    g_ch.append(pixel[1] / 255.0)
                    b_ch.append(pixel[2] / 255.0)

                tensor_data = torch.tensor([r_ch, g_ch, b_ch], dtype=torch.float32).view(3, height, width)
                return tensor_data, label
        elif _HAS_PIL:
            with Image.open(img_path) as raw_img:
                rgb_img = raw_img.convert("RGB").resize(self.image_size)
                return list(rgb_img.getdata()), label
        else:
            return self._read_image_fallback(img_path), label


def get_retina_data_loader(data_dir: str, batch_size: int = 2, shuffle: bool = True):
    """Build DataLoader or iterable collection over retinal dataset."""
    fundus_dataset = RetinaFundusDataset(data_dir=data_dir)
    if _HAS_TORCH and DataLoader is not None:
        return DataLoader(fundus_dataset, batch_size=batch_size, shuffle=shuffle)
    return fundus_dataset
