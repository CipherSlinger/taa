"""
Industrial surface defect detection dataset loader (P3).
Loads defect images and parses annotations.yaml with bbox targets.
Licensed under Apache-2.0 / BSD-3-Clause permissive terms.
"""

import os
import re
from pathlib import Path
from typing import List, Dict, Any, Tuple, Optional

try:
    import yaml
    _HAS_YAML = True
except ImportError:
    yaml = None
    _HAS_YAML = False

try:
    import torch
    from torch.utils.data import Dataset
    _HAS_TORCH = True
except ImportError:
    torch = None
    Dataset = object
    _HAS_TORCH = False

try:
    from PIL import Image
    _HAS_PIL = True
except ImportError:
    Image = None
    _HAS_PIL = False


def parse_annotations_fallback(yaml_path: Path) -> Dict[str, Any]:
    """Lightweight fallback parser for annotations.yaml when PyYAML is unavailable."""
    with open(yaml_path, "r", encoding="utf-8") as f:
        text = f.read()

    samples = []
    current_sample = None
    for line in text.splitlines():
        line_clean = line.strip()
        if not line_clean or line_clean.startswith("#"):
            continue
        if line_clean.startswith("- filename:"):
            fn = line_clean.split(":", 1)[1].strip()
            current_sample = {"filename": fn, "objects": []}
            samples.append(current_sample)
        elif line_clean.startswith("bbox:") and current_sample is not None:
            # Parse [x1, y1, x2, y2]
            match = re.search(r"\[([\d\s,]+)\]", line_clean)
            if match:
                coords = [int(v.strip()) for v in match.group(1).split(",")]
                current_sample["objects"].append({"bbox": coords, "category_id": 1})

    return {"samples": samples}


def load_defect_annotations(yaml_path: str) -> List[Dict[str, Any]]:
    """Parse annotation file into structured defect records."""
    yp = Path(yaml_path)
    if not yp.is_file():
        return []

    if _HAS_YAML:
        with open(yp, "r", encoding="utf-8") as f:
            ann_data = yaml.safe_load(f)
    else:
        ann_data = parse_annotations_fallback(yp)

    return ann_data.get("samples", [])


class DefectDetectionDataset(Dataset):
    """Surface defect detection dataset returning image tensors and bounding boxes."""

    def __init__(self, data_dir: str, image_size: Tuple[int, int] = (64, 64)):
        self.data_dir = Path(data_dir)
        self.image_size = image_size
        self.annotation_records = load_defect_annotations(str(self.data_dir / "annotations.yaml"))

    def __len__(self) -> int:
        return len(self.annotation_records)

    def __getitem__(self, index: int) -> Tuple[Any, Dict[str, Any]]:
        record = self.annotation_records[index]
        img_path = self.data_dir / record.get("filename", f"defect_{index+1:02d}.png")

        # Parse target boxes and labels
        boxes_list = []
        labels_list = []
        for obj in record.get("objects", []):
            boxes_list.append(obj.get("bbox", [0, 0, 10, 10]))
            labels_list.append(obj.get("category_id", 1))

        if not boxes_list:
            boxes_list = [[0, 0, 10, 10]]
            labels_list = [1]

        target_dict = {
            "boxes": boxes_list,
            "labels": labels_list,
        }

        if _HAS_PIL and _HAS_TORCH:
            with Image.open(img_path) as raw_img:
                rgb_img = raw_img.convert("RGB").resize(self.image_size)
                w, h = rgb_img.size
                flat_pixels = list(rgb_img.getdata())
                r_ch = [p[0] / 255.0 for p in flat_pixels]
                g_ch = [p[1] / 255.0 for p in flat_pixels]
                b_ch = [p[2] / 255.0 for p in flat_pixels]
                pixel_tensor = torch.tensor([r_ch, g_ch, b_ch], dtype=torch.float32).view(3, h, w)

                target_dict["boxes"] = torch.tensor(boxes_list, dtype=torch.float32)
                target_dict["labels"] = torch.tensor(labels_list, dtype=torch.int64)
                return pixel_tensor, target_dict
        else:
            h, w = self.image_size
            fallback_plane = [[0.5 for _ in range(w)] for _ in range(h)]
            return [fallback_plane, fallback_plane, fallback_plane], target_dict
