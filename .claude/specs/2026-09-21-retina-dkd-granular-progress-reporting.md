# Retina-DKD Granular Training Progress Reporting Spec

## 1. Background and Motivation
In `models/examples/Retina-DKD/Retina-DKD`, model training is coordinated through `train_fusion.py` and monitored by TAA's telemetry watcher and the Platform Mock dashboard.

Previously, `train_fusion.py` reported progress only at coarse milestones:
- `0.0%` upon script entry
- `2.0%` when datasets were loaded
- `2.0% + 93.0% * (epoch / EPOCH)` at the start of each epoch
- `100.0%` upon complete termination

During an entire epoch (which may take minutes or hours and comprise dozens of batches and evaluation passes), no intermediate progress was written to `progress.json`, causing the progress bar in Platform Mock to freeze at static values. Furthermore, `progress.json` only contained `percent` and `timestamp`, lacking stage, epoch, batch, and loss/acc context.

The objective is to introduce granular, intuitive progress reporting across:
1. Multi-phase initialization (0.0% - 2.0%)
2. Intra-epoch batch training progress with periodic progress file updates and terminal logs (2.0% - 96.0%)
3. Evaluation and model checkpoint saving milestones
4. Post-training result generation and finalization (96.0% - 100.0%)
5. Enhanced `ProgressTracker` metadata payload (stage, epoch, batch, loss, accuracy, message) with RFC3339Nano UTC timestamps and smart write throttling.

## 2. Technical Design

### 2.1 Enhanced `ProgressTracker` Class
Update `ProgressTracker` in `train_fusion.py`:
```python
class ProgressTracker:
    """Atomic writer for training progress and rich status metadata into progress.json."""

    def __init__(
        self,
        progress_dir: Path | str,
        filename: str = "progress.json",
        min_interval_seconds: float = 0.5,
        min_percent_delta: float = 0.1,
    ):
        ...
```
Features:
- **Rich Payload**: Emits `percent`, `timestamp` (with microsecond precision `%Y-%m-%dT%H:%M:%S.%fZ`), `stage`, `message`, `epoch`, `total_epochs`, `batch`, `total_batches`, `loss`, and `acc`.
- **Monotonic Clamping**: Ensures `percent` is clamped to `[0.0, 100.0]` and never regresses backwards unless explicitly reset.
- **Smart Throttling**: Avoids excessive disk I/O during rapid batch iteration by checking `time.time() - last_write_time >= min_interval_seconds` or `percent - last_percent >= min_percent_delta`, while supporting `force=True` on key milestone transitions.
- **Atomic File Replacement**: Continues to write to `progress.json.tmp` followed by `fsync` and atomic `os.replace`.

### 2.2 Progress Budget Allocation
1. **Initialization (0.0% - 2.0%)**:
   - `0.0%`: Start initialization, argument parsing, directory resolution.
   - `0.5%`: Model structure instantiated and bound to device.
   - `1.0%`: Loss criterion, optimizer, scheduler configured.
   - `1.5%`: Train and test datasets and DataLoaders created.
   - `2.0%`: Tensorboard and logger ready, entering training loop.

2. **Epoch Execution (2.0% - 96.0%)**:
   - Base progress for epoch `e` (`epoc_begin` to `EPOCH - 1`):
     `epoch_base = 2.0 + 94.0 * (e - epoc_begin) / total_epochs`
     `epoch_span = 94.0 / total_epochs`
   - If evaluation runs in epoch `e` (`has_eval = e % 4 == 0 or e == EPOCH - 1`):
     - Training batches: span 80% of `epoch_span`
     - Evaluation batches: span 15% of `epoch_span`
     - Checkpoint saving & epoch completion: span 5% of `epoch_span`
   - If no evaluation:
     - Training batches: span 95% of `epoch_span`
     - Epoch completion: span 5% of `epoch_span`
   - Batch-level reporting:
     - Update progress continuously across batches with fine precision (4 decimal places) and low-latency throttling (0.2s interval, 0.0001% delta).
     - Force progress file write and terminal logging on key intra-epoch milestones: Batch 1, Quarter (25%), Midpoint (50%), Three-quarter (75%), and Batch N.
     - Tag progress message with `(Midpoint)` and completion percentage.
     - Log training step metrics to `logger.log` on midpoint and every `max(1, total_batches // 5)` batches.
   - Evaluation reporting:
     - Report evaluation start, periodic batches (including 50% midpoint), and evaluation summary metrics.
   - Checkpoint reporting:
     - Report checkpoint saving event.

3. **Finalization (96.0% - 100.0%)**:
   - `96.0%`: Final metrics aggregation.
   - `98.0%`: `training_result.json` writing.
   - `100.0%`: Training successfully concluded.

### 2.3 Compatibility
- TAA runtime `ReadLatestProgress` deserializes `{"percent": ...}` or `{"percentage": ...}` and RFC3339Nano timestamp. Extra keys (`stage`, `message`, `epoch`, `batch`, etc.) are gracefully ignored by Go JSON unmarshaling.
- Platform Mock displays `percent` and logs streamed from `train.log`.
- Existing tests in `test_reporting_helpers.py` remain fully supported and expanded with new assertions.

## 3. Verification Plan
- Run `python3 models/examples/Retina-DKD/Retina-DKD/test_reporting_helpers.py`.
- Run `go test ./...` across the entire workspace.
- Build `bin/taa` and `bin/platform-mock`.
- Perform git commit following Conventional Commits without AI traces.
