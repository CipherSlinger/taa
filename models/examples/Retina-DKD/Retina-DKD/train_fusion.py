import torch.nn as nn
import torch.optim as optim
from data_pre_process.data_process import my_default_collate, DrdatasetMultidataFactor5
import numpy as np
import torch
from torch.utils.data import DataLoader
from tensorboardX import SummaryWriter
import os
import json
import time
from datetime import datetime, timezone
from pathlib import Path
import torch.cuda
from tqdm import tqdm
import argparse
from network import KeNetMultFactorNew

# python train_fusion.py -b TransMUF -g 0 -bc 8 -e 150 -d _4

parser = argparse.ArgumentParser(description='train_fusion')
parser.add_argument('-b', '--basic_net', type=str, required=True, help='basic_net')
parser.add_argument('-g', '--gpu', type=str, required=False, default='0', help='gpu id (e.g. 0) or "cpu"')
parser.add_argument('-device', '--device', type=str, required=False, default=None, help='device: "cpu", "cuda", "cuda:0"')
parser.add_argument('-s', '--img_size', type=int, required=False, default=1024, help="image size (e.g. 1024, 512, 256)")
parser.add_argument('-pre', '--pretrain', type=str, required=False, default='False', help='pretrain')
parser.add_argument('-w', '--wam', type=str, required=False, default=False, help="whether to use windows attention")
parser.add_argument('-n', '--win_num', type=int, required=False, default=3, help="The windows number")
parser.add_argument('-lr', '--LR', type=int, required=False, default=1, help="Learning rate")
parser.add_argument('-bc', '--batch', type=int, required=False, default=4, help="batch_size")
parser.add_argument('-e', '--epoc', type=int, required=False, default=800, help="epoc_num")
parser.add_argument('-l_num', '--layer_num', type=int, required=False, default=1, help="the num of resnet wam layer")
parser.add_argument('-ld', '--load_model', type=int, required=False, default='-1', help="the number of model")
parser.add_argument('-d', '--dataset', type=str, required=False, default='', help="dataset describe")
parser.add_argument('-nw', '--num_workers', type=int, required=False, default=4, help="num_workers for DataLoader")
parser.add_argument('--data-root', type=str, required=False, default=None, help='data root (default: /opt/taa/input)')
parser.add_argument('--output-dir', type=str, required=False, default=None, help='output root directory for checkpoints and results (default: /opt/taa/output)')
parser.add_argument('--log-dir', type=str, required=False, default=None, help='log directory for training output (default: None)')
parser.add_argument('--progress-dir', type=str, required=False, default=None, help='progress directory for training progress (default: None)')
args = parser.parse_args()

EPOCH = args.epoc
num_epochs_decay = 600
img_size = args.img_size
num_class = 2
dataset = 'DKD'
num_thread = args.num_workers

if args.device is not None:
    if args.device.lower() == 'cpu':
        device = torch.device('cpu')
    else:
        device = torch.device(args.device)
else:
    if str(args.gpu).lower() in ['cpu', '-1']:
        device = torch.device('cpu')
    else:
        device = torch.device(f'cuda:{args.gpu}' if torch.cuda.is_available() else 'cpu')

basic_model = args.basic_net  # inception  densenet resnet
pretrain = True if args.pretrain == 'True' else False

from config.train_config import *

if args.wam == 'True' or args.wam == 'true':
    windows_attention = True
else:
    windows_attention = False

net = KeNetMultFactorNew(classes_num=num_class, basic_model=basic_model, windows_attention=windows_attention,
                         pretrain=pretrain, windows_num=args.win_num, initial_method="Uniform", k=0.8,
                         layer_num=args.layer_num, img_size=img_size).to(device)
if device.type == 'cuda':
    device_ids = [device.index if device.index is not None else 0]
    net = torch.nn.DataParallel(net, device_ids)

# load the pretrain model
if pretrain:
    pre_model_dir = args.pre_path
    save_model = torch.load(pre_model_dir, map_location=device)
    model_dict = net.state_dict()
    state_dict = {k: v for k, v in save_model.items() if k in model_dict.keys()}
    model_dict.update(state_dict)
    net.load_state_dict(model_dict)
# sf:small factor
model_name = 'fusion_' + basic_model + args.dataset + '_win_num' + str(args.win_num) + '_lr' + str(
    args.LR) + '_ep' + str(
    args.epoc) + 'bc_' + str(args.batch) + 'lnum_' + str(args.layer_num)
if args.wam == "True" or args.wam == "true":
    model_name = 'begin_wam_' + model_name
if not pretrain:
    model_name = model_name + '_Nopretrain'


def resolve_data_root(data_root_text: str | None) -> Path:
    if data_root_text and data_root_text != '/opt/taa/input':
        target = data_root_text
    else:
        target = os.environ.get('TAA_DATA_DIR') or os.environ.get('TAA_INPUT_DIR') or data_root_text or '/opt/taa/input'
    path = Path(target).expanduser().resolve(strict=False)
    if (path / 'data').is_dir() and not (path / f'cls{args.dataset}').is_dir() and not (path / 'risk_factor_5.xlsx').is_file():
        return path / 'data'
    return path


def resolve_output_dir(output_dir_text: str | None) -> Path:
    if output_dir_text and output_dir_text != '/opt/taa/output':
        target = output_dir_text
    else:
        target = os.environ.get('TAA_OUTPUT_DIR') or os.environ.get('TAA_MODEL_OUTPUT_DIR') or output_dir_text or '/opt/taa/output'
    return Path(target).expanduser().resolve(strict=False)


def resolve_log_dir(log_dir_text: str | Path | None = None, output_dir_text: str | Path | None = None) -> Path:
    if log_dir_text is not None and str(log_dir_text).strip():
        return Path(log_dir_text).expanduser().resolve(strict=False)
    if output_dir_text is not None and str(output_dir_text).strip():
        out = Path(output_dir_text).expanduser().resolve(strict=False)
        if out.name == "result":
            return out.parent / "log"
        return out / "log"
    return Path("/opt/taa/output/log")


def resolve_progress_dir(progress_dir_text: str | Path | None = None, output_dir_text: str | Path | None = None) -> Path:
    if progress_dir_text is not None and str(progress_dir_text).strip():
        return Path(progress_dir_text).expanduser().resolve(strict=False)
    if output_dir_text is not None and str(output_dir_text).strip():
        out = Path(output_dir_text).expanduser().resolve(strict=False)
        if out.name == "result":
            return out.parent / "progress"
        return out / "progress"
    return Path("/opt/taa/output/progress")


class ModelLogger:
    """JSONL 终端日志记录器，写入 train.log 并同步输出到控制台。"""

    def __init__(self, log_dir: Path | str, filename: str = "train.log"):
        self.log_dir = Path(log_dir)
        self.log_dir.mkdir(parents=True, exist_ok=True)
        self.log_path = self.log_dir / filename
        self._file = open(self.log_path, "a", encoding="utf-8")

    def log(self, message: str) -> None:
        msg_str = str(message)
        ts = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
        record = {"timestamp": ts, "message": msg_str}
        if self._file and not self._file.closed:
            self._file.write(json.dumps(record, ensure_ascii=False) + "\n")
            self._file.flush()
        print(msg_str)

    def close(self) -> None:
        if self._file and not self._file.closed:
            try:
                self._file.flush()
                self._file.close()
            except Exception:
                pass
            finally:
                self._file = None

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        self.close()


class ProgressTracker:
    """原子化写入训练百分比进度到 progress.json。"""

    def __init__(self, progress_dir: Path | str, filename: str = "progress.json"):
        self.progress_dir = Path(progress_dir)
        self.progress_dir.mkdir(parents=True, exist_ok=True)
        self.filename = filename
        self.progress_path = self.progress_dir / self.filename
        self.tmp_path = self.progress_dir / f"{self.filename}.tmp"

    def update(self, percent: float) -> None:
        clamped = max(0.0, min(100.0, round(float(percent), 2)))
        ts = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
        payload = {"percent": clamped, "timestamp": ts}
        content = json.dumps(payload, ensure_ascii=False, indent=2) + "\n"
        with open(self.tmp_path, "w", encoding="utf-8") as f:
            f.write(content)
            f.flush()
            os.fsync(f.fileno())
        os.replace(self.tmp_path, self.progress_path)


output_root = resolve_output_dir(args.output_dir)
model_save_dir = output_root / f'model_{model_name}_{dataset}'

epoc_begin = 0
if args.load_model > 0:
    checkpoint_path = model_save_dir / f'net_{args.load_model:03d}.pth'
    if not checkpoint_path.exists():
        legacy_path = Path('model') / f'model_{model_name}_{dataset}' / f'net_{args.load_model:03d}.pth'
        if legacy_path.exists():
            checkpoint_path = legacy_path
    checkpoint = torch.load(str(checkpoint_path), map_location=device)
    if isinstance(net, torch.nn.DataParallel):
        net.load_state_dict(checkpoint)
    else:
        checkpoint = {k.replace('module.', ''): v for k, v in checkpoint.items()}
        net.load_state_dict(checkpoint)
    epoc_begin = args.load_model
train_BATCH_SIZE = args.batch
test_BATCH_SIZE = 1


def utc_timestamp() -> str:
    return datetime.now(timezone.utc).strftime('%Y-%m-%dT%H:%M:%SZ')


def env_or_default(name: str, default: str) -> str:
    value = os.environ.get(name, '')
    return value if value else default


def build_training_task_info(
    task_id: str,
    started_at: str,
    finished_at: str,
    duration_seconds: int,
    status: str,
    exit_code: int,
    failure_reason: str | None = None,
    metrics: dict | None = None,
) -> dict:
    task = {
        'task_id': task_id,
        'started_at': started_at,
        'finished_at': finished_at,
        'duration_seconds': duration_seconds,
        'status': status,
        'exit_code': exit_code,
        'failure_reason': None if status == 'succeeded' else failure_reason,
    }
    if metrics:
        task['metrics'] = metrics
    return task


def main():
    training_started = time.time()
    started_at_text = env_or_default('TAA_STARTED_AT', utc_timestamp())
    task_id = env_or_default('TAA_TASK_ID', 'task-local')
    data_root = resolve_data_root(args.data_root)
    output_root = resolve_output_dir(args.output_dir)
    cls_root = data_root / f'cls{args.dataset}'
    seg_disk_root = data_root / 'seg' / 'disk'
    seg_lesion_root = data_root / 'seg' / 'lesion'
    xlsx_path = data_root / 'risk_factor_5.xlsx'

    log_dir = resolve_log_dir(args.log_dir, args.output_dir)
    progress_dir = resolve_progress_dir(args.progress_dir, args.output_dir)
    logger = ModelLogger(log_dir)
    progress = ProgressTracker(progress_dir)

    progress.update(0.0)
    logger.log(f"[Init] Starting Retina-DKD training: basic_net={basic_model}, epochs={EPOCH}, batch_size={args.batch}, img_size={img_size}")
    logger.log(f"[Init] Directories: data_root={data_root}, output_root={output_root}, log_dir={log_dir}, progress_dir={progress_dir}")
    logger.log(f"[Init] Paths: class_root={cls_root}, seg_disk_root={seg_disk_root}, seg_lesion_root={seg_lesion_root}, xlsx_path={xlsx_path}")

    print(f'Data root: {data_root}')
    print(f'Output root: {output_root}')
    print(f'Class root: {cls_root}')
    print(f'Seg root 1: {seg_disk_root}')
    print(f'Seg root 2: {seg_lesion_root}')
    print(f'XLSX path: {xlsx_path}')

    criterion = nn.CrossEntropyLoss(
        weight=torch.from_numpy(np.array([weight[0], weight[1]])).float().to(device))
    optimizer = optim.Adam(net.parameters(), lr=LR * args.LR, weight_decay=weight_decay)
    scheduler = optim.lr_scheduler.CosineAnnealingWarmRestarts(optimizer, T_0=5, T_mult=2)
    dr_dataset_train = DrdatasetMultidataFactor5(root_img=str(cls_root) + '/',
                                                 root_seg1=str(seg_disk_root) + '/',
                                                 root_seg2=str(seg_lesion_root) + '/',
                                                 xlsx_path=str(xlsx_path),
                                                 phase='Train',
                                                 img_size=img_size, num_class=num_class, transform=True,
                                                 if_after=True)
    dr_dataset_test = DrdatasetMultidataFactor5(
        root_img=str(cls_root) + '/',
        root_seg1=str(seg_disk_root) + '/',
        root_seg2=str(seg_lesion_root) + '/',
        xlsx_path=str(xlsx_path),
        phase='Test',
        img_size=img_size, num_class=num_class, transform=False, if_after=True)

    loader_train = DataLoader(dr_dataset_train, batch_size=train_BATCH_SIZE, num_workers=num_thread, shuffle=True,
                              collate_fn=my_default_collate, drop_last=True)
    loader_test = DataLoader(dr_dataset_test, batch_size=test_BATCH_SIZE, num_workers=num_thread, shuffle=False)
    runs_dir = output_root / 'runs' / f'runs_{model_name}_{dataset}'
    try:
        os.makedirs(runs_dir.parent, exist_ok=True)
    except OSError:
        pass
    writer = SummaryWriter(logdir=str(runs_dir))
    count_all = 0
    new_lr = LR * args.LR
    best_acc = 0.0
    best_train_loss = 0.0
    epoch_history = []
    acc_dir = output_root / 'acc'
    try:
        os.makedirs(acc_dir, exist_ok=True)
    except OSError:
        pass
    acc_file_path = acc_dir / f'acc_{model_name}_{dataset}.txt'
    progress.update(2.0)
    logger.log(f"[Init] KeNetMultFactorNew initialized successfully on device={device}. Dataset sizes: train={len(dr_dataset_train)}, test={len(dr_dataset_test)}")
    with open(str(acc_file_path), "w+", encoding='utf-8') as f:
        for epoch in range(epoc_begin, EPOCH):
            # if (epoch + 1) > (EPOCH - num_epochs_decay):
            #     new_lr -= (LR / float(num_epochs_decay))
            #     for param_group in optimizer.param_groups:
            #         param_group['lr'] = new_lr
            #     print('Decay learning rate to lr: {}.'.format(new_lr))

            current_percent = 2.0 + 93.0 * (epoch / max(EPOCH, 1))
            progress.update(current_percent)
            current_lr = optimizer.param_groups[0]['lr']
            logger.log(f"[Train] Starting Epoch {epoch + 1}/{EPOCH} (lr={current_lr})")

            running_results = {'acc': 0.0, 'acc_loss': 0.0}
            print('Decay learning rate to lr: {}.'.format(optimizer.param_groups[0]['lr']))
            train_bar = tqdm(loader_train)
            count = 0
            """--------------------------------------Train---------------------------------------"""
            for packs in train_bar:
                count += 1
                count_all += 1
                net.train()
                inputs, seg1, seg2, non_inv_fac, inv_fac, labels, labels_split = packs[0].to(device), packs[
                    1].to(device), packs[2].to(device), packs[3].to(device), packs[4].to(device), packs[5].to(device), packs[7].to(device)
                if inputs[0].equal(torch.from_numpy(np.array(-1)).to(device)):
                    continue
                optimizer.zero_grad()

                outputs = net(inputs, seg1, seg2, non_inv_fac, inv_fac)
                loss_ce = criterion(outputs, labels)  # vanilla softmax loss

                _, predicted = torch.max(outputs.data, 1)

                loss = loss_ce
                loss.backward()
                optimizer.step()

                total = labels.size(0)
                correct = predicted.eq(labels).sum().item()
                batch_acc = 100.0 * correct / total

                running_results['acc'] += batch_acc
                running_results['acc_loss'] += loss.item()

                train_bar.set_description(
                    desc=model_name + ' [%d/%d] acc_loss: %.4f  ' % (
                        epoch, EPOCH,
                        running_results['acc_loss'] / count
                    ))

                """------------------tensorboard test--------------"""
                if count % 4 == 0:
                    writer.add_scalar('scalar/train_loss_per_iter', loss.item(), count_all)
                    writer.add_scalar('scalar/acc_batchwise', batch_acc, count_all)

            epoch_loss = running_results['acc_loss'] / max(count, 1)
            epoch_acc = running_results['acc'] / max(count, 1)
            logger.log(f"[Train] Epoch {epoch + 1}/{EPOCH} finished - train_loss: {epoch_loss:.4f}, train_acc: {epoch_acc:.2f}%")

            """------------------Test--------------"""

            if epoch % 4 == 0:
                test_bar = tqdm(loader_test)
                print("Waiting Test!")
                with torch.no_grad():
                    correct_all = 0
                    total_all = 0
                    tp = 0
                    tn = 0
                    fp = 0
                    fn = 0
                    for packs in test_bar:
                        net.eval()
                        images, seg1, seg2, non_inv_fac, inv_fac, labels = packs[0].to(device), packs[1].to(
                            device), packs[2].to(device), packs[3].to(device), packs[4].to(
                            device), packs[5].to(device)
                        if images[0].equal(torch.from_numpy(np.array(-1)).to(device)):
                            continue
                        outputs = net(images, seg1, seg2, non_inv_fac, inv_fac)
                        _, predicted = torch.max(outputs.data, 1)
                        total_all += labels.size(0)
                        correct_all += (predicted == labels).sum()
                        labels = labels.cpu().numpy()
                        predicted = predicted.cpu().numpy()

                        for i_test in range(test_BATCH_SIZE):
                            if labels[i_test] == 1 and predicted[i_test] == 1:
                                tp += 1
                            if labels[i_test] == 1 and predicted[i_test] == 0:
                                fn += 1
                            if labels[i_test] == 0 and predicted[i_test] == 1:
                                fp += 1
                            if labels[i_test] == 0 and predicted[i_test] == 0:
                                tn += 1

                    Acc = (tp + tn) / (tp + tn + fp + fn) if (tp + tn + fp + fn) > 0 else 0
                    Sen = (tp) / (tp + fn) if (tp + fn) > 0 else 0
                    Spec = (tn) / (tn + fp) if (tn + fp) > 0 else 0
                    print('Testset Acc=：%.1f%% | Sen=：%.1f%% | Spec=：%.1f%% ' % (Acc * 100, Sen * 100, Spec * 100))
                    logger.log(f"[Eval] Epoch {epoch + 1}/{EPOCH} - Testset Acc: {Acc * 100:.1f}%, Sen: {Sen * 100:.1f}%, Spec: {Spec * 100:.1f}%")

                    if Acc > best_acc:
                        best_acc = Acc
                        best_train_loss = running_results['acc_loss'] / max(count, 1)

                    save_dir = output_root / f'model_{model_name}_{dataset}'
                    try:
                        os.makedirs(save_dir, exist_ok=True)
                    except OSError:
                        pass
                    torch.save(net.state_dict(), str(save_dir / f'net_{epoch + 1:03d}.pth'))
                    f.write("EPOCH=%03d | Acc=：%.1f%% | Sen=：%.1f%% | Spec=：%.1f%% "
                            % (epoch + 1, Acc * 100, Sen * 100, Spec * 100))
                    f.write('\n')
                    f.flush()

                    writer.add_scalar('scalar/test_Acc', Acc, epoch)
                    writer.add_scalar('scalar/test_Sen', Sen, epoch)
                    writer.add_scalar('scalar/test_Spec', Spec, epoch)

            epoch_history.append({
                'epoch': epoch + 1,
                'accuracy': round((running_results['acc'] / max(count, 1)) / 100.0, 6),
                'loss': round(running_results['acc_loss'] / max(count, 1), 6),
            })

            scheduler.step()
        writer.close()

    finished_at_text = utc_timestamp()
    duration_seconds = max(0, int(time.time() - training_started))
    training_result = {
        'training_task': build_training_task_info(
            task_id,
            started_at_text,
            finished_at_text,
            duration_seconds,
            'succeeded',
            0,
            None,
            {
                'final_accuracy': round(best_acc, 6),
                'final_loss': round(best_train_loss, 6),
                'epochs': epoch_history,
            },
        ),
        'dataset': {
            'total_samples': len(dr_dataset_train) + len(dr_dataset_test),
            'splits': {
                'train': len(dr_dataset_train),
                'test': len(dr_dataset_test),
            },
        },
    }
    try:
        os.makedirs(output_root, exist_ok=True)
    except OSError:
        pass
    result_path = output_root / 'training_result.json'
    with open(str(result_path), 'w', encoding='utf-8') as f_out:
        json.dump(training_result, f_out, indent=2, ensure_ascii=False)
        f_out.write('\n')
    print(f'Training result written to: {result_path}')

    progress.update(100.0)
    logger.log(f"[Done] Training finished successfully: duration={duration_seconds}s, final_acc={best_acc:.4f}, result saved to {result_path}")
    logger.close()


def remove_all_file(path):
    if os.path.isdir(path):
        for i in os.listdir(path):
            path_file = os.path.join(path, i)
            try:
                if os.path.isfile(path_file) or os.path.islink(path_file):
                    os.remove(path_file)
            except OSError:
                pass


if __name__ == "__main__":

    init_seed = 1115
    np.random.seed(init_seed)
    torch.manual_seed(init_seed)
    if torch.cuda.is_available():
        torch.cuda.manual_seed_all(init_seed)

    output_root = resolve_output_dir(args.output_dir)
    target_model_dir = output_root / f'model_{model_name}_{dataset}'
    target_runs_dir = output_root / 'runs' / f'runs_{model_name}_{dataset}'

    try:
        if not target_model_dir.is_dir():
            os.makedirs(target_model_dir, exist_ok=True)
        else:
            if args.load_model < 0:
                remove_all_file(str(target_model_dir))
        if target_runs_dir.is_dir():
            if args.load_model < 0:
                remove_all_file(str(target_runs_dir))
    except OSError as e:
        print(f'Warning: unable to prepare output directory {output_root}: {e}')

    main()
