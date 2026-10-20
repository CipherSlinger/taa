import matplotlib
from data_pre_process.data_process import DrdatasetMultidataFactor5
import numpy as np
import os
import json
import time
from datetime import datetime, timezone
import torch
from torch.utils.data import DataLoader
from matplotlib import pyplot as plt
import torch.cuda
from tqdm import tqdm
from sklearn import metrics
import argparse
from pathlib import Path
import pandas as pd

from network import KeNetMultFactorNew
from test_file.bootstrap_ci import my_bootstrap_ci_model
from data_pre_process.xlsx_process import test_data_write_xlsx

parser = argparse.ArgumentParser(description='test_fusion')
parser.add_argument('-s', '--set', type=str, required=True, help='Dataset name')
parser.add_argument('-m', '--model_name', type=str, required=True, help='Model name')
parser.add_argument('-x', '--xlsx_name', type=str, required=True, help='xlsx name')
parser.add_argument('-d', '--dataset_num', type=int, required=True, help='dataset num')
parser.add_argument('-mnp', '--model_name_path', type=str, required=True, help='Model name pth')
parser.add_argument('-b', '--basic_model', type=str, required=True, help='basic pth')
parser.add_argument('-g', '--gpu', type=str, required=False, default='0', help='gpu id (e.g. 0) or "cpu"')
parser.add_argument('-device', '--device', type=str, required=False, default=None, help='device: "cpu", "cuda", "cuda:0"')
parser.add_argument('-s_img', '--img_size', type=int, required=False, default=1024, help="image size (e.g. 1024, 512, 256)")
parser.add_argument('-w', '--wam', type=str, required=False, default=False, help="whether to use windows attention")
parser.add_argument('-n', '--win_num', type=int, required=False, default=3, help="The windows number")
parser.add_argument('-el', '--ep_left', type=int, required=False, default=1, help="test begin epoc")
parser.add_argument('-er', '--ep_right', type=int, required=False, default=1, help="test end epoc")
parser.add_argument('-l', '--layer', type=int, required=False, default=1, help="resnet layer")
parser.add_argument('-df', '--dataset', type=str, required=False, default='', help="the number of model")
parser.add_argument('-lb', '--lamb', type=float, required=False, default=1, help="the weight of seg image")
parser.add_argument('-nw', '--num_workers', type=int, required=False, default=4, help="DataLoader num_workers")
parser.add_argument('--data-root', type=str, required=False, default=None, help='data root (default: /opt/taa/input)')
parser.add_argument('--output-dir', type=str, required=False, default=None, help='output root directory for results (default: TAA_OUTPUT_DIR, else /opt/taa/output)')
parser.add_argument('--log-dir', type=str, required=False, default=None, help='log directory for inference output (default: derived from the output root)')
parser.add_argument('--progress-dir', type=str, required=False, default=None, help='progress directory for inference progress (default: derived from the output root)')
pars = parser.parse_args()

if pars.device is not None:
    if pars.device.lower() == 'cpu':
        device = torch.device('cpu')
    else:
        device = torch.device(pars.device)
else:
    if str(pars.gpu).lower() in ['cpu', '-1']:
        device = torch.device('cpu')
    else:
        device = torch.device(f'cuda:{pars.gpu}' if torch.cuda.is_available() else 'cpu')

basic_model = pars.basic_model  # inception fold1 797 densenet fold0 793 resnet fold0 793
fold = '0'
test_epoch = range(pars.ep_left, pars.ep_right, 4)

if pars.wam == 'True' or pars.wam == 'true':
    windows_attention = True
else:
    windows_attention = False

img_size = pars.img_size
num_class = 2
dataset = 'DKD'
num_thread = pars.num_workers

net = KeNetMultFactorNew(classes_num=2, basic_model=basic_model, windows_attention=windows_attention,
                         pretrain=False, windows_num=pars.win_num, initial_method="Uniform", k=0.8,
                         layer_num=pars.layer, lb_weight=pars.lamb, img_size=img_size).to(device)

if device.type == 'cuda':
    device_ids = [device.index if device.index is not None else 0]
    net = torch.nn.DataParallel(net, device_ids)

def resolve_input_root(data_root_text):
    """Resolve the input root: --data-root when given, /opt/taa/input otherwise.

    No environment variable participates here on purpose: the two roots are
    either passed explicitly or fall back to the platform's fixed paths.
    """
    target = data_root_text if data_root_text else '/opt/taa/input'
    return Path(target).expanduser().resolve(strict=False)


def resolve_dataset_root(input_root):
    """Descend into data/ when the input root is a project root rather than a data dir."""
    if (input_root / 'data').is_dir() and not (input_root / f'cls{pars.dataset}').is_dir() \
            and not (input_root / 'risk_factor_5.xlsx').is_file():
        return input_root / 'data'
    return input_root


def resolve_output_dir(output_dir_text):
    """Resolve the output root: --output-dir, then TAA_OUTPUT_DIR, then /opt/taa/output.

    TAA injects TAA_OUTPUT_DIR pointing at the result directory it collects,
    so a launch command without --output-dir still lands where TAA expects.
    """
    if output_dir_text is not None and str(output_dir_text).strip():
        target = str(output_dir_text)
    else:
        target = os.environ.get('TAA_OUTPUT_DIR', '') or '/opt/taa/output'
    return Path(target).expanduser().resolve(strict=False)


def resolve_log_dir(log_dir_text=None, output_dir_text=None):
    """Resolve the log dir, keeping it a sibling of the output root's parent when it ends in result/."""
    if log_dir_text is not None and str(log_dir_text).strip():
        return Path(log_dir_text).expanduser().resolve(strict=False)
    if output_dir_text is not None and str(output_dir_text).strip():
        out = Path(output_dir_text).expanduser().resolve(strict=False)
        if out.name == "result":
            return out.parent / "log"
        return out / "log"
    return Path("/opt/taa/output/log")


def resolve_progress_dir(progress_dir_text=None, output_dir_text=None):
    """Resolve the progress dir, keeping it a sibling of the output root's parent when it ends in result/."""
    if progress_dir_text is not None and str(progress_dir_text).strip():
        return Path(progress_dir_text).expanduser().resolve(strict=False)
    if output_dir_text is not None and str(output_dir_text).strip():
        out = Path(output_dir_text).expanduser().resolve(strict=False)
        if out.name == "result":
            return out.parent / "progress"
        return out / "progress"
    return Path("/opt/taa/output/progress")


class ModelLogger:
    """JSONL terminal logger that appends to a .log file and mirrors lines to stdout."""

    def __init__(self, log_dir, filename="test.log"):
        self.log_dir = Path(log_dir)
        self.log_dir.mkdir(parents=True, exist_ok=True)
        self.log_path = self.log_dir / filename
        self._file = open(self.log_path, "a", encoding="utf-8")

    def log(self, message):
        msg_str = str(message)
        ts = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
        record = {"timestamp": ts, "message": msg_str}
        if self._file and not self._file.closed:
            self._file.write(json.dumps(record, ensure_ascii=False) + "\n")
            self._file.flush()
        print(msg_str)

    def close(self):
        if self._file and not self._file.closed:
            try:
                self._file.flush()
                self._file.close()
            except Exception:
                pass
            finally:
                self._file = None


class ProgressTracker:
    """Atomic writer for inference progress and status metadata into progress.json."""

    def __init__(self, progress_dir, filename="progress.json", min_interval_seconds=0.2,
                 min_percent_delta=0.0001, decimal_places=4):
        self.progress_dir = Path(progress_dir)
        self.progress_dir.mkdir(parents=True, exist_ok=True)
        self.filename = filename
        self.progress_path = self.progress_dir / self.filename
        self.tmp_path = self.progress_dir / f"{self.filename}.tmp"
        self.min_interval_seconds = max(0.0, float(min_interval_seconds))
        self.min_percent_delta = max(0.0, float(min_percent_delta))
        self.decimal_places = max(0, int(decimal_places))
        self._last_percent = -1.0
        self._last_write_time = 0.0
        self._last_payload = None

    @property
    def last_percent(self):
        return max(0.0, self._last_percent)

    @property
    def last_payload(self):
        return self._last_payload

    def should_write(self, current_percent, force):
        if force or self._last_percent < 0.0:
            return True
        if current_percent >= 100.0 or current_percent <= 0.0:
            return True
        now = time.time()
        time_elapsed = now - self._last_write_time
        percent_diff = abs(current_percent - self._last_percent)
        return (time_elapsed >= self.min_interval_seconds) or (percent_diff >= self.min_percent_delta)

    def update(self, percent, stage=None, message=None, epoch=None, total_epochs=None, batch=None,
               total_batches=None, loss=None, acc=None, force=False, allow_regression=False, **kwargs):
        """Update progress percentage and optional metadata atomically. Returns True if written."""
        clamped = max(0.0, min(100.0, round(float(percent), self.decimal_places)))
        # Enforce non-decreasing progress unless explicitly allowed
        if not allow_regression and self._last_percent >= 0.0:
            clamped = max(clamped, self._last_percent)

        if not self.should_write(clamped, force=force):
            return False

        ts = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%fZ")
        payload = {
            "percent": clamped,
            "timestamp": ts,
        }
        if stage is not None and str(stage).strip():
            payload["stage"] = str(stage).strip()
        if message is not None and str(message).strip():
            payload["message"] = str(message).strip()
        if epoch is not None:
            payload["epoch"] = int(epoch)
        if total_epochs is not None:
            payload["total_epochs"] = int(total_epochs)
        if batch is not None:
            payload["batch"] = int(batch)
        if total_batches is not None:
            payload["total_batches"] = int(total_batches)
        if loss is not None:
            try:
                payload["loss"] = round(float(loss), 4)
            except (ValueError, TypeError):
                pass
        if acc is not None:
            try:
                payload["acc"] = round(float(acc), 2)
            except (ValueError, TypeError):
                pass
        for k, v in kwargs.items():
            if v is not None:
                payload[k] = v

        content = json.dumps(payload, ensure_ascii=False, indent=2) + "\n"
        with open(self.tmp_path, "w", encoding="utf-8") as f:
            f.write(content)
            f.flush()
            os.fsync(f.fileno())
        os.replace(self.tmp_path, self.progress_path)

        self._last_percent = clamped
        self._last_write_time = time.time()
        self._last_payload = payload
        return True


# Inputs are read from the mounted input root; results are written to the output
# root (--output-dir, else TAA_OUTPUT_DIR, else /opt/taa/output). Model weights
# travel with the code, so they stay next to this script.
INPUT_ROOT = resolve_input_root(pars.data_root)
DATA_ROOT = resolve_dataset_root(INPUT_ROOT)
OUTPUT_ROOT = resolve_output_dir(pars.output_dir)
LOG_DIR = resolve_log_dir(pars.log_dir, OUTPUT_ROOT)
PROGRESS_DIR = resolve_progress_dir(pars.progress_dir, OUTPUT_ROOT)
MODEL_ROOT = Path(__file__).resolve().parent / 'model'

main_dataset = str(DATA_ROOT / ('cls' + pars.dataset)) + '/'
Prospective = str(INPUT_ROOT / 'data_test/Prospective/fundus/Prospective') + '/'
Multi_center = str(INPUT_ROOT / 'data_test/Multi_center') + '/'
Non_standard = str(INPUT_ROOT / 'data_test/Non_standard') + '/'
dataset_dic = {
    'main': main_dataset,
    'Prospective': Prospective,
    'Multi_center': Multi_center,
    'Non_standard': Non_standard
}
set_dir = dataset_dic[pars.set]

main_disk = str(DATA_ROOT / 'seg/disk') + '/'
disk_Prospective = str(INPUT_ROOT / 'data_test/Prospective/seg/disk/Prospective') + '/'
disk_Non_standard = str(INPUT_ROOT / 'data_test/Prospective/seg/disk/Non_standard') + '/'
disk_Multi = str(INPUT_ROOT / 'data_test/Multi_center/seg/disk') + '/'

disk_dic = {
    'main': main_disk,
    'Prospective': disk_Prospective,
    'Multi_center': disk_Multi,
    'Non_standard': disk_Non_standard,
}
disk_dir = disk_dic[pars.set]

main_lesion = str(DATA_ROOT / 'seg/lesion') + '/'
lesion_Prospective = str(INPUT_ROOT / 'data_test/Prospective/seg/lesion/Prospective') + '/'
lesion_Non_standard = str(INPUT_ROOT / 'data_test/Prospective/seg/lesion/Non_standard') + '/'
lesion_Multi = str(INPUT_ROOT / 'data_test/Multi_center/seg/lesion') + '/'

lesion_dic = {
    'main': main_lesion,
    'Prospective': lesion_Prospective,
    'Multi_center': lesion_Multi,
    'Non_standard': lesion_Non_standard,
}
lesion_dir = lesion_dic[pars.set]

model_name = pars.model_name_path
model_dir = str(MODEL_ROOT / model_name) + '/'

if_after = True
isolate = True

if set_dir == main_dataset:
    isolate = False
else:
    isolate = True
if set_dir == Prospective or set_dir == Non_standard:
    if_after = False
else:
    if_after = True

if set_dir == main_dataset:
    dataset = dataset + '_maindata_test'
    xlsx_path = str(DATA_ROOT / 'risk_factor_5.xlsx')
elif set_dir == Prospective:
    dataset = dataset + '_Prospective'
    xlsx_path = str(DATA_ROOT / 'Prospective_5.xlsx')
elif set_dir == Multi_center:
    dataset = dataset + '_Multi_center'
    xlsx_path = str(DATA_ROOT / 'Multi_center_5.xlsx')
elif set_dir == Non_standard:
    dataset = dataset + '_Non_standard_no'
    xlsx_path = str(DATA_ROOT / 'Prospective_5.xlsx')

distribution_dir = OUTPUT_ROOT / 'isolate_test/cls_metrics' / ('metrics_' + model_name + '_distribution') / dataset
roc_data_save_path = OUTPUT_ROOT / 'excel_data/roc_data'

Total_Acc_ci = []
Total_Spec_ci = []
Total_Sen_ci = []
Total_F1_Score_ci = []
Total_AUC_ci = []

Total_Acc = []
Total_Spec = []
Total_Sen = []
Total_F1_Score = []
Total_AUC = []

distribution_scatter_0 = []
distribution_scatter_1 = []


def main():
    dis_show = 0
    print("Waiting Test!")
    logger = ModelLogger(LOG_DIR)
    progress = ProgressTracker(PROGRESS_DIR)
    inference_started = time.time()
    total_epochs = max(1, len(test_epoch))
    logger.log("[Init] Starting Retina-DKD inference: model=%s, checkpoints=%s, img_size=%d, device=%s"
               % (model_name, list(test_epoch), img_size, device))
    logger.log("[Init] Directories: input_root=%s, data_root=%s, output_root=%s, log_dir=%s, progress_dir=%s"
               % (INPUT_ROOT, DATA_ROOT, OUTPUT_ROOT, LOG_DIR, PROGRESS_DIR))
    progress.update(0.0, stage="init", message="Starting Retina-DKD inference", force=True)
    label_all_allfold = []
    predicted_all_allfold = []
    metrics_dir = OUTPUT_ROOT / 'isolate_test/cls_metrics'
    metrics_dir.mkdir(parents=True, exist_ok=True)
    with open(str(metrics_dir / ('metrics_' + model_name + '_' + dataset + '_isolate.txt')), "w+") as f:
        for epoch_index, ep in enumerate(test_epoch, start=1):
            epoch_base = 2.0 + 93.0 * (epoch_index - 1) / total_epochs
            epoch_span = 93.0 / total_epochs
            ep_s = str(ep)
            while len(ep_s) < 3:
                ep_s = '0' + ep_s
            progress.update(epoch_base, stage="load",
                            message="Epoch %s (%d/%d) loading checkpoint net_%s.pth"
                                    % (ep_s, epoch_index, total_epochs, ep_s),
                            epoch=epoch_index, total_epochs=total_epochs, force=True)
            logger.log("[Load] Epoch %s (%d/%d) - loading %snet_%s.pth"
                       % (ep_s, epoch_index, total_epochs, model_dir, ep_s))
            checkpoint = torch.load(model_dir + 'net_' + ep_s + '.pth', map_location=device)
            if isinstance(net, torch.nn.DataParallel):
                net.load_state_dict(checkpoint)
            else:
                checkpoint = {k.replace('module.', ''): v for k, v in checkpoint.items()}
                net.load_state_dict(checkpoint)
            if pars.dataset == '_all':
                phase = 'Train'
            else:
                phase = 'Test'
            dr_dataset_test = DrdatasetMultidataFactor5(
                root_img=set_dir,
                root_seg1=disk_dir,
                root_seg2=lesion_dir,
                xlsx_path=xlsx_path,
                phase=phase,
                img_size=img_size, num_class=num_class, transform=False, isolate=isolate, if_after=if_after)
            loader_test = DataLoader(dr_dataset_test, batch_size=1, num_workers=num_thread, shuffle=False)
            test_bar = tqdm(loader_test)
            total_batches = max(1, len(loader_test))
            midpoint_batch = max(1, total_batches // 2)
            progress_interval = max(1, total_batches // 10)
            logger.log("[Test] Epoch %s starting (%d batches, phase=%s)" % (ep_s, len(loader_test), phase))
            progress.update(epoch_base + epoch_span * 0.1, stage="eval",
                            message="Epoch %s evaluation started" % ep_s,
                            epoch=epoch_index, total_epochs=total_epochs, force=True)

            with torch.no_grad():
                label_all = []
                predicted_all = []
                tp = 0
                tn = 0
                fp = 0
                fn = 0
                for batch_index, packs in enumerate(test_bar, start=1):
                    batch_ratio = batch_index / total_batches
                    is_milestone = (
                        batch_index == 1
                        or batch_index == total_batches
                        or batch_index == midpoint_batch
                        or batch_index % progress_interval == 0
                    )
                    progress.update(
                        epoch_base + epoch_span * batch_ratio,
                        stage="eval",
                        message="Epoch %s [Eval %d/%d, %.1f%%]" % (ep_s, batch_index, total_batches, batch_ratio * 100),
                        epoch=epoch_index,
                        total_epochs=total_epochs,
                        batch=batch_index,
                        total_batches=total_batches,
                        force=is_milestone,
                    )
                    if batch_index == midpoint_batch:
                        logger.log("[Eval] Epoch %s (Midpoint 50%%) [Eval %d/%d]"
                                   % (ep_s, batch_index, total_batches))
                    net.eval()
                    images, seg1, seg2, non_inv_fac, inv_fac, labels = (
                        packs[0].to(device),
                        packs[1].to(device),
                        packs[2].to(device),
                        packs[3].to(device),
                        packs[4].to(device),
                        packs[5].to(device),
                    )
                    if images[0].equal(torch.from_numpy(np.array(-1)).to(device)):
                        continue
                    outputs = net(images, seg1, seg2, non_inv_fac, inv_fac)
                    outputs = torch.softmax(outputs, dim=1)
                    predicted_all.append(outputs.detach().cpu().numpy()[0][1])
                    _, predicted = torch.max(outputs.data, 1)

                    labels = labels.cpu().numpy()
                    label_all.append(labels[0])
                    predicted = predicted.cpu().numpy()
                    if labels[0] == 0:
                        distribution_scatter_0.append(torch.softmax(outputs.cpu(), dim=1).numpy()[0][1])
                    else:
                        distribution_scatter_1.append(torch.softmax(outputs.cpu(), dim=1).numpy()[0][1])
                    for i_test in range(1):
                        if labels[i_test] == 1 and predicted[i_test] == 1:
                            tp += 1
                        if labels[i_test] == 1 and predicted[i_test] == 0:
                            fn += 1
                        if labels[i_test] == 0 and predicted[i_test] == 1:
                            fp += 1
                        if labels[i_test] == 0 and predicted[i_test] == 0:
                            tn += 1

                Acc = (tp + tn) / (tp + tn + fp + fn) if (tp + tn + fp + fn) > 0 else 0
                print('epoc:%d acc:%f' % (ep, Acc * 100))
                Sen = (tp) / (tp + fn) if (tp + fn) > 0 else 0  # recall
                Spec = (tn) / (tn + fp) if (tn + fp) > 0 else 0

                if tp + fp == 0:
                    precision = 0
                else:
                    precision = (tp) / (tp + fp)

                if precision + Sen == 0:
                    F1_Score = 0
                else:
                    F1_Score = 2 * precision * Sen / (precision + Sen)

                AUC = metrics.roc_auc_score(y_true=np.array(label_all), y_score=np.array(predicted_all))

                Total_Acc.append(Acc)
                Total_Spec.append(Spec)
                Total_Sen.append(Sen)
                Total_F1_Score.append(F1_Score)
                Total_AUC.append(AUC)

                ACC_low, ACC_high, SEN_low, SEN_high, SPEC_low, SPEC_high, F1_SCORE_low, F1_SCORE_high, AUC_low, AUC_high = my_bootstrap_ci_model(
                    predicted_all, label_all)

                Total_Acc_ci.append((Acc, ACC_low, ACC_high))
                Total_Sen_ci.append((Sen, SEN_low, SEN_high))
                Total_Spec_ci.append((Spec, SPEC_low, SPEC_high))
                Total_AUC_ci.append((AUC, AUC_low, AUC_high))
                Total_F1_Score_ci.append((F1_Score, F1_SCORE_low, F1_SCORE_high))

                print('Acc=%.2f%%  ci=[%.2f%% , %.2f%%]' % (Acc * 100, ACC_low * 100, ACC_high * 100))
                print('Sen=%.2f%%  ci=[%.2f%% , %.2f%%]' % (Sen * 100, SEN_low * 100, SEN_high * 100))
                print('Spec=%.2f%% ci=[%.2f%% , %.2f%%]' % (Spec * 100, SPEC_low * 100, SPEC_high * 100))
                print('F1=%.2f%%   ci=[%.2f%% , %.2f%%]' % (F1_Score * 100, F1_SCORE_low * 100, F1_SCORE_high * 100))
                print('AUC=%.2f%%  ci=[%.2f%% , %.2f%%]' % (AUC * 100, AUC_low * 100, AUC_high * 100))
                logger.log("[Result] Epoch %s - Acc=%.2f%% Sen=%.2f%% Spec=%.2f%% F1=%.2f%% AUC=%.2f%%"
                           % (ep_s, Acc * 100, Sen * 100, Spec * 100, F1_Score * 100, AUC * 100))
                progress.update(epoch_base + epoch_span, stage="result",
                                message="Epoch %s evaluation completed" % ep_s,
                                epoch=epoch_index, total_epochs=total_epochs,
                                acc=round(Acc * 100, 2), force=True)

                f.write("epoc=%03d Acc=%.2f%% ci=[%.2f%% , %.2f%%] Sen=%.2f%% ci=[%.2f%% , %.2f%%] Spec=%.2f%% ci=[%.2f%% , %.2f%%] F1=%.2f%% ci=[%.2f%% , %.2f%%] AUC=%.2f%% ci=[%.2f%% , %.2f%%] "
                        % (ep, Acc * 100, ACC_low * 100, ACC_high * 100, Sen * 100, SEN_low * 100, SEN_high * 100,
                           Spec * 100, SPEC_low * 100, SPEC_high * 100, F1_Score * 100, F1_SCORE_low * 100,
                           F1_SCORE_high * 100, AUC * 100, AUC_low * 100, AUC_high * 100))
                f.write('\n')
                f.flush()

                if dis_show == 0:
                    plt.figure()
                    plt.hist(distribution_scatter_0, bins=50, density=0, facecolor="blue", edgecolor="black",
                             alpha=0.7)
                    plt.savefig(
                        str(distribution_dir / 'positive.jpg'))
                    plt.figure()
                    plt.hist(distribution_scatter_1, bins=50, density=0, facecolor="blue", edgecolor="black",
                             alpha=0.7)
                    plt.savefig(
                        str(distribution_dir / 'negative.jpg'))
                else:
                    dis_show = 1

                # roc curve
                fpr, tpr, _ = metrics.roc_curve(y_true=np.array(label_all), y_score=np.array(predicted_all))
                data_roc = {'label': np.array(label_all),
                            'pre': np.array(predicted_all)}
                roc_curve = pd.DataFrame(data=data_roc)
                roc_dir = roc_data_save_path / model_name
                roc_dir.mkdir(parents=True, exist_ok=True)
                roc_curve.to_excel(str(roc_dir / (dataset + '.xlsx')))

    ave_acc = np.average(Total_Acc)
    var_acc = np.var(Total_Acc)

    ave_sen = np.average(Total_Sen)
    var_sen = np.var(Total_Sen)

    ave_spec = np.average(Total_Spec)
    var_spec = np.var(Total_Spec)

    ave_f1_score = np.average(Total_F1_Score)
    var_f1_score = np.var(Total_F1_Score)

    ave_auc = np.average(Total_AUC)
    var_auc = np.var(Total_AUC)

    print(model_name + ':')
    print(dataset + '--------')
    print('ave_acc: %.2f%%    var_acc: %.2f%%   ci=[%.2f%% , %.2f%%]' % (
        ave_acc * 100, var_acc * 100, Total_Acc_ci[0][1] * 100, Total_Acc_ci[0][2] * 100))
    print('ave_sen: %.2f%%    var_sen: %.2f%%   ci=[%.2f%% , %.2f%%]' % (
        ave_sen * 100, var_sen * 100, Total_Sen_ci[0][1] * 100, Total_Sen_ci[0][2] * 100))
    print('ave_spec: %.2f%%   var_spec: %.2f%%  ci=[%.2f%% , %.2f%%]' % (
        ave_spec * 100, var_spec * 100, Total_Spec_ci[0][1] * 100, Total_Spec_ci[0][2] * 100))
    print('ave_f1sc: %.2f%%   var_f1sc: %.2f%%  ci=[%.2f%% , %.2f%%]' % (
        ave_f1_score * 100, var_f1_score * 100, Total_F1_Score_ci[0][1] * 100, Total_F1_Score_ci[0][2] * 100))
    print('ave_auc: %.2f%%    var_auc: %.2f%%   ci=[%.2f%% , %.2f%%]' % (
        ave_auc * 100, var_auc * 100, Total_AUC_ci[0][1] * 100, Total_AUC_ci[0][2] * 100))

    data_all = [ave_acc, var_acc, ave_sen, var_sen, ave_spec, var_spec, ave_f1_score, var_f1_score, ave_auc, var_auc]
    test_data_write_xlsx(pars.xlsx_name, pars.model_name, pars.set, pars.dataset_num, data_all, pars.model_name_path,
                         len(test_epoch), out_dir=str(OUTPUT_ROOT))
    logger.log("[Summary] %s %s - ave_acc=%.2f%% ave_sen=%.2f%% ave_spec=%.2f%% ave_f1=%.2f%% ave_auc=%.2f%%"
               % (model_name, dataset, ave_acc * 100, ave_sen * 100, ave_spec * 100,
                  ave_f1_score * 100, ave_auc * 100))
    logger.log("[Done] Results written to %s (xlsx=%s)" % (OUTPUT_ROOT, OUTPUT_ROOT / pars.xlsx_name))
    progress.update(100.0, stage="completed", message="Inference successfully completed",
                    total_epochs=total_epochs, force=True)
    logger.log("[Done] Inference finished successfully in %.1fs" % (time.time() - inference_started))
    logger.close()


if __name__ == "__main__":

    init_seed = 1115
    np.random.seed(init_seed)
    torch.manual_seed(init_seed)
    if torch.cuda.is_available():
        torch.cuda.manual_seed_all(init_seed)
    # Every artefact lands under the output root (--output-dir, else
    # TAA_OUTPUT_DIR, else /opt/taa/output).
    (OUTPUT_ROOT / 'isolate_test/ROC').mkdir(parents=True, exist_ok=True)
    distribution_dir.mkdir(parents=True, exist_ok=True)
    main()
