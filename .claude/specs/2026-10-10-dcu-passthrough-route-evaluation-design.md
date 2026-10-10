# DCU 直通的两条路线评估与实测证据（2026-10-10）

- **状态**：实测结论已定，路线选择待卡恢复后复验
- **日期**：2026-10-10
- **宿主**：`root@172.16.10.178`（`hygon-master`），1 张 DCU，CSV2 机密虚拟机
- **相关文件**：`tools/csv2-vm/csv2-vm.sh`、`/opt/kata/share/defaults/kata-containers/configuration-qemu-hygon-dcu-csv2.toml`

---

## 1. 触发

原始目标：**把 TAA 部署进 VM，使 initrd 被 CSV2 度量覆盖，同时支持 DCU。**

这个目标成立的物理前提是度量口径：

```
MEASUREMENT = SM3( OVMF || table{ cmdline, initrd, kernel } )
```

**容器镜像与 rootfs 磁盘不进度量。** 所以要让 TAA 出现在 `MEASUREMENT` 里，TAA 必须落在
initrd（或 kernel / cmdline）中——这是「改镜像」而不是「改磁盘」的理由。

于是问题收敛为：**在哪条 DCU 路线上做这个 initrd 注入。**

---

## 2. 两条路线

| | 路线 A（Pod / kata） | 路线 B（脚本自有 QEMU） |
| :--- | :--- | :--- |
| 入口 | `csv2-vm.sh pod-up` → `runtimeClassName: kata-qemu-hygon-dcu-csv2` | `CSV2_DCU=1 csv2-vm.sh up` |
| QEMU 进程归属 | containerd → kata runtime | 脚本直接 `-daemonize` |
| 引导方式 | `image=`（kata 配置第 17 行），`initrd=` 在第 16 行**被注释掉** | `root=/dev/vda2`，initrd = 122 字节**空壳** |
| 内核 | kata 配置内 | `vmlinuz-hycu-confidential-csv.container` |
| DCU 注入 | CDI（`/var/run/cdi/hygon_cn-k100_ai.json` → `/dev/vfio/73`） | QEMU `-device vfio-pci,host=c3:00.0` |
| 历史战绩 | **唯一实测跑通 DCU 完整工作**（hycu 绑定 + `/dev/dri/card0` + `/dev/kfd`） | 此前从未实测过真实透传 |

**TAA 注入点**：路线 B 那个 122 字节空 initrd 是天然的挂载点（append-only cpio，
`init=/usr/local/bin/taa-init`，wrapper 先起 TAA 再 `exec /sbin/init`）；路线 A 需要回答
「kata 同时给 `image=` 和 `initrd=` 是什么语义」——**这一问至今未验证**（脚本头的路线说明、
kata 的 `configuration-qemu-hygon-dcu-csv2.toml` 第 16/17 行只证明现状是「只有 image」，不证明
两者同时给出时谁生效）。

---

## 3. 路线 B 实测：DCU 透传失败

`CSV2_VM_NAME=csv2-dcutest CSV2_DCU=1 up`，两轮，唯一变量是 `CSV2_REDUCED_PHYS_BITS`。

### 3.1 两轮都到达的公共点

| 项 | 结果 |
| :--- | :--- |
| guest 引导 | 正常，22s 到 login prompt |
| DCU 枚举 | `0000:01:00.0`，位于根端口 `rp0` 之后 |
| hycu 模块加载 | 成功 |
| `/dev/kfd` | **存在**（`crw-rw-rw- 246,0`） |
| `/dev/dri/card0` | **不存在** ← 失败判据 |
| `csv-guest` 模块 | 正常，`/dev/csv-guest` 存在 |
| `up` 退出码 | **0** |

> ⚠️ **`up` 在 DCU 失败时依然返回 0。** `cmd_verify` 的 DCU 检查是 **report-only**，不影响退出码。
> 只看退出码会把这次失败读成成功——这是本脚本的一个真实陷阱。

### 3.2 两轮各自的失败点

| `reduced-phys-bits` | guest dmesg 关键行 |
| ---: | :--- |
| **5**（脚本默认） | `RLC ucode load fail` → `ring kiq_2.1.0 test failed (-110)` → `probe ... failed with error -110` |
| **1**（对齐 kata） | `read flash failed, force as sep-vbios` → `Failed initializing VRAM heap` → `sw_init of IP block <gmc_v9_0> failed -22` → `XID:190 info:HCU 01:00.00 load KMD fail(-22)!` |

两轮的失败模式不同，但**都不完成初始化**。`-110` 是 `-ETIMEDOUT`，`-22` 是 `-EINVAL`。

### 3.3 已排除的差异项

以下几点都已与 kata 路线对齐，仍失败，故**不是**路线 B 失败的原因：

- `-machine q35` 机型
- DCU 挂在 `pcie-root-port` 之后（而非直接挂 `pcie.0`）
- `kernel_irqchip=split`
- QEMU 二进制（即为 kata 自带那份 `/opt/kata/bin/qemu-system-x86_64`）
- guest 内核与 hycu 模块（同一份 kata hycu 资产）
- virtio 磁盘（guest 正常引导即证明）

---

## 4. 真正的缺陷：这块卡经不起「不复位的换手」

这是本次最有价值的发现，**优先级高于路线 B 本身的失败**。

### 4.1 警告就在启动日志里

两轮 `up` 的 QEMU stderr 都打出两遍：

```
qemu-system-x86_64: vfio: Cannot reset device 0000:c3:00.0, no available reset mechanism.
```

宿主模块 `hycu_pci_fixup_header` 给该设备打了 `NO_BUS_RESET`（它同时负责使能设备：
`0000 → 0002`，并打开 PCIe atomic）。**所以这句字面就是「换手时复位不了」，不是噪音。**

### 4.2 宿主机 IOMMU 事件计数

| 事件 | 10-08 起总数 | 我们的 VM 两轮（10 日 09h） | pod 两轮（10 日 10h） | 10-08 ～ 10-09 |
| :--- | ---: | ---: | ---: | ---: |
| `IOTLB_INV_TIMEOUT device=0000:c3:00.0` | 112 | 74 | 38 | **0** |
| `AMD-Vi: Completion-Wait loop timed out` | 131 | 88 | 43 | **0** |

**全部事件都发生在 10-10；前两整天为 0。** 事件地址形如 `0x8010_8002_1xxx`，其 bit 47 置位，
正是 C-bit 的位置——IOMMU 在对机密映射地址做无效化，然后超时。

### 4.3 卡被交还之后，pod 也起不来了

路线 A 的 pod 在拿到这张「被用过」的卡之后：

```
Error: failed to create containerd task: ... failed to inject devices after CDI timeout of 100 seconds
```

两次重试（459s、440s 后 `Failed`），**失败点完全一致**；其间没有碰过绑定，所以不是「谁在占着卡」。

### 4.4 事后卡状态

```
driver = vfio-pci
enable = 1          ← 内存解码被关（正常被使用时是 2）
holder = (none)
```

### 4.5 结论

**这块卡无法承受「不复位的换手」。** kata 那条腿历来是**开机之后卡的第一个使用者**，
接手的永远是一张干净卡，所以这个缺陷从未暴露。一旦有人先用过（无论走哪条路线），
下一个使用者就废。

> **因果归属**：确凿的只有时序——故障计数在我第一次 `up` 之前为 0，之后开始上涨且再未归零。
> 无法区分是 `pod-down` 交还那一刻还是 QEMU 占用那一刻造成的，也无法证明 `rpb=5` 与 `1`
> 哪个更糟（两者都失败、都伴随同一批事件）。

**对方案的硬约束**：任何「共享这张卡」的设计，都必须先解决换手复位，否则第 2 个使用者必然失败。
这一条直接限制了对 TAA 目标的路线的选择。

---

## 5. 对原始目标的影响

| 路线 | TAA 注入可行性 | DCU 可行性 | 综合 |
| :--- | :--- | :--- | :--- |
| A（kata Pod） | 待验证：需先回答 `image=` + `initrd=` 同时给出的语义 | 历史可行（需卡干净） | **DCU 有先例；TAA 注入点未知** |
| B（脚本 QEMU） | 清晰：122 字节空 initrd 就是注入点 | **本次实测失败** | **注入点最好，但 DCU 不通** |

**当前结论**：路线 B 的「注入点简单」这个优势，被 DCU 透传实测失败抵消；而路线 A 的 DCU 可行性
有先例、却卡在「TAA 怎么进度量」。因此**下一步不是继续调路线 B 的 DCU 参数，而是先把
route A 的 `image=` + `initrd=` 语义问清楚**——如果 kata 允许同时给，TAA 就能以 initrd 形式进度量，
那么路线 A 同时满足两个条件。

---

## 6. 恢复与遗留

**恢复路径**（`csv2-vm.sh` 头部注释给出，顺序不可颠倒）：

1. `systemctl start dcu-bind-vfio.service`
2. 若已 wedge，则 `reboot`

本次两次 pod 重试证明「等待即可自愈」不成立。约束（用户明令）：

- **不碰绑定**：`remove` / `rescan` / `unbind` / `rmmod` 全禁。
- **不单方面重启宿主**。

**本次已清理**（10-10）：`default/dcu-tee-test`（StartError）与其 Service（NodePort 32222 已释放）、
`csv2-dcutest-dcu-overlay.qcow2`、`/var/log/csv2-dcutest-console.log`、`/run/csv2-dcutest.*`。

**未清理、非本次创建**：孤儿 QEMU（pid 22112，`csv2-8c16g`，自 10-09 闲置在 login 界面）、
`csv2-dcu-base.qcow2` 及其共享盘。

---

## 7. 未决项

1. **宿主重启后复验**：卡恢复后重跑 `CSV2_DCU=1 up` + `verify`，确认故障计数是否归零；
   并记录「重启后第一个使用者」是否必然是干净卡。
2. **路线 A 的 `image=` + `initrd=` 语义**（§2 遗留）：这是原始目标的关键一问，至今未验证。
3. **`up` 退出码陷阱**（§3.1）：DCU 失败仍返回 0，容易误读为成功；是否要改为非零退出待定。
4. **`rpb` 取值**：5 与 1 都失败，但失败模式不同；卡恢复后若复跑，需在「清洁卡」前提下重测，
   否则结论受 wedge 状态污染。
5. **多实例串扰**：本次误用默认 `CSV2_QMP_PORT`（2223）与孤儿 VM 冲突，已用 `CSV2_QMP_PORT=2224`
   规避。三个实例参数（`CSV2_VM_NAME` / `CSV2_VM_MAC` / `CSV2_QMP_PORT`）应成组给出。
