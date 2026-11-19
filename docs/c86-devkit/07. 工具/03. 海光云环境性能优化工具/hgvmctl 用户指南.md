---
title: "hgvmctl 用户指南"
docCode: "2002289459805229056"
updated: "2026-03-13 15:50:42"
breadcrumb: "C86 DevKit / 07. 工具 / 03. 海光云环境性能优化工具 / hgvmctl 用户指南"
source: https://c86.sourcefind.cn/documents/2/2002289459805229056
---
# hgvmctl

## 目录

- [简介](#简介)
- [工具特点](#工具特点)
- [下载安装](#下载安装)
- [功能介绍](#功能介绍)
  - [辅助性命令](#辅助性命令)
  - [cpu命令集](#cpu命令集)
    - [cpu一级命令总览](#cpu一级命令总览)
    - [cpu二级命令](#cpu二级命令)
  - [进程命令集](#进程命令集)
    - [process一级命令总览](#process一级命令总览)
    - [process二级命令](#process二级命令)
  - [虚拟机命令集](#虚拟机命令集)
    - [vm一级命令总览](#vm一级命令总览)
    - [vm二级命令](#vm二级命令)
  - [容器命令集](#容器命令集)
    - [container一级命令总览](#container一级命令总览)
    - [container二级命令](#container二级命令)
  - [ebpf性能追踪命令集](#ebpf性能追踪命令集)
    - [ebpftrace一级命令总览](#ebpftrace一级命令总览)
    - [ebpftrace二级命令](#ebpftrace二级命令)
  - [ftrace性能追踪工具集](#ftrace性能追踪工具集)
  - [性能优化参考指导](#性能优化参考指导)
- [典型使用示例](#典型使用示例)
  - [cpu命令示例](#cpu命令示例)
  - [进程命令示例](#进程命令示例)
  - [虚拟机命令示例](#虚拟机命令示例)
  - [容器命令示例](#容器命令示例)
  - [ebpf性能追踪命令示例](#ebpf性能追踪命令示例)
  - [ftrace性能追踪工具命令示例](#ftrace性能追踪工具命令示例)
- [k8s环境容器化服务](#k8s环境容器化服务)
  - [服务介绍](#服务介绍)
  - [安装部署](#安装部署)
  - [在线更新服务配置及状态监控](#在线更新服务配置及状态监控)
  - [configmap配置数据说明](#configmap配置数据说明)

## 简介

hgvmctl 是一款专为 Hygon 全系 CPU 平台设计的面向云计算基础设施环境的性能优化工具，采用 command-line 操作模式，可应用于虚拟机、K8S 容器、裸金属负载场景下的系统资源分配优化、性能观测与追踪，并提供优化参考指导，帮助用户提高性能分析效率，提升系统性能。

## 工具特点

* 零依赖度设计：运行无需依赖任何环境配置文件、第三方工具或共享库，部署无额外前置条件；
* 极简部署方式：采用单一可执行文件形态，无需复杂安装流程，下载即可启动使用；
* 超强兼容适配：全面兼容各版本Linux x86环境，无需针对性适配改造，跨环境部署无阻碍；
* 卓越运行效率：基于编译型语言开发，具备运行速度快、系统资源开销低的特性，性能表现优异；
* 极致用户体验：操作高效易用，内置完整子命令帮助文档及示例说明，支持命令自动补全功能，降低使用门槛；
* 一键智能调优：自动化实现虚拟机/Pod环境的统一CPU/NUMA资源亲和性分配，无需手动配置，调优高效精准；
* 云原生化适配：基于Go语言开发，深度契合云原生架构设计，支持云原生环境无缝调用；
* 灵活功能拓展：支持二级命令架构及丰富Flag选项，可按需灵活配置，满足多样化使用场景；
* 广谱应用场景：广泛适配虚拟化部署、K8s 云原生容器、裸金属基础底座等多类 IT 基础设施环境；

## 下载安装

可以通过以下链接获取hgvmctl可执行文件，并直接运行：[tools | 光合开发者社区](https://download.sourcefind.cn:65024/8/main/c86-devkit/latest/tools)

```bash
wget https://download.sourcefind.cn:65024/directlink/8/c86-devkit/latest/tools/hgvmctl
chmod +x hgvmctl
```

说明：部分命令需要使用root权限执行。

## 功能介绍

hgvmctl命令总入口如下，展现工具的所有一级命令以及功能范畴概述。

``````
$ hgvmctl -h
hgvmctl is a command-line tool that provides utilities for:
- CPU topology query.
- Process affinity and scheduling management.
- Virtual machine resource query, affinity management, cgroup query and automatic affinity orchestration, etc.
- Kubernetes pod resource query, affinity management, cgroup query and automatic affinity orchestration, etc.
- A toolset for performance tracing based on Linux ftrace and perf_events.
- eBPF-based performance tracing.
- Performance optimization guides.

Usage:
  hgvmctl [flags]
  hgvmctl [command]

Available Commands:
  command-tree   Display command hierarchy in a tree-like structure
  completion     Generate the autocompletion script for the specified shell
  container      Kubernetes Pod/Container related operations
  cpu            CPU related operations
  ebpftrace      eBPF-based performance tracing
  opti-guide     Performance optimization guides
  process        Process related operations
  tracing-tools  Linux performance analysis tool collection
  version        Print the version information
  vm             Virtual machine related operations

Flags:
  -h, --help      help for hgvmctl
  -v, --version   Print the version information

Use "hgvmctl [command] --help" for more information about a command.
``````

### 辅助性命令

`hgvmctl version` 查询版本信息；

`hgvmctl completion` 配置命令自动补全；

`hgvmctl command-tree` 查询命令树；

### cpu命令集

#### cpu一级命令总览

支持CPU拓扑层级信息查询，可选择按照列表或者树形结构方式呈现。

CPU内部拓扑结构单元按照范围从小到大依次是：CPU -\> Core -\> CCX -\> NUMA -\> Socket。

``````
$ hgvmctl cpu -h
A set of commands for CPU topology query.

Usage:
  hgvmctl cpu [flags]
  hgvmctl cpu [command]

Available Commands:
  ls          List CPU topology in table view
  tree        Display CPU topology in tree structure

Flags:
  -h, --help   help for cpu

Use "hgvmctl cpu [command] --help" for more information about a command.
``````

#### cpu二级命令

* 以树形结构呈现CPU拓扑层级信息，可以清晰的观测到CPU/Core/NUMA/Socket这几级拓扑结构。
  * 支持按照CPU拓扑单元范围呈现，如CPU、CCX、NUMA、Socket；
  * 支持呈现完整CPU内部拓扑结构；

``````
$ hgvmctl cpu tree -h
Display CPU topology in tree structure
Examples:
  hgvmctl cpu tree --all         # Show all CPUs tree structure in whole system
  hgvmctl cpu tree --socket 0    # Show all CPUs tree structure in socket 0
  hgvmctl cpu tree --numa 1,2-4  # Show all CPUs tree structure in NUMA node range 1,2-4
  hgvmctl cpu tree --ccx 2-5     # Show all CPUs tree structure in CCX range 2-5
  hgvmctl cpu tree --core 1,4    # Show all CPUs tree structure in core 1 and 4
  hgvmctl cpu tree --cpu 0-3     # Show all CPUs tree structure in CPU range 0-3

Usage:
  hgvmctl cpu tree [flags]

Flags:
  -a, --all             Show all CPUs
      --ccx string      Filter by CCX ID(s) (e.g. 1,4-6)
      --core string     Filter by core ID(s) (e.g. 1,4-6)
      --cpu string      Filter by CPU IDs (e.g. 1,4-6)
  -h, --help            help for tree
      --numa string     Filter by NUMA node(s) (e.g. 1,4-6)
      --socket string   Filter by socket(s) (e.g. 1,2)
``````

* 以列表形式展现CPU拓扑层级信息。
  * 支持按照CPU拓扑单元范围呈现，如CPU、CCX、NUMA、Socket；
  * 支持呈现完整CPU内部拓扑结构；

``````
$ hgvmctl cpu ls -h
List CPU topology in table view
Examples:
  hgvmctl cpu ls --all          # List all CPUs in whole system
  hgvmctl cpu ls --cpu 0,1      # List only CPUs 0 and 1
  hgvmctl cpu ls --socket 0     # List all CPUs in socket 0
  hgvmctl cpu ls --numa 1,2-4   # List all CPUs in NUMA node range 1,2-4
  hgvmctl cpu ls --ccx 2-5      # List all CPUs in CCX range 2-5
  hgvmctl cpu ls --core 1,4     # List all CPUs in core 1 and 4

Usage:
  hgvmctl cpu ls [flags]

Flags:
  -a, --all             Show all CPUs
      --ccx string      Filter by CCX IDs (e.g. 0,1-2)
      --core string     Filter by core IDs (e.g. 0,1-2)
      --cpu string      Filter by CPU IDs (e.g. 0,1,3-5)
  -h, --help            help for ls
      --numa string     Filter by NUMA nodes (e.g. 0,1-2)
      --socket string   Filter by socket IDs (e.g. 0,1-2)
``````

### 进程命令集

#### process一级命令总览

支持进程/线程的CPU/NUMA亲和性配置与拓扑落位查询，CPU亲和性绑定，触发重新调度。

``````
$ hgvmctl process -h
A set of commands for process affinity management.

Usage:
  hgvmctl process [flags]
  hgvmctl process [command]

Available Commands:
  affinity    Display process affinity information
  bind        Bind or clear CPU affinity for process/thread
  resched     Trigger rescheduling for process/thread

Flags:
  -h, --help   help for process

Use "hgvmctl process [command] --help" for more information about a command.
``````

#### process二级命令

* 进程/线程的CPU/NUMA亲和性配置与CPU拓扑落位查询。
  * 支持对指定进程及其所有线程的查询，并显示完整command信息；
  * 支持对系统内所有进程的亲和性配置查询；

``````
$ hgvmctl process affinity -h
Display CPU and memory affinity information for a process and its threads
Examples:
  hgvmctl process affinity -p 1234       # Show affinity information for process 1234 and its threads
  hgvmctl process affinity -p 1234 -v    # Show affinity information for process 1234 and its threads with full command line
  hgvmctl process affinity -a            # Show all processes with non-full CPU affinity

Usage:
  hgvmctl process affinity [flags]

Flags:
  -a, --all       Show all processes with non-full CPU affinity
  -h, --help      help for affinity
  -p, --pid int   Process ID to query
  -v, --verbose   Show full command line
``````

* 进程/线程的CPU亲和性绑定配置。
  * 支持对指定单线程或完整进程的操作；
  * 支持按照CPU拓扑单元范围绑定，如CPU、CCX、NUMA、Socket；
  * 支持对指定单线程或完整进程清除绑定配置；
  * 注意：若进程的cgroup cpuset已被设定则可能执行失败，需清除原始cpuset设定后再执行；

``````
$ hgvmctl process bind -h
Bind or clear CPU affinity for a process and optionally its threads.
You can use "hgvmctl process resched" to trigger rescheduling for process/thread after binding operation.

Examples:
  hgvmctl process bind -p 1234 --cpu 0,2-5       # Bind single thread 1234 to CPUs 0,2-5
  hgvmctl process bind -p 1234 -a --cpu 0,2-5    # Bind process 1234 and all its threads to CPUs 0,2-5
  hgvmctl process bind -p 1234 -a --ccx 0-2      # Bind to CPUs in CCX 0-2
  hgvmctl process bind -p 1234 -a --numa 0,1     # Bind to CPUs in NUMA 0,1
  hgvmctl process bind -p 1234 -a --socket 0     # Bind to CPUs in Socket 0
  hgvmctl process bind -p 1234 --clear           # Clear binding for single process/thread 1234
  hgvmctl process bind -p 1234 -a --clear        # Clear binding for process 1234 and all its threads

Note: --cpu, --ccx, --numa, and --socket are mutually exclusive options.

Usage:
  hgvmctl process bind [flags]

Flags:
  -a, --all-threads     Operate on all threads for a given pid
      --ccx string      CCX range to bind (e.g. 0-2)
      --clear           Clear CPU affinity instead of binding
  -c, --cpu string      CPU range to bind (e.g. 0,2-5)
  -h, --help            help for bind
      --numa string     NUMA range to bind (e.g. 0,1)
  -p, --pid int         Operate on existing given pid
      --socket string   Socket range to bind (e.g. 0)
``````

* 立即触发进程/线程的重新调度，操作系统将对其调度到合适的CPU核心
  *  支持对指定单线程或完整进程的操作；

``````
$ hgvmctl process resched -h
Force process/thread to be rescheduled right now.
Examples:
  hgvmctl process resched -p 1234       # Reschedule process/thread 1234
  hgvmctl process resched -p 1234 -a    # Reschedule process 1234 and all its threads

Usage:
  hgvmctl process resched [flags]

Flags:
  -a, --all-threads   Reschedule all threads of the process
  -h, --help          help for resched
  -p, --pid int       Process/Thread ID to reschedule
``````

### 虚拟机命令集

#### vm一级命令总览

针对kvm/qemu虚拟机，支持资源信息查询，工作线程的亲和性配置与CPU拓扑落位查询，CPU/NUMA内存亲和性绑定，cgroup信息查询，内核级进程重新调度，一键自动优化CPU/NUMA内存的资源分配布局。

``````
$ hgvmctl vm -h
A set of commands to manage QEMU virtual machines running on this node.

Usage:
  hgvmctl vm [flags]
  hgvmctl vm [command]

Available Commands:
  affinity     Display CPU and memory affinity information for VMs
  bind         Bind or clear CPU affinity for the VM via OS syscall
  bind-cgroup  Bind or clear CPU/memory affinity for the VM via cgroup
  cgroup       Display cgroup paths for VMs (support cgroup v1 and v2)
  env          Display and set environment variables for hgvmctl vm operations
  ls           List the resource information of VMs
  orche        Orchestrate CPU affinity automatically for all VMs via OS syscall
  orche-cgroup Orchestrate CPU and memory affinity automatically for all VMs via cgroup
  resched      Trigger process/thread rescheduling for the VM

Flags:
  -h, --help   help for vm

Use "hgvmctl vm [command] --help" for more information about a command.
``````

#### vm二级命令

* 列出节点上虚拟机的主要资源信息。
  * 支持对指定的单台虚拟机操作；
  * 支持对所有虚拟机操作；

``````
$ hgvmctl vm ls -h
List all running QEMU virtual machines with their basic information.
This command parses the QEMU process information directly without using libvirt.

Usage:
  hgvmctl vm ls [flags]

Flags:
  -a, --all           Show all VMs (default behavior)
  -h, --help          help for ls
  -n, --name string   Filter VMs by name
``````

* 列表展示虚拟机内所有工作线程的CPU/NUMA亲和性配置与CPU拓扑落位。
  * 支持对指定的单台虚拟机操作；
  * 支持对所有虚拟机操作；
  * 支持显示完整的command信息列；

``````
$ hgvmctl vm affinity -h
Display CPU and memory affinity information for all threads of running QEMU virtual machines.

Usage:
  hgvmctl vm affinity [flags]

Flags:
  -a, --all-vms       Show affinity for all VMs
  -h, --help          help for affinity
  -n, --name string   Show affinity for specific VM
  -v, --verbose       Show full command line
``````

* 将虚拟机做CPU亲和性绑定，采用OS系统调用的配置方式。
  * 支持按照CPU拓扑单元范围绑定，如CPU、CCX、NUMA、Socket；
  * 支持保存、刷新或呈现虚拟机的亲和性绑定配置；
  * 支持亲和性配置回滚；
  * 支持绑定后立即触发操作系统级重新调度；
  * 支持按照JSON文件配置各工作线程的CPU亲和性映射，并提供模版示例；
  * 支持删除指定虚拟机的CPU亲和性绑定；
  * 支持删除节点上所有虚拟机的CPU亲和性绑定；
  * 注意：若虚拟机的cgroup cpuset已被配置则可能执行失败，可先用hgvmctl vm bind-cgroup --clear清除后再执行；

```
$ hgvmctl vm bind -h
Bind or clear CPU/memory affinity for the virtual machine via OS syscall.

Examples:
  hgvmctl vm bind --name my-vm --cpu 0-3,16-19                  # Bind CPUs for specific VM ('--no-prompt' to skip prompt)
  hgvmctl vm bind --name my-vm --cpu 0-3,16-19 --resched-now    # Bind CPUs and trigger immediate rescheduling
  hgvmctl vm bind --name my-vm --ccx 4-7                        # Bind CPUs in CCX range
  hgvmctl vm bind --name my-vm --numa 0,1                       # Bind CPUs in NUMA range
  hgvmctl vm bind --name my-vm --socket 0                       # Bind CPUs in Socket range
  hgvmctl vm bind --config /path/to/myvm.json                   # Bind for specified VMs from JSON config file
  hgvmctl vm bind --show-config-example                         # Show an example of JSON config file for VM affinity usage
  hgvmctl vm bind --refresh-affinity-record                     # Retrieve and record VMs affinity setting
  hgvmctl vm bind --show-affinity-record                        # Show content of VM affinity record file
  hgvmctl vm bind --restore --name my-vm                        # Restore specific VM affinity from record file
  hgvmctl vm bind --restore-all                                 # Restore all VMs affinity from record file
  hgvmctl vm bind --clear --name my-vm                          # Clear CPU affinity for specific VM (bind to all CPUs)
  hgvmctl vm bind --clear-all                                   # Clear CPU affinity for all running VMs (bind to all CPUs)

Note: --cpu, --ccx, --numa, and --socket are mutually exclusive options.

Usage:
  hgvmctl vm bind [flags]

Flags:
      --ccx string                CCX range to bind (e.g. 4-7)
      --clear                     Clear CPU affinity for specific VM (bind to all CPUs)
      --clear-all                 Clear CPU affinity for all running VMs (bind to all CPUs)
  -f, --config string             JSON config file for VMs affinity setting
  -c, --cpu string                CPU range to bind (e.g. 0-3,16-19)
  -h, --help                      help for bind
  -n, --name string               Virtual machine name
      --no-prompt                 Do not display prompt words
      --numa string               NUMA range to bind (e.g. 0,1)
      --refresh-affinity-record   Retrieve VMs' affinity setting and refresh the record
      --resched-now               Trigger immediate rescheduling after CPU binding
      --restore                   Restore VM affinity from record
      --restore-all               Restore all VMs affinity from record file
      --show-affinity-record      Show content of VM affinity record file
      --show-config-example       Show example about JSON config file for CPU binding
      --socket string             Socket range to bind (e.g. 0)
```

* 将虚拟机做CPU/NUMA内存亲和性绑定，采用配置cgroup cpuset的方式。
  * 支持按照CPU拓扑单元范围绑定，如CPU、CCX、NUMA、Socket；
  * 支持按照指定的内存NUMA节点范围绑定；
  * 支持绑定CPU范围时同步绑定本地内存NUMA节点范围；
  * 支持绑定后立即触发操作系统级重新调度；
  * 支持对指定虚拟机清除CPU或NUMA内存绑定配置；
  * 支持对节点上所有虚拟机清除CPU和NUMA内存绑定配置；
  * 支持cgroup v1 和 v2 版本环境；

```
$ hgvmctl vm bind-cgroup -h
Bind or clear CPU/memory affinity for the virtual machine by configuring cgroup cpuset.

Examples:
  # Bind CPUs and automatically set NUMA memory based on CPU's NUMA nodes
  hgvmctl vm bind-cgroup --name my-vm --cpu 0-3,128-131 --mem-local

  # Bind CPUs and trigger immediate rescheduling
  hgvmctl vm bind-cgroup --name my-vm --cpu 0-3,128-131 --resched-now

  # Bind CPUs in CCX range and specify NUMA memory nodes explicitly
  hgvmctl vm bind-cgroup --name my-vm --ccx 4-7 --mem 0

  # Bind CPUs in NUMA range
  hgvmctl vm bind-cgroup --name my-vm --numa 0,1

  # Bind CPUs in Socket range
  hgvmctl vm bind-cgroup --name my-vm --socket 0

  # Only bind memory NUMA nodes without changing CPU binding
  hgvmctl vm bind-cgroup --name my-vm --mem 0,1

  # Clear CPU binding only for specific VM
  hgvmctl vm bind-cgroup --name my-vm --clear-cpu

  # Clear memory binding only for specific VM
  hgvmctl vm bind-cgroup --name my-vm --clear-mem

  # Clear both CPU and memory binding for specific VM
  hgvmctl vm bind-cgroup --name my-vm --clear

  # Clear CPU and memory binding for all running VMs
  hgvmctl vm bind-cgroup --clear-all

Note: --cpu, --ccx, --numa, and --socket are mutually exclusive options.

Usage:
  hgvmctl vm bind-cgroup [flags]

Flags:
      --ccx string      CCX range to bind (e.g. 4-7)
      --clear           Clear both CPU and memory binding
      --clear-all       Clear CPU and memory binding for all running VMs
      --clear-cpu       Clear CPU binding and set to full CPU range
      --clear-mem       Clear memory binding and set to full NUMA range
  -c, --cpu string      CPU range to bind (e.g. 0-3,128-131)
  -h, --help            help for bind-cgroup
      --mem string      Specify NUMA memory nodes to bind (e.g. 0-1)
      --mem-local       Automatically set NUMA mems based on CPU's NUMA nodes
  -n, --name string     Virtual machine name (required)
      --numa string     NUMA range to bind (e.g. 0,1)
      --resched-now     Trigger immediate rescheduling after CPU binding
      --socket string   Socket range to bind (e.g. 0)
```

* 查询虚拟机的cgroup目录，兼容支持cgroup v1 和 v2 版本。
  * 支持对指定的单台虚拟机操作；
  * 支持对所有虚拟机操作；

```
$ hgvmctl vm cgroup -h
Display cgroup paths for QEMU virtual machines.
It supports both cgroup v1 and v2 environment.

Usage:
  hgvmctl vm cgroup [flags]

Flags:
  -a, --all           Show cgroup paths for all VMs
  -h, --help          help for cgroup
  -n, --name string   Show cgroup path for specific VM
```

* 立即触发虚拟机所有工作线程的内核级重新调度。
  * 支持对指定的单台虚拟机操作；
  * 支持对所有虚拟机操作；

```
$ hgvmctl vm resched -h
Trigger rescheduling for QEMU virtual machine processes and their threads.
This can be useful for forcing processes to be rescheduled on different CPUs.
Examples:
  hgvmctl vm resched --name my-vm  # Trigger rescheduling for VM my-vm processes and threads
  hgvmctl vm resched --all         # Trigger rescheduling for all running VMs

Usage:
  hgvmctl vm resched [flags]

Flags:
  -a, --all           Trigger reschedule for all VMs
  -h, --help          help for resched
  -n, --name string   Trigger reschedule for specific VM
```

* 一键自动执行节点上所有虚拟机的CPU资源分配布局，以全局视角合理配置不同规格虚拟机的CPU亲和性范围，提升整体的通用计算性能。
  * 采用OS系统调用的配置方式做资源绑定；
  * 支持 ccx-logical-core 策略，对所有虚拟机按照逻辑核心分配；
  * 支持 ccx-physical-core 策略，对所有虚拟机按照物理核心分配；
  * 支持自动分配后立即触发操作系统级重新调度；
  * 支持虚拟机CPU超分场景；
  * 注意：若虚拟机的cgroup cpuset已被配置则可能执行失败，可先用hgvmctl vm bind-cgroup --clear-all清除后再执行；

```
$ hgvmctl vm orche -h
Automatically perform CPU affinity orchestration for all running QEMU virtual machines via OS syscall.

Examples:
  hgvmctl vm orche --policy ccx-logical-core                  # Orchestrate VMs CPU affinity by 'ccx-logical-core' policy
  hgvmctl vm orche --policy ccx-physical-core                 # Orchestrate VMs CPU affinity by 'ccx-physical-core' policy
  hgvmctl vm orche --policy ccx-logical-core --resched-now    # Orchestrate and trigger immediate rescheduling
  hgvmctl vm orche --stat                                     # Show statistics of VM orchestration

Supported policies:
  ccx-logical-core: CCX-aware logical core allocation strategy for all running VMs.
  ccx-physical-core: CCX-aware physical core allocation strategy for all running VMs.

Policy explanations:
  ccx-*: allocate CPUs sharing CCX (L3 Cache) for each pod.
  ccx-physical-core: always allocate full physical cores.
  ccx-logical-core: allocate individual logical cores, which correspond to hardware threads.

Usage:
  hgvmctl vm orche [flags]

Flags:
  -h, --help            help for orche
  -p, --policy string   Orchestration policy (supported: ccx-logical-core, ccx-physical-core)
      --resched-now     Trigger immediate rescheduling after orchestration
      --stat            Show statistics of VM orchestration
```

* 一键自动执行节点上所有虚拟机的CPU及NUMA内存资源分配布局，以全局视角合理配置不同规格虚拟机的CPU和内存亲和性范围，提升整体的通用计算性能
  * 采用配置cgroup cpuset的方式做资源绑定；
  * 支持 ccx-logical-core 策略，对所有虚拟机按照逻辑核心分配；
  * 支持 ccx-physical-core 策略，对所有虚拟机按照物理核心分配；
  * 支持自动分配后立即触发操作系统级重新调度；
  * 支持虚拟机CPU超分场景；

```
$ hgvmctl vm orche-cgroup
Automatically perform CPU and memory affinity orchestration for all running QEMU virtual machines via cgroup.

Examples:
  hgvmctl vm orche-cgroup --policy ccx-logical-core                  # Orchestrate all VMs by 'ccx-logical-core' policy
  hgvmctl vm orche-cgroup --policy ccx-physical-core                 # Orchestrate all VMs by 'ccx-physical-core' policy
  hgvmctl vm orche-cgroup --policy ccx-logical-core --resched-now    # Orchestrate and trigger immediate rescheduling
  hgvmctl vm orche-cgroup --stat                                     # Show statistics of VM orchestration

Supported policies:
  ccx-logical-core: CCX-aware logical core allocation strategy for all running VMs.
  ccx-physical-core: CCX-aware physical core allocation strategy for all running VMs.

Policy explanations:
  ccx-*: allocate CPUs sharing CCX (L3 Cache) for each pod.
  ccx-physical-core: always allocate full physical cores.
  ccx-logical-core: allocate individual logical cores, which correspond to hardware threads.

Usage:
  hgvmctl vm orche-cgroup [flags]

Flags:
  -h, --help            help for orche-cgroup
  -p, --policy string   Orchestration policy (supported: ccx-logical-core, ccx-physical-core)
      --resched-now     Trigger immediate rescheduling after orchestration
      --stat            Show statistics of VM orchestration
```

* 配置虚拟机类命令的环境变量
  * 应用于为自定制虚拟化环境时，可以通过配置环境变量的方式让工具达到兼容适配；
  * 支持适配qemu可执行文件的路径；

```
$ hgvmctl vm env -h
Display and configure environment variables for hgvmctl vm operations.

Environment variables used by hgvmctl:
  HGVMCTL_QEMU_BIN: Specify the QEMU binary path for VM detection
                    Default search name: qemu-system-*, qemu-kvm

Examples:
  hgvmctl vm env                      # Show all environment variables
  export HGVMCTL_QEMU_BIN=/path/to/qemu-binary

Usage:
  hgvmctl vm env [flags]

Flags:
  -h, --help   help for env
```

### 容器命令集

#### container一级命令总览

针对Kubernetes节点环境，支持Pod资源信息查询，Pod容器的亲和性配置与CPU拓扑落位查询，Pod容器的CPU/NUMA内存亲和性绑定，cgroup信息查询，内核级进程重新调度，一键自动优化CPU/NUMA内存的资源分配布局。

``````
$ hgvmctl container -h
A set of commands to manage pods running on this Kubernetes node.

Usage:
  hgvmctl container [flags]
  hgvmctl container [command]

Available Commands:
  affinity    Display CPU and memory affinity information for pods
  bind        Bind or clear CPU/memory affinity for containers in the pod
  cgroup      Display cgroup paths for containers in the pod (support cgroup v1 and v2)
  env         Display and set environment variables for hgvmctl container operations
  ls          List the resource information of pods
  orche       Orchestrate CPU and memory affinity automatically for all pods
  resched     Trigger process/thread rescheduling for containers in the pod

Flags:
  -h, --help   help for container

Use "hgvmctl container [command] --help" for more information about a command.
``````

#### container二级命令

* 列出K8S节点上Pod的主要资源信息。
  * 支持对指定的单个Pod操作；
  * 支持对所有Pod操作；
  * 支持按照namespace或者label过滤查询；

``````
$ hgvmctl container ls -h
List the resource information of pods.

Usage:
  hgvmctl container ls [flags]

Flags:
  -a, --all                Show all pods
  -h, --help               help for ls
  -n, --namespace string   Show all pods in specific namespace
  -p, --pod string         Show specific pod (format: namespace/podname)
  -l, --selector string    Show all pods with specific labels (format: key1=value1,key2=value2)
``````

* 列表展示Pod内所有容器中进程/线程的CPU/NUMA亲和性配置与CPU拓扑落位。
  * 支持对指定的单个Pod操作；
  * 支持对所有Pod操作；
  * 支持按照namespace或者label过滤查询；
  * 支持只显示进程的主线程信息，以降低输出的行数；

``````
$ hgvmctl container affinity -h
Display CPU and memory affinity information for the running pod.

Usage:
  hgvmctl container affinity [flags]

Flags:
  -a, --all                Show affinity for all pods
  -h, --help               help for affinity
      --main-thread        Show only main thread information for each process
  -n, --namespace string   Show affinity for all pods in specific namespace
  -p, --pod string         Show affinity for specific pod (format: namespace/podname)
  -l, --selector string    Show affinity for all pods with specific labels (format: key1=value1,key2=value2)
``````

* 将Pod容器做CPU/NUMA内存亲和性绑定。
  * 支持按照CPU拓扑单元范围绑定，如CPU、CCX、NUMA、Socket；
  * 支持按照指定的内存NUMA节点范围绑定；
  * 支持绑定CPU范围时同步绑定本地内存NUMA节点范围；
  * 支持对指定的Pod或其中的某个容器操作；
  * 支持绑定后立即触发操作系统级重新调度；
  * 支持对指定Pod清除CPU或NUMA内存绑定配置；
  * 支持对节点上所有Pod清除CPU和NUMA内存绑定配置；

```
$ hgvmctl container bind -h
Bind or clear CPU/memory affinity for containers in the pod.

Examples:
  # Bind CPUs for all containers in specific pod
  hgvmctl container bind --pod namespace/podname --cpu 0-3,128-131

  # Bind CPUs and trigger immediate rescheduling
  hgvmctl container bind --pod namespace/podname --cpu 0-3,128-131 --resched-now

  # Bind CPUs for specific container in specific pod
  hgvmctl container bind --pod namespace/podname --container mycontainer --cpu 0-3

  # Bind CPUs in CCX range
  hgvmctl container bind --pod namespace/podname --ccx 4-7

  # Bind CPUs in NUMA range
  hgvmctl container bind --pod namespace/podname --numa 0,2

  # Bind CPUs in Socket range
  hgvmctl container bind --pod namespace/podname --socket 0

  # Bind CPUs and automatically set NUMA memory based on CPU's NUMA nodes
  hgvmctl container bind --pod namespace/podname --cpu 0-3 --mem-local

  # Bind CPUs and specify NUMA memory nodes explicitly
  hgvmctl container bind --pod namespace/podname --cpu 0-3 --mem 0-1

  # Clear CPU binding only for specific pod
  hgvmctl container bind --pod namespace/podname --clear-cpu

  # Clear memory binding only for specific pod
  hgvmctl container bind --pod namespace/podname --clear-mem

  # Clear both CPU and memory binding for specific pod
  hgvmctl container bind --pod namespace/podname --clear

  # Clear both CPU and memory binding for all pods on current node
  hgvmctl container bind --clear-all

Note: --cpu, --ccx, --numa, and --socket are mutually exclusive options.

Usage:
  hgvmctl container bind [flags]

Flags:
      --ccx string         CCX range to bind (e.g. 4-7)
      --clear              Clear both CPU and memory binding
      --clear-all          Clear both CPU and memory binding for all pods on current node
      --clear-cpu          Clear CPU binding and set to full CPU range
      --clear-mem          Clear memory binding and set to full NUMA range
      --container string   Specific container to bind CPUs (optional)
      --cpu string         CPU range to bind (e.g. 0-3,128-131)
  -h, --help               help for bind
      --mem string         Specify NUMA memory nodes to bind (e.g. 0-1)
      --mem-local          Automatically set NUMA mems based on CPU's NUMA nodes
      --numa string        NUMA range to bind (e.g. 0,2)
      --pod string         Pod to bind CPUs (format: namespace/podname)
      --resched-now        Trigger immediate rescheduling after CPU binding
      --socket string      Socket range to bind (e.g. 0)
```

* 查询Pod容器的cgroup目录，兼容支持cgroup v1 和 v2 版本。
  * 支持对指定的单个Pod或所有Pod操作；
  * 支持按照namespace或者label过滤查询；

```
$ hgvmctl container cgroup -h
Display cgroup paths for containers in the running pod.
It supports both cgroup v1 and v2 environment.

Usage:
  hgvmctl container cgroup [flags]

Flags:
  -a, --all                Show cgroup paths for all pods
  -h, --help               help for cgroup
  -n, --namespace string   Show cgroup paths for all pods in specific namespace
  -p, --pod string         Show cgroup paths for specific pod (format: namespace/podname)
  -l, --selector string    Show cgroup paths for all pods with specific labels (format: key1=value1,key2=value2)
```

* 立即触发Pod的内核级重新调度。
  * 支持对指定的Pod操作；
  * 支持对指定Pod中的某个容器操作；

```
$ hgvmctl container resched -h
Trigger process/thread rescheduling for containers in the pod.
This can be useful for forcing processes to be rescheduled on different CPUs.

Examples:
  # Reschedule all containers in specific pod
  hgvmctl container resched --pod namespace/podname

  # Reschedule a specific container in specific pod
  hgvmctl container resched --pod namespace/podname --container mycontainer

Usage:
  hgvmctl container resched [flags]

Flags:
      --container string   Specific container to reschedule (optional)
  -h, --help               help for resched
      --pod string         Pod to reschedule (format: namespace/podname) (required)
```

* 一键自动执行K8S节点上所有目标Pod的CPU及NUMA内存资源分配布局，以全局视角合理配置不同规格容器的CPU及NUMA内存亲和性范围，提升整体的通用计算性能。
  * 支持 ccx-physical-core-guaranteed 策略，对所有Guaranteed Qos类型Pod，按照物理核心分配（不包括超线程核心）；
  * 支持 ccx-logical-core-guaranteed 策略，对所有Guaranteed Qos类型Pod，按照逻辑核心分配（包括超线程核心）；
  * 支持 ccx-physical-core 策略，对所有指定request CPU的目标Pod，按照物理核心分配，可按照namespace指定pod范围；
  * 支持 ccx-logical-core 策略，对所有指定request CPU的目标Pod，按照逻辑核心分配，可按照namespace指定pod范围；
  * 支持自动分配后立即触发操作系统级重新调度；

```
$ hgvmctl container orche -h
Automatically perform CPU and memory affinity orchestration for pods.

Examples:
  hgvmctl container orche --policy ccx-physical-core-guaranteed      # Orchestrate all Guaranteed Qos class pods by 'ccx-physical-core-guaranteed' policy
  hgvmctl container orche --policy ccx-logical-core-guaranteed       # Orchestrate all Guaranteed Qos class pods by 'ccx-logical-core-guaranteed' policy
  hgvmctl container orche --policy ccx-physical-core                 # Orchestrate all pods based on CPU requests by 'ccx-physical-core' policy
  hgvmctl container orche --policy ccx-logical-core                  # Orchestrate all pods based on CPU requests by 'ccx-logical-core' policy
  hgvmctl container orche --policy ccx-logical-core --resched-now    # Orchestrate and trigger immediate rescheduling
  hgvmctl container orche --stat                                     # Show statistics of pod orchestration

  # Namespace filtering options (for ccx-physical-core or ccx-logical-core policies):
  hgvmctl container orche --policy ccx-physical-core --namespace default,kube-system    # Only orchestrate pods in specific namespaces
  hgvmctl container orche --policy ccx-logical-core --exclude-namespace kube-system     # Orchestrate all pods except those in kube-system

Supported policies:
  ccx-physical-core-guaranteed: CCX-aware physical core allocation strategy exclusively for guaranteed QoS class pods.
  ccx-logical-core-guaranteed: CCX-aware logical core allocation strategy exclusively for guaranteed QoS class pods.
  ccx-physical-core: CCX-aware physical core allocation strategy for all pods based on CPU request values.
  ccx-logical-core: CCX-aware logical core allocation strategy for all pods based on CPU request values.

Policy explanations:
  ccx-*: allocate CPUs sharing CCX (L3 Cache) for each pod.
  *-physical-core-*: always allocate full physical cores.
  *-logical-core-*: allocate individual logical cores, which correspond to hardware threads.
  *-guaranteed: allocate CPUs for all Guaranteed Qos class pods, ignore Burstable or BestEffort Qos class pods.

Usage:
  hgvmctl container orche [flags]

Flags:
      --exclude-namespace string   Orchestrate all pods except those in specified namespaces (comma-separated)
  -h, --help                       help for orche
      --namespace string           Only orchestrate pods in specified namespaces (comma-separated, e.g., default,kube-system)
  -p, --policy string              Orchestration policy
      --resched-now                Trigger immediate rescheduling after orchestration
      --stat                       Show statistics of pod orchestration
```

* 配置k8s容器类命令的环境变量
  * 当应用于为非默认的定制化k8s环境时，可以通过配置环境变量的方式让工具达到兼容适配；
  * 支持适配kubeconfig文件路径；
  * 支持适配CRI容器运行时的socket文件路径；
  * 支持适配集群节点的node name；

```
$ hgvmctl container env -h
Display and configure environment variables for hgvmctl container operations.

Environment variables used by hgvmctl container commands:
  HGVMCTL_KUBE_CONFIG: Specify the kubeconfig file path for Kubernetes client
                       Default search paths: $KUBECONFIG, $HOME/.kube/config, /etc/kubernetes/admin.conf
  HGVMCTL_CRI_SOCK:    Specify the container runtime unix domain socket file
                       Default search paths: /run/containerd/containerd.sock
  HGVMCTL_NODE_NAME:   Specify node name
                       Default: hostname value in /etc/hostname

Examples:
  hgvmctl container env                      # Show all environment variables
  export HGVMCTL_KUBE_CONFIG=/path/to/kubeconfig
  export HGVMCTL_CRI_SOCK=/path/to/containerd.sock
  export HGVMCTL_NODE_NAME=my_node

Usage:
  hgvmctl container env [flags]

Flags:
  -h, --help   help for env
```

### ebpf性能追踪命令集

#### ebpftrace一级命令总览

支持基于Linux eBPF技术的性能追踪。

注意：需要操作系统内核支持eBPF。

``````
$ hgvmctl ebpftrace -h
eBPF-based performance tracing.

Usage:
  hgvmctl ebpftrace [command]

Available Commands:
  vm-exit     Show VM-exit statistics for KVM virtual machines.

Flags:
  -h, --help   help for ebpftrace

Use "hgvmctl ebpftrace [command] --help" for more information about a command.
``````

#### ebpftrace二级命令

* 使用eBPF追踪KVM虚拟机的vm exit事件，统计并显示vm exit原因。
  * 支持实时追踪或设置追踪时长；
  * 支持指定虚拟机进程PID、vCPU线程TID或编号；

``````
$ hgvmctl ebpftrace vm-exit -h
Use eBPF to trace KVM exit events and provides detailed statistics about why virtual machines are exiting to the hypervisor.

Usage:
  hgvmctl ebpftrace vm-exit [duration] [flags]

Examples:
  hgvmctl ebpftrace vm-exit                     # Display kvm_exit_reason and its statistics in real-time until Ctrl-C
  hgvmctl ebpftrace vm-exit 5                   # Display in real-time after sleeping 5s
  hgvmctl ebpftrace vm-exit -n my-vm            # Display for a specific virtual machine
  hgvmctl ebpftrace vm-exit -p 19651            # Collapse all tids for pid 19651 with exit reasons sorted in descending order
  hgvmctl ebpftrace vm-exit -p 19651 5          # Collapse all tids for pid 19651 with exit reasons sorted in descending order, and display after sleeping 5s
  hgvmctl ebpftrace vm-exit -p 19651 -v 0       # Display only vcpu0 for pid 19651, descending sort by default
  hgvmctl ebpftrace vm-exit -p 19651 -a         # Display all tids for pid 19651
  hgvmctl ebpftrace vm-exit -t 19680            # Display only for tid 19680 with exit reasons sorted in descending order
  hgvmctl ebpftrace vm-exit -t 19680 5          # Display only for tid 19680 with exit reasons sorted in descending order after sleeping 5s
  hgvmctl ebpftrace vm-exit -T '19680,19681'    # Display for a union like {19680, 19681}

Flags:
  -a, --all-tids      trace all tids for this pid
  -d, --debug         enable debug facilities
  -h, --help          help for vm-exit
  -n, --name string   trace virtual machine by name
  -p, --pid int       trace this PID only
  -t, --tid int       trace this TID only
  -T, --tids string   trace a comma separated series of tids with no space in between
  -v, --vcpu int      trace this vcpu only (default -1)
``````

### ftrace性能追踪工具集

基于Linux Ftrace技术汇总提供了一套工具集，可以对kernel、system、syscall、fs、disk、net等领域做出性能追踪。

注意：需要操作系统内核支持Ftrace并已挂载tracefs文件系统，系统默认支持。

使用命令时，可通过 -h 分别查看相关的使用帮助。

```
$ hgvmctl tracing-tools -h
A miscellaneous collection of performance analysis tools for Linux ftrace and perf_events (aka the "perf" command).

Prerequisites:
Make sure you have configured Ftrace in the kernel and installed "perf" command.

Tools Summary:
+---------------------------+----------+--------+---------------------------------------------------------------+
| Usage                     | Category | Tech   | Description                                                   |
+---------------------------+----------+--------+---------------------------------------------------------------+
| hgvmctl funccount -h      | kernel   | Ftrace | count kernel function calls matching specified wildcards      |
| hgvmctl funcgraph -h      | kernel   | Ftrace | trace kernel function graph, showing child function calls     |
| hgvmctl funcslower -h     | kernel   | Ftrace | trace kernel functions slower than a threshold (microseconds) |
| hgvmctl functrace -h      | kernel   | Ftrace | trace kernel function calls matching specified wildcards      |
| hgvmctl kprobe -h         | kernel   | Ftrace | trace a given kprobe definition. Kernel dynamic tracing       |
| hgvmctl tpoint -h         | system   | Ftrace | trace a given tracepoint. Static tracing                      |
| hgvmctl uprobe -h         | user     | Ftrace | trace a given uprobe definition. User-level dynamic tracing   |
| hgvmctl execsnoop -h      | syscall  | Ftrace | trace process exec() with arguments                           |
| hgvmctl killsnoop -h      | syscall  | Ftrace | trace kill() syscalls with signal/process details             |
| hgvmctl opensnoop -h      | syscall  | Ftrace | trace open() syscalls with file details                       |
| hgvmctl syscount -h       | syscall  | perf   | count system calls                                            |
| hgvmctl cachestat -h      | fs       | Ftrace | show Linux page cache hit/miss statistics                     |
| hgvmctl bitesize -h       | disk     | perf   | show disk I/O size as a histogram                             |
| hgvmctl iolatency -h      | disk     | Ftrace | summarize block device I/O latency as a histogram             |
| hgvmctl iosnoop -h        | disk     | Ftrace | trace block device I/O                                        |
| hgvmctl tcpretrans -h     | net      | Ftrace | show TCP retransmts, with address and other details           |
| hgvmctl perf-stat-hist -h | misc     | perf   | perf_events stat histogram hack                               |
| hgvmctl reset-ftrace -h   | tool     | Ftrace | reset state of ftrace, disabling all tracing                  |
+---------------------------+----------+--------+---------------------------------------------------------------+
```

### 性能优化参考指导

按照几类优化方向，列出虚拟机及容器等应用场景下的一些常用优化方法与指导建议。

注意：需设置环境变量 HGVMCTL\_USER 以启用此功能。

```
$ hgvmctl opti-guide -h
opti-guide provides performance optimization guidance for different domains including:
- GRUB bootloader configuration
- BIOS settings
- Device optimization
- Operating system tuning
- Application optimization
- Network performance
- Container optimization
- Virtual machine optimization

Usage:
  hgvmctl opti-guide [flags]
  hgvmctl opti-guide [command]

Available Commands:
  app         Application optimization guide
  bios        BIOS/UEFI settings optimization guide
  container   Container optimization guide
  device      Device optimization guide
  devkit      C86-Devkit optimization guide
  grub        GRUB bootloader optimization guide
  net         Network optimization guide
  os          Operating system optimization guide
  vm          Virtual machine optimization guide

Flags:
  -h, --help   help for opti-guide

Use "hgvmctl opti-guide [command] --help" for more information about a command.
```

## 典型使用示例

下面用一系列典型的实验介绍hgvmctl工具命令的使用方法。

### cpu命令示例

* 查询系统中CCX 0,2-4范围的CPU拓扑结构，以树状形式展示，可以观察到涉及目标查询单元的上下级拓扑映射

```
$ hgvmctl cpu tree --ccx 0,2-4
System
├── Socket 0
    ├── NUMA 0
        ├── CCX 0
            ├── Core 0
                └── CPUs: [0 128]
            ├── Core 1
                └── CPUs: [1 129]
            ├── Core 2
                └── CPUs: [2 130]
            ├── Core 3
                └── CPUs: [3 131]
        ├── CCX 2
            ├── Core 8
                └── CPUs: [8 136]
            ├── Core 9
                └── CPUs: [9 137]
            ├── Core 10
                └── CPUs: [10 138]
            ├── Core 11
                └── CPUs: [11 139]
        ├── CCX 3
            ├── Core 12
                └── CPUs: [12 140]
            ├── Core 13
                └── CPUs: [13 141]
            ├── Core 14
                └── CPUs: [14 142]
            ├── Core 15
                └── CPUs: [15 143]
    ├── NUMA 1
        ├── CCX 4
            ├── Core 16
                └── CPUs: [16 144]
            ├── Core 17
                └── CPUs: [17 145]
            ├── Core 18
                └── CPUs: [18 146]
            ├── Core 19
                └── CPUs: [19 147]
```

### 进程命令示例

* 查询进程PID 360620的CPU/NUMA亲和性配置与CPU拓扑落位，可观察到当前各子线程的CPU核心落位分布情况。
  * 列表显示包括其所有子线程；
  * TID：线程ID；
  * Allowed\_CPUs：CPU的亲和性绑定范围；
  * Allowed\_Mems：内存NUMA节点的亲和性绑定范围；
  * Last\_CPU：当前的CPU核心落位；
  * Socket/NUMA/CCX/Core：当前CPU核心落位所对应的CPU拓扑单元ID；
  * Command：线程所对应的命令；

```
$ hgvmctl process affinity -p 360620
PID     TID     Allowed_CPUs  Allowed_Mems  Last_CPU  Socket  NUMA  CCX  Core  Command
360620  360620  0-255         0-7           3         0       0     0    3     /usr/libexec/qemu-kvm -name...
360620  360634  0-255         0-7           32        0       2     8    32    qemu-kvm
360620  360640  0-255         0-7           2         0       0     0    2     IO mon_iothread
360620  360641  0-255         0-7           35        0       2     8    35    CPU 0/KVM
360620  360642  0-255         0-7           33        0       2     8    33    CPU 1/KVM
360620  360643  0-255         0-7           132       0       0     1    4     CPU 2/KVM
360620  360644  0-255         0-7           128       0       0     0    0     CPU 3/KVM
360620  360646  0-255         0-7           131       0       0     0    3     vnc_worker
```

* 对主线程360620绑定到CPU核心范围3-5

```
$ hgvmctl process bind -p 360620 --cpu 3-5
Successfully bound PID 360620 process to CPUs 3-5
```

* 对主线程360620触发重新调度

```
$ hgvmctl process resched -p 360620
Successfully triggered rescheduling for process 360620
```

* 对子线程360644绑定到CPU核心范围11-15

```
$ hgvmctl process bind -p 360644 --cpu 11-15
Successfully bound PID 360644 process to CPUs 11-15
```

* 对子线程360644触发重新调度

```
$ hgvmctl process resched -p 360644
Successfully triggered rescheduling for thread 360644
```

* 再次查询进程360620的亲和性，获知当前主线程和子线程的CPU亲和性配置和落位拓扑情况

```
$ hgvmctl process affinity -p 360620
PID     TID     Allowed_CPUs  Allowed_Mems  Last_CPU  Socket  NUMA  CCX  Core  Command
360620  360620  3-5           0-7           3         0       0     0    3     /usr/libexec/qemu-kvm -name...
360620  360634  0-255         0-7           1         0       0     0    1     qemu-kvm
360620  360640  0-255         0-7           2         0       0     0    2     IO mon_iothread
360620  360641  0-255         0-7           7         0       0     1    7     CPU 0/KVM
360620  360642  0-255         0-7           132       0       0     1    4     CPU 1/KVM
360620  360643  0-255         0-7           5         0       0     1    5     CPU 2/KVM
360620  360644  11-15         0-7           11        0       0     2    11    CPU 3/KVM
360620  360646  0-255         0-7           131       0       0     0    3     vnc_worker
```

* 对进程360620及其所有子线程清除CPU核心绑定

```
$ hgvmctl process bind -p 360620 -a --clear
Successfully cleared CPU affinity for PID 360620 (process and threads)
```

* 对进程360620及其所有子线程触发重新调度

```
$ hgvmctl process resched -p 360620 -a
Successfully triggered rescheduling for process and threads 360620
```

* 再次查询进程360620的亲和性，获知CPU的亲和性配置已还原

```
$ hgvmctl process affinity -p 360620
PID     TID     Allowed_CPUs  Allowed_Mems  Last_CPU  Socket  NUMA  CCX  Core  Command
360620  360620  0-255         0-7           3         0       0     0    3     /usr/libexec/qemu-kvm -name...
360620  360634  0-255         0-7           32        0       2     8    32    qemu-kvm
360620  360640  0-255         0-7           2         0       0     0    2     IO mon_iothread
360620  360641  0-255         0-7           35        0       2     8    35    CPU 0/KVM
360620  360642  0-255         0-7           33        0       2     8    33    CPU 1/KVM
360620  360643  0-255         0-7           132       0       0     1    4     CPU 2/KVM
360620  360644  0-255         0-7           11        0       0     2    11    CPU 3/KVM
360620  360646  0-255         0-7           131       0       0     0    3     vnc_worker
```

### 虚拟机命令示例

* 查询虚拟机centos7.0-1的资源信息

```
$ hgvmctl vm ls -n centos7.0-1
Name         PID     vCPU  Memory(GB)  Source_file
centos7.0-1  360620  4     2.00        /var/lib/libvirt/images/centos7.0-1.qcow2
```

* 查询虚拟机centos7.0-1的CPU/NUMA亲和性配置与CPU拓扑落位，可观察到当前含vCPU各工作线程的CPU核心落位分布情况，各列含义与hgvmctl process affinity相同

```
$ hgvmctl vm affinity -n centos7.0-1
Name         PID     TID     Allowed_CPUs  Allowed_Mems  Last_CPU  Socket  NUMA  CCX  Core  Command
centos7.0-1  360620  360620  0-255         0-7           128       0       0     0    0     /usr/libexec/qemu-kvm -name...
centos7.0-1  360620  360634  0-255         0-7           32        0       2     8    32    qemu-kvm
centos7.0-1  360620  360640  0-255         0-7           2         0       0     0    2     IO mon_iothread
centos7.0-1  360620  360641  0-255         0-7           35        0       2     8    35    CPU 0/KVM
centos7.0-1  360620  360642  0-255         0-7           33        0       2     8    33    CPU 1/KVM
centos7.0-1  360620  360643  0-255         0-7           8         0       0     2    8     CPU 2/KVM
centos7.0-1  360620  360644  0-255         0-7           128       0       0     0    0     CPU 3/KVM
centos7.0-1  360620  360646  0-255         0-7           131       0       0     0    3     vnc_worker
```

* 对虚拟机centos7.0-1绑定到CPU核心范围12-15，同意保存虚拟机亲和性配置，并立刻触发重新调度

```
$ hgvmctl vm bind -n centos7.0-1 --cpu 12-15 --resched-now
Before performing this operation, do you want to record current VM affinity setting so that it can be used to restore setting in the future?
Choose [Y/n], default is 'yes': yes
Successfully refreshed affinity record at: /opt/hygon/hgvmctl/vm-affinity-record.json
VM affinity record has been updated
Successfully bound VM 'centos7.0-1' (PID: 360620, vCPU: 4) to CPUs: 12-15
Successfully triggered reschedule for VM 'centos7.0-1' (PID 360620)
Successfully bound VM 'centos7.0-1' to CPUs: 12-15
```

* 再次查询虚拟机centos7.0-1的CPU/NUMA亲和性配置与CPU拓扑落位，可观察到各工作线程已被绑定CPU核心范围12-15，均落位到CCX3范围

```
$ hgvmctl vm affinity -n centos7.0-1
Name         PID     TID     Allowed_CPUs  Allowed_Mems  Last_CPU  Socket  NUMA  CCX  Core  Command
centos7.0-1  360620  360620  12-15         0-7           14        0       0     3    14    /usr/libexec/qemu-kvm -name...
centos7.0-1  360620  360634  12-15         0-7           12        0       0     3    12    qemu-kvm
centos7.0-1  360620  360640  12-15         0-7           13        0       0     3    13    IO mon_iothread
centos7.0-1  360620  360641  12-15         0-7           12        0       0     3    12    CPU 0/KVM
centos7.0-1  360620  360642  12-15         0-7           12        0       0     3    12    CPU 1/KVM
centos7.0-1  360620  360643  12-15         0-7           13        0       0     3    13    CPU 2/KVM
centos7.0-1  360620  360644  12-15         0-7           13        0       0     3    13    CPU 3/KVM
centos7.0-1  360620  360646  12-15         0-7           12        0       0     3    12    vnc_worker
```

* 对虚拟机centos7.0-1执行CPU亲和性配置回滚

```
$ hgvmctl vm bind -n centos7.0-1 --restore
Bound process 360620 to CPUs: 0-255
Successfully triggered reschedule for VM 'centos7.0-1' (PID 360620)
Bound thread 360634 to CPUs: 0-255
Successfully triggered reschedule for thread 360634
Bound thread 360640 to CPUs: 0-255
Successfully triggered reschedule for thread 360640
Bound thread 360641 to CPUs: 0-255
Successfully triggered reschedule for thread 360641
Bound thread 360642 to CPUs: 0-255
Successfully triggered reschedule for thread 360642
Bound thread 360643 to CPUs: 0-255
Successfully triggered reschedule for thread 360643
Bound thread 360644 to CPUs: 0-255
Successfully triggered reschedule for thread 360644
Bound thread 360646 to CPUs: 0-255
Successfully triggered reschedule for thread 360646
Successfully restored CPU affinity for VM 'centos7.0-1'
```

* 对虚拟机centos7.0-1立刻触发重新调度，操作系统将对工作线程调度到合适的CPU核心

```
$ hgvmctl vm resched -n centos7.0-1
Successfully triggered reschedule for centos7.0-1 (PID 360620)
```

* 再次查询虚拟机centos7.0-1的CPU/NUMA亲和性配置与CPU拓扑落位，可观察到各工作线程的CPU亲和性恢复原状，CPU落位分散

```
$ hgvmctl vm affinity -n centos7.0-1
Name         PID     TID     Allowed_CPUs  Allowed_Mems  Last_CPU  Socket  NUMA  CCX  Core  Command
centos7.0-1  360620  360620  0-255         0-7           14        0       0     3    14    /usr/libexec/qemu-kvm -name...
centos7.0-1  360620  360634  0-255         0-7           12        0       0     3    12    qemu-kvm
centos7.0-1  360620  360640  0-255         0-7           15        0       0     3    15    IO mon_iothread
centos7.0-1  360620  360641  0-255         0-7           32        0       2     8    32    CPU 0/KVM
centos7.0-1  360620  360642  0-255         0-7           33        0       2     8    33    CPU 1/KVM
centos7.0-1  360620  360643  0-255         0-7           136       0       0     2    8     CPU 2/KVM
centos7.0-1  360620  360644  0-255         0-7           13        0       0     3    13    CPU 3/KVM
centos7.0-1  360620  360646  0-255         0-7           142       0       0     3    14    vnc_worker
```

* 按照cgroup cpuset配置的方式，绑定虚拟机的CPU核心范围在NUMA 0节点范围，绑定内存为本地即NUMA 0节点，并立即触发重新调度

```
$ hgvmctl vm bind-cgroup -n kylin-v11-2503 --numa 0 --mem-local
Found 7 cgroup subdirectories to configure:
  1. emulator
  2. iothread1
  3. iothread2
  4. vcpu0
  5. vcpu1
  6. vcpu2
  7. vcpu3
Calculated CPU list from topology: 0-15,128-143
Calculated memory nodes from CPU NUMA affinity: 0

Applying cgroup configuration...
  ✓ emulator: CPUs: 0-15,128-143, Memory: 0
  ✓ iothread1: CPUs: 0-15,128-143, Memory: 0
  ✓ iothread2: CPUs: 0-15,128-143, Memory: 0
  ✓ vcpu0: CPUs: 0-15,128-143, Memory: 0
  ✓ vcpu1: CPUs: 0-15,128-143, Memory: 0
  ✓ vcpu2: CPUs: 0-15,128-143, Memory: 0
  ✓ vcpu3: CPUs: 0-15,128-143, Memory: 0

Successfully configured 7/7 cgroup directories

Successfully bound VM 'kylin-v11-2503' to CPUs: 0-15,128-143, Memory nodes: 0
```

* 查询cgroup路径，验证cgroup cpuset的配置结果，观察CPU/NUMA内存的亲和性配置

```
$ hgvmctl vm cgroup -n kylin-v11-2503
Name            PID     Cgroup_v1_Path(cpuset)
kylin-v11-2503  377532  /sys/fs/cgroup/cpuset/machine.slice/machine-qemu\\x2d22\\x2dkylin\\x2dv11\\x2d2503.scope/libvirt/emulator
$ cat /sys/fs/cgroup/cpuset/machine.slice/machine-qemu\\x2d22\\x2dkylin\\x2dv11\\x2d2503.scope/libvirt/emulator/cpuset.cpus
0-15,128-143
$ cat /sys/fs/cgroup/cpuset/machine.slice/machine-qemu\\x2d22\\x2dkylin\\x2dv11\\x2d2503.scope/libvirt/emulator/cpuset.mems
0
$ hgvmctl vm affinity -n kylin-v11-2503
Name            PID     TID     Allowed_CPUs  Allowed_Mems  Last_CPU  Socket  NUMA  CCX  Core  Command
kylin-v11-2503  377532  377532  0-15,128-143  0             4         0       0     1    4     /usr/libexec/qemu-kvm -name...
kylin-v11-2503  377532  377553  0-15,128-143  0             130       0       0     0    2     qemu-kvm
kylin-v11-2503  377532  377554  0-15,128-143  0             131       0       0     0    3     IO iothread1
kylin-v11-2503  377532  377555  0-15,128-143  0             132       0       0     1    4     IO iothread2
kylin-v11-2503  377532  377560  0-15,128-143  0             3         0       0     0    3     IO mon_iothread
kylin-v11-2503  377532  377561  0-15,128-143  0             12        0       0     3    12    CPU 0/KVM
kylin-v11-2503  377532  377562  0-15,128-143  0             15        0       0     3    15    CPU 1/KVM
kylin-v11-2503  377532  377563  0-15,128-143  0             14        0       0     3    14    CPU 2/KVM
kylin-v11-2503  377532  377564  0-15,128-143  0             143       0       0     3    15    CPU 3/KVM
kylin-v11-2503  377532  377566  0-15,128-143  0             2         0       0     0    2     vnc_worker
kylin-v11-2503  377532  830675  0-15,128-143  0             135       0       0     1    7     worker
```

### 容器命令示例

* 查询Pod stress-test-6db5df8b6-rjjxt的资源信息，其namespace为default

```
$ hgvmctl container ls --pod default/stress-test-6db5df8b6-rjjxt
Namespace  Pod                          Container          Qos         CPU.request  Memory.request  CPU.limit  Memory.limit
default    stress-test-6db5df8b6-rjjxt  stress-container1  Guaranteed  2            256Mi           2          256Mi
default    stress-test-6db5df8b6-rjjxt  stress-container2  Guaranteed  2            256Mi           2          256Mi
```

* 查询Pod的CPU/NUMA内存的亲和性配置与CPU拓扑落位，可观察到当前Pod内各容器中进程/线程的CPU核心落位分布情况，各列含义与hgvmctl process affinity相同

```
$ hgvmctl container affinity --pod default/stress-test-6db5df8b6-rjjxt
Namespace  Pod                          Container          PID     TID     Allowed_CPUs  Allowed_Mems  Last_CPU  Socket  NUMA  CCX  Core  Command
default    stress-test-6db5df8b6-rjjxt  stress-container1  418708  418708  0-255         0-7           65        1       4     16   1     stress --cpu 2 --vm 1 --vm-...
default    stress-test-6db5df8b6-rjjxt  stress-container1  418721  418721  0-255         0-7           64        1       4     16   0     stress --cpu 2 --vm 1 --vm-...
default    stress-test-6db5df8b6-rjjxt  stress-container1  418722  418722  0-255         0-7           119       1       7     29   55    stress --cpu 2 --vm 1 --vm-...
default    stress-test-6db5df8b6-rjjxt  stress-container1  418723  418723  0-255         0-7           177       0       3     12   49    stress --cpu 2 --vm 1 --vm-...
Namespace  Pod                          Container          PID     TID     Allowed_CPUs  Allowed_Mems  Last_CPU  Socket  NUMA  CCX  Core  Command
default    stress-test-6db5df8b6-rjjxt  stress-container2  418744  418744  0-255         0-7           21        0       1     5    21    stress --cpu 2 --vm 1 --vm-...
default    stress-test-6db5df8b6-rjjxt  stress-container2  418759  418759  0-255         0-7           157       0       1     7    29    stress --cpu 2 --vm 1 --vm-...
default    stress-test-6db5df8b6-rjjxt  stress-container2  418760  418760  0-255         0-7           19        0       1     4    19    stress --cpu 2 --vm 1 --vm-...
default    stress-test-6db5df8b6-rjjxt  stress-container2  418761  418761  0-255         0-7           155       0       1     6    27    stress --cpu 2 --vm 1 --vm-...
```

* 绑定Pod的CPU核心范围在NUMA 0节点范围，绑定内存为本地即NUMA 0节点，并立即触发重新调度

```
$ hgvmctl container bind --pod default/stress-test-6db5df8b6-rjjxt --numa 0 --mem-local --resched-now
Calculated CPU list: 0-15,128-143
Calculated NUMA mems from CPUs: 0
Binding resources for all containers in pod default/stress-test-6db5df8b6-rjjxt
Setting NUMA mems to 0 for container stress-container1
Successfully bound CPUs 0-15,128-143 and NUMA mems 0 for container stress-container1
Successfully triggered reschedule for container stress-container1 after binding
Setting NUMA mems to 0 for container stress-container2
Successfully bound CPUs 0-15,128-143 and NUMA mems 0 for container stress-container2
Successfully triggered reschedule for container stress-container2 after binding
```

* 再次查询Pod的CPU/NUMA内存的亲和性配置与CPU拓扑落位，可观察到当前Pod内各容器中进程/线程的亲和性配置和CPU拓扑落位情况，已在NUMA 0节点范围内

```
$ hgvmctl container affinity --pod default/stress-test-6db5df8b6-rjjxt
Namespace  Pod                          Container          PID     TID     Allowed_CPUs  Allowed_Mems  Last_CPU  Socket  NUMA  CCX  Core  Command
default    stress-test-6db5df8b6-rjjxt  stress-container1  418708  418708  0-15,128-143  0             0         0       0     0    0     stress --cpu 2 --vm 1 --vm-...
default    stress-test-6db5df8b6-rjjxt  stress-container1  418721  418721  0-15,128-143  0             14        0       0     3    14    stress --cpu 2 --vm 1 --vm-...
default    stress-test-6db5df8b6-rjjxt  stress-container1  418722  418722  0-15,128-143  0             8         0       0     2    8     stress --cpu 2 --vm 1 --vm-...
default    stress-test-6db5df8b6-rjjxt  stress-container1  418723  418723  0-15,128-143  0             140       0       0     3    12    stress --cpu 2 --vm 1 --vm-...
Namespace  Pod                          Container          PID     TID     Allowed_CPUs  Allowed_Mems  Last_CPU  Socket  NUMA  CCX  Core  Command
default    stress-test-6db5df8b6-rjjxt  stress-container2  418744  418744  0-15,128-143  0             0         0       0     0    0     stress --cpu 2 --vm 1 --vm-...
default    stress-test-6db5df8b6-rjjxt  stress-container2  418759  418759  0-15,128-143  0             4         0       0     1    4     stress --cpu 2 --vm 1 --vm-...
default    stress-test-6db5df8b6-rjjxt  stress-container2  418760  418760  0-15,128-143  0             10        0       0     2    10    stress --cpu 2 --vm 1 --vm-...
default    stress-test-6db5df8b6-rjjxt  stress-container2  418761  418761  0-15,128-143  0             128       0       0     0    0     stress --cpu 2 --vm 1 --vm-...
```

* 绑定Pod内的容器stress-container2的CPU核心在CCX 8-11范围，绑定内存为NUMA 2节点，并立即触发重新调度

```
$ hgvmctl container bind --pod default/stress-test-6db5df8b6-rjjxt --container stress-container2 --ccx 8-11 --mem 2 --resched-now
Calculated CPU list: 32-47,160-175
Binding resources for container stress-container2 in pod default/stress-test-6db5df8b6-rjjxt
Setting NUMA mems to 2 for container stress-container2
Successfully bound CPUs 32-47,160-175 and NUMA mems 2 for container stress-container2
Successfully triggered reschedule for container stress-container2 after binding
```

* 再次查询Pod的CPU/NUMA内存的亲和性配置与CPU拓扑落位，可观察到当前Pod内容器stress-container2中进程/线程的亲和性配置和CPU拓扑落位情况，CPU核心已在CCX 8-11范围内，内存使用NUMA 2节点，容器stress-container1则保持不变

```
$ hgvmctl container affinity --pod default/stress-test-6db5df8b6-rjjxt
Namespace  Pod                          Container          PID     TID     Allowed_CPUs  Allowed_Mems  Last_CPU  Socket  NUMA  CCX  Core  Command
default    stress-test-6db5df8b6-rjjxt  stress-container1  418708  418708  0-15,128-143  0             0         0       0     0    0     stress --cpu 2 --vm 1 --vm-...
default    stress-test-6db5df8b6-rjjxt  stress-container1  418721  418721  0-15,128-143  0             4         0       0     1    4     stress --cpu 2 --vm 1 --vm-...
default    stress-test-6db5df8b6-rjjxt  stress-container1  418722  418722  0-15,128-143  0             8         0       0     2    8     stress --cpu 2 --vm 1 --vm-...
default    stress-test-6db5df8b6-rjjxt  stress-container1  418723  418723  0-15,128-143  0             140       0       0     3    12    stress --cpu 2 --vm 1 --vm-...
Namespace  Pod                          Container          PID     TID     Allowed_CPUs   Allowed_Mems  Last_CPU  Socket  NUMA  CCX  Core  Command
default    stress-test-6db5df8b6-rjjxt  stress-container2  418744  418744  32-47,160-175  2             32        0       2     8    32    stress --cpu 2 --vm 1 --vm-...
default    stress-test-6db5df8b6-rjjxt  stress-container2  418759  418759  32-47,160-175  2             44        0       2     11   44    stress --cpu 2 --vm 1 --vm-...
default    stress-test-6db5df8b6-rjjxt  stress-container2  418760  418760  32-47,160-175  2             36        0       2     9    36    stress --cpu 2 --vm 1 --vm-...
default    stress-test-6db5df8b6-rjjxt  stress-container2  418761  418761  32-47,160-175  2             163       0       2     8    35    stress --cpu 2 --vm 1 --vm-...
```

* 查询获取Pod内两个容器的cgroup目录地址，进一步可查询到cpuset的数值

```
$ hgvmctl container cgroup --pod default/stress-test-6db5df8b6-rjjxt
Namespace  Pod                          Container          Cgroup_v1_Path(cpuset)
default    stress-test-6db5df8b6-rjjxt  stress-container1  /sys/fs/cgroup/cpuset/kubepods.slice/kubepods-pod9505d42d_30c8_4af7_b4b5_b695e72fa2c4.slice/cri-containerd-a8ccb810ad42b55e2eb09c09d5b2ee30b9b1a9630dce2dc3f6d14133840b389f.scope
default    stress-test-6db5df8b6-rjjxt  stress-container2  /sys/fs/cgroup/cpuset/kubepods.slice/kubepods-pod9505d42d_30c8_4af7_b4b5_b695e72fa2c4.slice/cri-containerd-0c50fc14e8fb5a89fca14fb2b38b5ebcd5fe1e54e14b4a4ac0be82587bd7f47a.scope
$
$ cat /sys/fs/cgroup/cpuset/kubepods.slice/kubepods-pod9505d42d_30c8_4af7_b4b5_b695e72fa2c4.slice/cri-containerd-a8ccb810ad42b55e2eb09c09d5b2ee30b9b1a9630dce2dc3f6d14133840b389f.scope/cpuset.cpus
0-15,128-143
$ cat /sys/fs/cgroup/cpuset/kubepods.slice/kubepods-pod9505d42d_30c8_4af7_b4b5_b695e72fa2c4.slice/cri-containerd-a8ccb810ad42b55e2eb09c09d5b2ee30b9b1a9630dce2dc3f6d14133840b389f.scope/cpuset.mems
0
$ cat /sys/fs/cgroup/cpuset/kubepods.slice/kubepods-pod9505d42d_30c8_4af7_b4b5_b695e72fa2c4.slice/cri-containerd-0c50fc14e8fb5a89fca14fb2b38b5ebcd5fe1e54e14b4a4ac0be82587bd7f47a.scope/cpuset.cpus
32-47,160-175
$ cat /sys/fs/cgroup/cpuset/kubepods.slice/kubepods-pod9505d42d_30c8_4af7_b4b5_b695e72fa2c4.slice/cri-containerd-0c50fc14e8fb5a89fca14fb2b38b5ebcd5fe1e54e14b4a4ac0be82587bd7f47a.scope/cpuset.mems
2
```

* 清除Pod的CPU/NUMA内存的亲和性配置，并立即触发重新调度

```
$ hgvmctl container bind --pod default/stress-test-6db5df8b6-rjjxt --clear --resched-now
Setting CPU to full range: 0-255
Setting NUMA mems to full range: 0-7
Binding resources for all containers in pod default/stress-test-6db5df8b6-rjjxt
Setting NUMA mems to 0-7 for container stress-container1
Successfully bound CPUs 0-255 and NUMA mems 0-7 for container stress-container1
Successfully triggered reschedule for container stress-container1 after binding
Setting NUMA mems to 0-7 for container stress-container2
Successfully bound CPUs 0-255 and NUMA mems 0-7 for container stress-container2
Successfully triggered reschedule for container stress-container2 after binding
```

* 再次查询Pod的CPU/NUMA内存的亲和性配置与CPU拓扑落位，可观察到当前Pod内容器中各进程/线程的亲和性恢复原状，CPU落位分散

```
$ hgvmctl container affinity --pod default/stress-test-6db5df8b6-rjjxt
Namespace  Pod                          Container          PID     TID     Allowed_CPUs  Allowed_Mems  Last_CPU  Socket  NUMA  CCX  Core  Command
default    stress-test-6db5df8b6-rjjxt  stress-container1  418708  418708  0-255         0-7           0         0       0     0    0     stress --cpu 2 --vm 1 --vm-...
default    stress-test-6db5df8b6-rjjxt  stress-container1  418721  418721  0-255         0-7           8         0       0     2    8     stress --cpu 2 --vm 1 --vm-...
default    stress-test-6db5df8b6-rjjxt  stress-container1  418722  418722  0-255         0-7           4         0       0     1    4     stress --cpu 2 --vm 1 --vm-...
default    stress-test-6db5df8b6-rjjxt  stress-container1  418723  418723  0-255         0-7           120       1       7     30   56    stress --cpu 2 --vm 1 --vm-...
Namespace  Pod                          Container          PID     TID     Allowed_CPUs  Allowed_Mems  Last_CPU  Socket  NUMA  CCX  Core  Command
default    stress-test-6db5df8b6-rjjxt  stress-container2  418744  418744  0-255         0-7           32        0       2     8    32    stress --cpu 2 --vm 1 --vm-...
default    stress-test-6db5df8b6-rjjxt  stress-container2  418759  418759  0-255         0-7           44        0       2     11   44    stress --cpu 2 --vm 1 --vm-...
default    stress-test-6db5df8b6-rjjxt  stress-container2  418760  418760  0-255         0-7           36        0       2     9    36    stress --cpu 2 --vm 1 --vm-...
default    stress-test-6db5df8b6-rjjxt  stress-container2  418761  418761  0-255         0-7           163       0       2     8    35    stress --cpu 2 --vm 1 --vm-...
```

### ebpf性能追踪命令示例

* 需要系统内核支持eBPF，若使用存在问题请检查系统环境。
* 追踪系统里虚拟机的vm exit事件10秒，显示其所有vCPU线程的vm exit原因和次数

```
$ hgvmctl ebpftrace vm-exit 10
Display kvm exit reasons and statistics for all threads after sleeping 10 secs.
NAME            PID     TID     VCPU    KVM_EXIT_REASON  COUNT
ubuntu22.04     360907  360936  0       MSR              1245
ubuntu22.04     360907  360936  0       HLT              387
ubuntu22.04     360907  360936  0       INTR             331
ubuntu22.04     360907  360936  0       VINTR            5
ubuntu22.04     360907  360937  1       MSR              1019
ubuntu22.04     360907  360937  1       HLT              328
ubuntu22.04     360907  360937  1       INTR             289
ubuntu22.04     360907  360937  1       VINTR            5
kylin-v11-2503  365790  365822  0       MSR              2105
kylin-v11-2503  365790  365822  0       HLT              511
kylin-v11-2503  365790  365822  0       VINTR            197
kylin-v11-2503  365790  365822  0       INTR             95
kylin-v11-2503  365790  365822  0       IOIO             8
kylin-v11-2503  365790  365823  1       MSR              881
kylin-v11-2503  365790  365823  1       HLT              265
kylin-v11-2503  365790  365823  1       IOIO             185
kylin-v11-2503  365790  365823  1       INTR             80
kylin-v11-2503  365790  365823  1       VINTR            67
```

### ftrace性能追踪工具命令示例

* 主流Linux发行版都默认启用了Ftrace，若使用存在问题请检查环境配置。
* Ftrace性能追踪的各个命令可通过-h获取帮助信息。
* 以funccount为例，追踪以'vfs'开头的内核函数调用次数，Ctrl+C停止。

```
$ hgvmctl funccount -h
USAGE: hgvmctl funccount [-hT] [-i secs] [-d secs] [-t top] funcstring
                         -d seconds      # total duration of trace
                         -h              # this usage message
                         -i seconds      # interval summary
                         -t top          # show top num entries only
                         -T              # include timestamp (for -i)
  eg,
       hgvmctl funccount 'vfs*'          # trace all funcs that match "vfs*"
       hgvmctl funccount -d 5 'tcp*'     # trace "tcp*" funcs for 5 seconds
       hgvmctl funccount -t 10 'ext3*'   # show top 10 "ext3*" funcs
       hgvmctl funccount -i 1 'ext3*'    # summary every 1 second
       hgvmctl funccount -i 1 -d 5 'ext3*' # 5 x 1 second summaries
$
$ hgvmctl funccount 'vfs*'
Tracing "vfs*"... Ctrl-C to end.
^C
FUNC                              COUNT
vfs_readlink                        106
vfs_fadvise                         227
vfs_fstat                           298
vfs_write                           431
vfs_statx                           453
vfs_open                            712
vfs_getattr                         731
vfs_getattr_nosec                   731
vfs_read                           4026

Ending tracing...
```

## k8s环境容器化服务

### 服务介绍

针对Hygon CPU微架构与K8S云原生微服务资源应用特点，hgvmctl工具提供了命令 hgvmctl container orche，用户可以根据需要采用不同的优化策略参数，为节点上多个不同资源请求量的Pods自动合理的分配绑定CPU与内存NUMA资源，从而提升系统整体性能。
但是，这是需要用户手动执行命令的半自动化方式，需要在K8S中为各个节点分别执行以集群化生效，当节点中Pod发生增删变更后，为了达到最优资源分配效果，可能需要再次手动触发执行命令。

为了将资源分配实现全自动化，本章节提供了容器服务的方式，以daemonset方式部署于K8S集群中，每个节点启动定时任务服务，可以通过在线配置configmap数据的方式更新优化策略、定时任务cron参数，并可控制服务运行状态。服务基于上述hgvmctl命令的算法实现，定时执行，达到同样的优化效果。建议用户可以根据实际运维情况，配置服务在业务负载不繁忙的时段（如夜间）自动触发执行，从而使得集群负载长期处于较优的资源分配布局中。

### 安装部署

* 从光合社区下载安装包 [tools | 光合开发者社区](https://download.sourcefind.cn:65024/8/main/c86-devkit/latest/tools)

```
wget https://download.sourcefind.cn:65024/directlink/8/c86-devkit/latest/tools/hgvmctl-container-installer.tar.gz
```

* 解压缩包到安装目录

```
mkdir -p /opt/hygon/hgvmctl && tar -zxvf hgvmctl-container-installer.tar.gz -C /opt/hygon/hgvmctl
```

* 进入安装目录

```
cd /opt/hygon/hgvmctl/hgvmctl-container-installer
```

* 导入镜像到K8S集群各个节点中

```
ctr -n=k8s.io images import hgvmctl-server-image.tar
```

* （可选）根据需求修改deploy.yaml中的configmap配置数据
* 安装部署服务

```
kubectl apply -f deploy.yaml
```

### 在线更新服务配置及状态监控

* 在线更新configmap配置数据，实时生效

```
kubectl edit configmap -n hgvmctl-system hgvmctl-config
```

* 查看各节点服务的状态

```
kubectl get daemonset -n hgvmctl-system
kubectl get pod -n hgvmctl-system -o wide
```

* 查看服务日志

```
kubectl logs -n hgvmctl-system <pod_name>
```

### configmap配置数据说明

在服务部署之前或者运行中都可以对configmap的数据配置做更新，各参数的功能说明如下。

```
data:
  ### 服务控制参数
  #（必填）服务运行状态控制，取值范围：
  # "runOnceThenStart" - 立即执行一次资源亲和性分配，然后启动服务
  # "start" - 启动服务
  # "clearThenStop" - 立即执行清除资源亲和性分配，然后停止服务
  # "stop" - 停止服务
  serviceControl: "start"

  ### 服务执行的策略
  #（必填）定时任务配置。示例："0 2 * * *" 为每天凌晨2点执行一次
  cron: "0 2 * * *"

  ### Pods自动资源亲和性分配的策略
  #（必填）只分配CPU物理核心或逻辑核心。取值范围："physical" 或 "logical"
  coreType: "physical"
  #（必填）是否只选取Guaranteed Qos类型的Pods。取值范围："true" 或 "false"
  requireGuaranteedPod: "false"

  ### Pods的namespace选取范围，仅对requireGuaranteedPod=false时有效，当不指定namespace时则选取所有符合条件的Pods
  #（选填）选取的namespace范围。示例："default,aaa,bbb"
  targetNamespace: ""
  #（选填）被排除的namespace范围。示例："kube-system,default,aaa"
  excludeNamespace: "kube-system"
```
