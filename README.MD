# Keystone Group / Extent-I/O

项目仓库：<https://github.com/qiran27/keystone-group.git>

本项目在 RISC-V Keystone 上实现多安全飞地协作及 Host 管理的异步 I/O，主要面向 StarFive VisionFive2。Master 与 Worker 通过受保护的 TSR 交接任务和结果，Control/Data UTM 用于与非可信 Host 交换控制信息及密文。Sync、Async、Adaptive 使用相同多飞地基础，分别提供同步等待、异步流水线、异步聚类与合并。默认性能拓扑为一个 Host/Master 核加三个 Worker 核；更多 Worker 在三个计算核上分时执行。

## 目录

| 目录 | 用途 |
| --- | --- |
| `sm/` | Security Monitor：组管理、PMP 权限、TSR 授权及调度 |
| `linux-keystone-driver/` | Linux 驱动：飞地创建、映射和事件接口 |
| `sdk/` | 与 SM、驱动及 Runtime 配套的 Host/eapp SDK |
| `runtime/` | enclave 内的 Eyrie Runtime 与 loader |
| `group-pmp-test/` | 测试程序、第三方测试源码及板端脚本 |

这不是完整 Linux 镜像工程。需要已有的 VisionFive2 Linux/OpenSBI 构建环境及 RISC-V Linux 交叉工具链。SM、驱动、SDK、Runtime 必须使用本仓库相互匹配的版本，不能仅替换测试程序。

## 1. 下载与系统集成

```bash
git clone https://github.com/qiran27/keystone-group.git
cd keystone-group
export GROUP_SRC="$PWD"
```

### Linux 驱动

驱动支持外部模块构建，无须移动目录。如果系统工程习惯把扩展驱动放入 Linux 源码内，也可以复制到 `linux/drivers/keystone/`（目录名称是 `drivers`，不是 `driver`）：

```bash
export LINUX_SRC=/path/to/linux
mkdir -p "$LINUX_SRC/drivers/keystone"
cp -a "$GROUP_SRC/linux-keystone-driver/." "$LINUX_SRC/drivers/keystone/"
```

之后仍可用 `make -C "$KERNEL_BUILD" M="$LINUX_SRC/drivers/keystone" ... modules` 作为外部模块编译。仅复制进去不会自动加入内核构建；若希望随内核自动构建，还需在系统工程中配置 Kbuild/Kconfig。本项目推荐使用下文脚本的 `KEYSTONE_KERNEL_BUILD` 直接构建仓库中的驱动，避免维护重复源码。

`KERNEL_BUILD` 必须是开发板所用内核**完整编译后的输出目录**，包含 `.config`、生成头文件和 `Module.symvers`，不是任意同版本源码。模块编译器应与内核构建工具链匹配。

### OpenSBI 与 SM

SM 不是 Linux 驱动，必须编入 M-mode 固件。可以把它复制到固件工程的 `opensbi/keystone-sm/`，或由现有 Keystone 构建配方引用仓库中的 `sm/`：

```bash
export OPENSBI_SRC=/path/to/opensbi
mkdir -p "$OPENSBI_SRC/keystone-sm"
cp -a "$GROUP_SRC/sm/." "$OPENSBI_SRC/keystone-sm/"
```

**复制并不会使普通 OpenSBI 自动启用 SM。** 必须沿用已适配 Keystone 的 OpenSBI/板级固件构建配方，令 `KEYSTONE_SM` 指向该目录，选择本项目 `plat/generic` 的平台扩展，并传入 `KEYSTONE_SDK_DIR="$GROUP_SRC/sdk"` 和 `KEYSTONE_PLATFORM=starfive/visionfive2`；本项目平台扩展会引用 SM 源码及共享 ABI 头。上游 OpenSBI 版本及板级 FIT 打包方式不同，不能把这些参数当作适用于所有原版 OpenSBI 的通用构建命令。

在已有 Keystone 系统工程中，通常将本仓库的 `sm/`、`sdk/`、`runtime/`、`linux-keystone-driver/` 同步到工程对应源码目录，再通过该工程的固件配方重新构建、打包、部署并重启。只复制 `deploy/` 或只加载驱动不会更新正在运行的 SM。

## 2. 从源码编译测试与部署文件

在 Linux 构建机执行，需 Bash、CMake >= 3.13、Make、C/C++ 编译器、Git、Python 3、binutils，以及与板端 libc 匹配的 `riscv64-buildroot-linux-gnu-gcc/g++`。默认还编译 native crypto 诊断，需要目标架构的 OpenSSL 开发库；不需要此诊断时可设置 `GROUP_PMP_ENABLE_NATIVE_AES_DIAGNOSTIC=OFF`，其他测试仍会构建。

例如使用已有 Buildroot 工具链：

```bash
export BUILDROOT_DIR=/path/to/buildroot.build
export PATH="$BUILDROOT_DIR/host/bin:$PATH"
cd "$GROUP_SRC/group-pmp-test"

# 可选：同时生成与板端内核匹配的 keystone-driver.ko。
export KEYSTONE_KERNEL_BUILD=/path/to/fully-built-board-kernel

# 内核使用另一套工具链时，显式指定模块交叉编译前缀。
# export SECURITY_EVIDENCE_CROSS_COMPILE=/path/to/kernel-toolchain/riscv64-buildroot-linux-gnu-

bash ./rebuild-and-test.sh --check-paths
bash ./rebuild-and-test.sh
```

脚本默认直接引用仓库内的源码：

1. 编译 `sdk/` 并安装到 `group-pmp-test/build/sdk-install/`。
2. 通过 CMake 直接引用 `group-pmp-test/`，编译 Host 程序和 `.eapp_riscv` 等 RISC-V 可执行文件。
3. 从所选 `runtime/` 编译 `eyrie-rt` 和 `loader.bin`。
4. 构建 SD/USB 测试工具，校验 ABI/功能标记，并把程序、测试脚本、配置、输入数据和所需诊断库打包到 `group-pmp-test/deploy/`。
5. 设置 `KEYSTONE_KERNEL_BUILD` 时同时编译并打包驱动；未设置时会提示缺少模块构建，需自行部署匹配的驱动。

SDK 与 Runtime 放在其他目录时，可通过以下参数指定源码、SDK 安装和构建路径：

```bash
KEYSTONE_SDK_SRC_DIR=/path/to/sdk \
KEYSTONE_EYRIE_RUNTIME=/path/to/runtime \
KEYSTONE_SDK_DIR=/path/to/sdk-install \
GROUP_PMP_BUILD_DIR=/path/to/group-build \
bash ./rebuild-and-test.sh
```

以上路径均可包含空格；SDK 安装目录不能等于 SDK 源码目录。源码 SM/驱动的核查路径还可通过 `KEYSTONE_SM_DIR`、`KEYSTONE_DRIVER_DIR` 覆盖。`PROJECT_ROOT` 默认取仓库根目录。

安全扫描还需要独立内核取证模块，仅在需要安全实验时设置：

```bash
SECURITY_EVIDENCE_KERNEL_BUILD="$KEYSTONE_KERNEL_BUILD" \
bash ./rebuild-and-test.sh
```

该模块要求对应内核启用其所需 tracepoint 等功能；不能通过忽略未解析符号来替代正确构建。脚本不自动重编或刷写 Linux/SM 固件，也不在构建机运行板端性能测试。

## 3. 板端部署与测试

将整个 `group-pmp-test/deploy/` 拷贝到开发板，例如 `/deploy/`。部署本项目匹配的固件与驱动，启动后执行：

```sh
cd /deploy
insmod ./keystone-driver.ko   # 尚未加载时执行；已加载则不要重复加载
./group-pmp-test-runner --artifact-info
sh ./run-group-pmp-test.sh
```

性能脚本要求预先配置 CPU 隔离启动参数，追加到现有 root/console 等参数，不能覆盖它们：

```text
isolcpus=domain,managed_irq,1-3 nohz_full=1-3 rcu_nocbs=1-3 irqaffinity=0
```

修改后重启并用 `cat /proc/cmdline` 确认。完整性能测试示例（1–9 Worker、三轮、六档数据量）：

```sh
sh ./run-p10-mixed-scaling.sh --cipher aes-gcm-128 sqlite-bench all 9 3 sweep cold
sh ./run-fio-enclave-scaling.sh --cipher aes-gcm-128 all all 9 3 sweep cold
sh ./run-rv8-enclave-scaling.sh all both 9 3 sweep
```

`sweep` 对应 60、100、200、300、400、500 MB；RV8 是 Sync/Async 纯计算对照，不包含 Adaptive。其余测试入口及结果位置见 `group-pmp-test/README.md` 和各测试子目录。测试脚本会建立临时数据及结果目录，运行前确认容量与挂载状态；缓存模式名不代表某条路径一定对应 SD 或 USB，应以实际挂载和配置为准。

