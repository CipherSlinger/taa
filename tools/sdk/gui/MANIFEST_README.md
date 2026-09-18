# 嵌入应用程序清单 - 启用现代视觉样式

本文档说明如何将应用程序清单嵌入可执行文件，使原生控件使用 Windows 10/11 的现代外观。

## 为什么需要清单？

默认情况下，Win32 应用程序使用"经典"Windows 外观。通过添加清单声明使用 Common Controls 6.0，可以让按钮、文本框等控件使用现代视觉样式。

## 方法 1：在 Linux 上构建（推荐）

### 安装 rsrc 工具

```bash
go install github.com/akavel/rsrc@latest
```

### 构建

```bash
cd cmd/teecrypto-gui
./build.sh
```

脚本会自动：
1. 使用 rsrc 将清单编译为 resource_windows.syso
2. 构建可执行文件（自动嵌入 syso）
3. 清理临时文件

## 方法 2：在 Windows 上构建

### 使用批处理脚本

1. 确保已安装 Windows SDK
2. 双击运行 `embed_manifest.bat`
3. 清单将被嵌入到 teecrypto-gui.exe 中

### 手动使用 mt.exe

```cmd
mt.exe -manifest teecrypto-gui.exe.manifest -outputresource:teecrypto-gui.exe;#1
```

## 方法 3：使用 go-winres（跨平台）

### 安装

```bash
go install github.com/tc-hib/go-winres@latest
```

### 初始化配置

```bash
cd cmd/teecrypto-gui
go-winres init
```

这会创建 `winres.json` 配置文件。

### 构建

```bash
go-winres make
CGO_ENABLED=0 GOOS=windows GOARCH=amd64 go build -o teecrypto-gui.exe .
```

## 方法 4：外部清单文件（最简单）

如果不想嵌入，可以直接使用外部清单：

1. 编译程序：
   ```bash
   CGO_ENABLED=0 GOOS=windows GOARCH=amd64 go build -o teecrypto-gui.exe .
   ```

2. 将 `teecrypto-gui.exe.manifest` 复制到与 `teecrypto-gui.exe` 相同的目录

3. 运行程序 - Windows 会自动加载清单

**注意**：清单文件名必须与可执行文件名完全一致（包括 .exe.manifest 后缀）。

## 验证清单是否生效

运行程序后，如果按钮显示为现代扁平化风格（而非经典 3D 凸起样式），说明清单已生效。

## 清单内容说明

当前清单包含：

- **Common Controls 6.0** - 启用现代视觉样式
- **Windows 版本兼容性** - 声明支持 Win7/8/8.1/10/11
- **DPI 感知** - 启用 PerMonitorV2 高 DPI 支持

## 故障排除

### 按钮仍然是经典样式

- 检查清单文件是否与 exe 同名
- 检查清单文件是否与 exe 在同一目录
- 如果是嵌入方式，重新编译程序

### mt.exe 找不到

- 安装 Windows SDK
- 或将 mt.exe 所在目录添加到 PATH

### rsrc 安装失败

- 检查网络连接
- 或使用 go-winres 替代
- 或使用外部清单文件方式
