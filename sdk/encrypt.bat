@echo off
chcp 65001 >nul
setlocal enabledelayedexpansion

echo ========================================
echo   格物平台加密工具 - 命令行版本
echo ========================================
echo.

REM 检查 CLI 工具是否存在
if not exist "teecrypto-cli.exe" (
    echo 错误: 未找到 teecrypto-cli.exe
    echo 请确保 teecrypto-cli.exe 在当前目录下
    pause
    exit /b 1
)

REM 查找 .pem 公钥文件
set pem_count=0
set pem_files=

for %%f in (*.pem) do (
    set /a pem_count+=1
    set "pem_files=!pem_files! %%f"
)

if %pem_count% equ 0 (
    echo 错误: 当前目录下未找到 .pem 公钥文件
    echo 请将 .pem 公钥文件放在当前目录
    pause
    exit /b 1
)

REM 选择公钥文件
set public_key=
if %pem_count% equ 1 (
    for %%f in (*.pem) do set "public_key=%%f"
    echo 检测到公钥: %public_key%
) else (
    echo 检测到多个 .pem 文件，请选择:
    set idx=0
    for %%f in (*.pem) do (
        set /a idx+=1
        set "pem_!idx!=%%f"
        echo   !idx!. %%f
    )
    echo.
    set /p choice="请输入序号 (1-%pem_count%): "

    REM 验证选择
    if %choice% lss 1 (
        echo 错误: 无效的选择
        pause
        exit /b 1
    )
    if %choice% gtr %pem_count% (
        echo 错误: 无效的选择
        pause
        exit /b 1
    )

    for /l %%i in (1,1,%pem_count%) do (
        if %%i equ %choice% (
            for %%f in (!pem_%%i!) do set "public_key=%%f"
        )
    )
    echo 已选择公钥: %public_key%
)

echo.

REM 查找待加密文件（排除 .pem, .enc, .exe, .bat, .md 文件）
set file_count=0
set file_list=

for %%f in (*) do (
    set "filename=%%f"
    set "ext=%%~xf"

    REM 排除特定扩展名
    if /i not "!ext!"==".pem" (
        if /i not "!ext!"==".enc" (
            if /i not "!ext!"==".exe" (
                if /i not "!ext!"==".bat" (
                    if /i not "!ext!"==".md" (
                        if /i not "!filename!"=="encrypt.bat" (
                            set /a file_count+=1
                            set "file_list=!file_list! %%f"
                        )
                    )
                )
            )
        )
    )
)

if %file_count% equ 0 (
    echo 错误: 当前目录下未找到可加密的文件
    echo 支持的文件类型: 除 .pem, .enc, .exe, .bat, .md 外的所有文件
    pause
    exit /b 1
)

REM 选择输入文件
set input_file=
if %file_count% equ 1 (
    for %%f in (!file_list!) do set "input_file=%%f"
    echo 检测到文件: %input_file%
) else (
    echo 检测到多个文件，请选择要加密的文件:
    set idx=0
    for %%f in (!file_list!) do (
        set /a idx+=1
        set "file_!idx!=%%f"
        echo   !idx!. %%f
    )
    echo.
    set /p choice="请输入序号 (1-%file_count%): "

    REM 验证选择
    if %choice% lss 1 (
        echo 错误: 无效的选择
        pause
        exit /b 1
    )
    if %choice% gtr %file_count% (
        echo 错误: 无效的选择
        pause
        exit /b 1
    )

    for /l %%i in (1,1,%file_count%) do (
        if %%i equ %choice% (
            for %%f in (!file_%%i!) do set "input_file=%%f"
        )
    )
    echo 已选择文件: %input_file%
)

echo.
echo ========================================
echo   开始加密...
echo ========================================
echo.

REM 执行加密
teecrypto-cli.exe "%public_key%" "%input_file%"

if %errorlevel% equ 0 (
    echo.
    echo ========================================
    echo   加密完成！
    echo ========================================
) else (
    echo.
    echo ========================================
    echo   加密失败！
    echo ========================================
)

echo.
pause
