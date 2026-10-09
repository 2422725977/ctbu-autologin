#!/bin/bash
# 一键安装自动验证码识别（ddddocr）—— macOS
#
# 作用：在项目里建一个独立的 .venv 并装上 ddddocr，
#       之后 campus_login.py 会自动切到这个 venv 运行（见 maybe_reexec_in_venv）。
#
# 为什么要在项目里建 venv 而不是装到系统 Python：
#   macOS 系统 Python 是"外部管理"的，pip 直接装会被拒绝；
#   建 venv 既干净又不污染系统，删掉 .venv 就等于完全卸载。
cd "$(dirname "$0")" || exit 1

echo "================================================================"
echo "  安装自动验证码识别（ddddocr）"
echo "================================================================"
echo "  说明：约 50MB 下载，只在【有外网】时能装（校园网未认证时不行）。"
echo "  装完后 CAS 那个带干扰线的验证码就能自动识别，不用手动输入。"
echo "================================================================ "
echo

PY=""
for cand in python3 /usr/bin/python3 /usr/local/bin/python3 /opt/homebrew/bin/python3; do
    if command -v "$cand" >/dev/null 2>&1; then PY="$cand"; break; fi
done
if [ -z "$PY" ]; then
    echo "[错误] 没找到 python3。可以执行： xcode-select --install"
    read -r _; exit 3
fi

if [ -x ".venv/bin/python3" ]; then
    echo "[1/3] 复用已有的 .venv"
else
    echo "[1/3] 创建 .venv ..."
    "$PY" -m venv .venv || { echo "[错误] 创建 venv 失败"; read -r _; exit 1; }
fi

echo "[2/3] 升级 pip ..."
.venv/bin/python3 -m pip install --upgrade pip -q 2>&1 | tail -2

echo "[3/3] 安装 ddddocr（可能要几分钟）..."
.venv/bin/python3 -m pip install ddddocr 2>&1 | tail -6

echo
if .venv/bin/python3 -c "import ddddocr" >/dev/null 2>&1; then
    echo "================================================================"
    echo "  ✔ 安装成功！以后验证码会自动识别，不用手动输入了。"
    echo "================================================================"
else
    echo "================================================================"
    echo "  ✘ 安装未成功。请检查网络（要能访问 pypi.org），然后重跑本脚本。"
    echo "    没装也不影响使用：程序会自动改成让你手动输入验证码。"
    echo "================================================================"
fi
echo
echo "按回车关闭窗口..."
read -r _
