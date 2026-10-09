#!/bin/bash
# CTBU 校园网自动登录 —— macOS 双击启动器
cd "$(dirname "$0")" || exit 1

PY=""
for cand in python3 /usr/bin/python3 /usr/local/bin/python3 /opt/homebrew/bin/python3; do
    if command -v "$cand" >/dev/null 2>&1; then PY="$cand"; break; fi
done

if [ -z "$PY" ]; then
    echo "[错误] 没找到 python3。macOS 可以执行： xcode-select --install"
    echo
    echo "按回车关闭窗口..."
    read -r _
    exit 3
fi

"$PY" campus_login.py "$@"
RC=$?

echo
echo "退出码：$RC"
case "$RC" in
    0) echo "结果：网络已可用（本来就通，或刚刚登录成功）" ;;
    2) echo "结果：当前不在校园网，程序没有做任何动作" ;;
    3) echo "结果：config.json 里还没填学号或密码" ;;
    4) echo "结果：学号或密码被服务器拒绝，已停止（避免锁号）" ;;
    5) echo "结果：验证码连续识别失败" ;;
    6) echo "结果：找不到校园门户地址" ;;
    *) echo "结果：运行出错，详情见 login.log" ;;
esac

echo
echo "按回车关闭窗口..."
read -r _
