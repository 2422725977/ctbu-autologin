#!/bin/bash
# CTBU 校园网自动登录 —— 诊断工具（macOS 双击运行）
# 连上校园网后运行它，会生成 diagnostic-report.txt，把那个文件发给开发者即可定位问题。
cd "$(dirname "$0")" || exit 1

PY=""
for cand in python3 /usr/bin/python3 /usr/local/bin/python3 /opt/homebrew/bin/python3; do
    if command -v "$cand" >/dev/null 2>&1; then PY="$cand"; break; fi
done

if [ -z "$PY" ]; then
    echo "[错误] 没找到 python3。macOS 可以执行： xcode-select --install"
    read -r _
    exit 3
fi

echo "================================================================"
echo "  CTBU 校园网诊断工具"
echo "================================================================"
echo "  前提：已经连上 CTBU-Student，但【先不要在浏览器里登录】"
echo "  因为出口列表只在未认证状态下才会出现。"
echo
echo "  整个过程约 1 分钟，中途【不要关闭这个窗口】。"
echo "  如果被打断也没关系，报告是逐行写入的，已抓到的不会丢。"
echo "================================================================"
echo

"$PY" campus_login.py --probe "$@"
RC=$?

echo
echo "================================================================"
if [ -f diagnostic-report.txt ]; then
    echo "  完成！诊断报告： $(pwd)/diagnostic-report.txt"
    echo "  报告行数： $(wc -l < diagnostic-report.txt)"
    echo
    echo "  接下来：切回手机热点/流量，然后告诉 AI 一声，它会自己读这个文件。"
else
    echo "  没生成报告（退出码 $RC）。请把上面的屏幕输出截图发给 AI。"
fi
echo "================================================================"
echo
echo "按回车关闭窗口..."
read -r _
