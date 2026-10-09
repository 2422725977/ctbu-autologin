#!/bin/bash
# 关闭 / 恢复 macOS 的"加入网络"认证弹窗（Captive Network Assistant，简称 CNA）
#
# 为什么需要它：
#   连上 CTBU-Student 后，macOS 会自动弹出一个"加入 CTBU-Student"的窗口去访问门户。
#   它和我们脚本用的是同一个客户端 IP，会互相干扰 —— 它可能把门户会话"占掉"，
#   导致脚本抓到的 queryString 失效，报「设备未注册」或拿不到 CAS 令牌。
#   关掉它之后，脚本就独占门户会话，稳定得多。
#
# 需要管理员密码（改的是系统级配置）。
cd "$(dirname "$0")" || exit 1

echo "================================================================"
echo "  macOS 认证弹窗（Captive Network Assistant）开关"
echo "================================================================"
echo "  当前状态："
CUR=$(defaults read /Library/Preferences/SystemConfiguration/com.apple.captive.control Active 2>/dev/null)
case "$CUR" in
    0) echo "    已关闭（弹窗不会再自动跳出来）";;
    1) echo "    已启用（连上 WiFi 后会自动弹出认证窗口）";;
    *) echo "    未设置（系统默认：启用）";;
esac
echo
echo "  说明：这个弹窗是 macOS 自动弹的，它和本脚本抢同一个门户会话，"
echo "        可能导致脚本报「设备未注册」。建议关掉。"
echo "        关掉后不影响你手动用浏览器登录（浏览器照常能打开门户）。"
echo
echo "  请选择："
echo "    1) 关闭弹窗（推荐）"
echo "    2) 恢复弹窗"
echo "    3) 什么都不做，退出"
echo
read -r -p "  输入 1 / 2 / 3 然后回车: " CHOICE

case "$CHOICE" in
    1)
        echo
        echo "  正在关闭（可能需要输入管理员密码）..."
        sudo defaults write /Library/Preferences/SystemConfiguration/com.apple.captive.control Active -boolean false
        if [ $? -eq 0 ]; then
            echo "  ✔ 已关闭。以后连上 CTBU-Student 不会再自动弹认证窗口。"
        else
            echo "  ✘ 失败（没输入密码或权限不足）。"
        fi
        ;;
    2)
        echo
        echo "  正在恢复（可能需要输入管理员密码）..."
        sudo defaults delete /Library/Preferences/SystemConfiguration/com.apple.captive.control Active 2>/dev/null
        echo "  ✔ 已恢复为系统默认（启用）。"
        ;;
    *)
        echo "  已取消。"
        ;;
esac

echo
echo "按回车关闭窗口..."
read -r _
