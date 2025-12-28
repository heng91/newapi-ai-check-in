#!/usr/bin/env python3
"""
runawaytime 自动签到脚本
"""

import asyncio
import hashlib
import json
import os
import sys
from datetime import datetime
from pathlib import Path

from dotenv import load_dotenv
from checkin import CheckIn

# Add parent directory to Python path to find utils module
sys.path.insert(0, str(Path(__file__).parent.parent))

from utils.notify import notify

load_dotenv(override=True)

BALANCE_HASH_FILE = "balance_hash_runawaytime.txt"


def load_accounts() -> list[dict] | None:
    """从环境变量加载账号配置

    支持格式:
    1. JSON 数组: [{"fuli_cookies": {...}, "cookies": {...}, "api_user": "123"}, ...]
    2. 单账号 JSON: {"fuli_cookies": {...}, "cookies": {...}, "api_user": "123"}

    其中:
    - fuli_cookies: fuli.hxi.me 站点的 cookies (用于签到)
    - cookies: runanytime.hxi.me 站点的 cookies (用于充值)
    - api_user: API 用户 ID
    """
    accounts_str = os.getenv("ACCOUNTS_RUNAWAYTIME")
    if not accounts_str:
        print("❌ ACCOUNTS_RUNAWAYTIME environment variable not found")
        return None

    try:
        data = json.loads(accounts_str)

        # 如果是单个对象，转换为数组
        if isinstance(data, dict):
            accounts = [data]
        elif isinstance(data, list):
            accounts = data
        else:
            print("❌ ACCOUNTS_RUNAWAYTIME must be a JSON object or array")
            return None

        # 验证每个账号配置
        valid_accounts = []
        for i, account in enumerate(accounts):
            if not isinstance(account, dict):
                print(f"❌ Account {i + 1} is not a valid object")
                continue

            fuli_cookies = account.get("fuli_cookies")
            cookies = account.get("cookies")
            api_user = account.get("api_user")

            if not fuli_cookies:
                print(f"❌ Account {i + 1} missing fuli_cookies")
                continue
            if not cookies:
                print(f"❌ Account {i + 1} missing cookies")
                continue
            if not api_user:
                print(f"❌ Account {i + 1} missing api_user")
                continue

            valid_accounts.append(account)

        if not valid_accounts:
            print("❌ No valid accounts found")
            return None

        print(f"✅ Loaded {len(valid_accounts)} account(s)")
        return valid_accounts
    except json.JSONDecodeError as e:
        print(f"❌ Failed to parse ACCOUNTS_RUNAWAYTIME as JSON: {e}")
        return None


def load_balance_hash() -> str | None:
    """加载余额 hash"""
    try:
        if os.path.exists(BALANCE_HASH_FILE):
            with open(BALANCE_HASH_FILE, "r", encoding="utf-8") as f:
                return f.read().strip()
    except Exception:
        pass
    return None


def save_balance_hash(balance_hash: str) -> None:
    """保存余额 hash"""
    try:
        with open(BALANCE_HASH_FILE, "w", encoding="utf-8") as f:
            f.write(balance_hash)
    except Exception as e:
        print(f"Warning: Failed to save balance hash: {e}")


def generate_balance_hash(checkin_results: dict) -> str:
    """生成所有账号余额的总 hash，基于 quota 和 used_quota"""
    if not checkin_results:
        return ""

    all_results = {}
    for account_key, checkin_info in checkin_results.items():
        if checkin_info:
            # 使用 quota 和 used_quota 生成 hash
            quota = checkin_info.get("quota", 0)
            used_quota = checkin_info.get("used_quota", 0)
            all_results[account_key] = f"{quota}:{used_quota}"

    results_json = json.dumps(all_results, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(results_json.encode("utf-8")).hexdigest()[:16]


async def main():
    """运行签到流程"""
    print("🚀 Runawaytime auto check-in script started")
    print(f'🕒 Execution time: {datetime.now().strftime("%Y-%m-%d %H:%M:%S")}')

    # 加载账号配置
    accounts = load_accounts()
    if not accounts:
        print("❌ Unable to load accounts, program exits")
        return 1

    print(f"⚙️ Found {len(accounts)} account(s) to process")

    # 加载余额 hash
    last_balance_hash = load_balance_hash()
    if last_balance_hash:
        print(f"ℹ️ Last balance hash: {last_balance_hash}")
    else:
        print("ℹ️ No previous balance hash found (first run)")

    # 加载全局代理配置
    global_proxy = None
    proxy_str = os.getenv("PROXY")
    if proxy_str:
        try:
            global_proxy = json.loads(proxy_str)
            print("⚙️ Global proxy loaded (dict format)")
        except json.JSONDecodeError:
            global_proxy = {"server": proxy_str}
            print(f"⚙️ Global proxy loaded: {proxy_str}")

    # 执行签到
    success_count = 0
    total_count = len(accounts)
    notification_content = []
    current_checkin_info = {}

    for i, account in enumerate(accounts):
        account_name = account.get("name", f"account_{i + 1}")
        fuli_cookies = account["fuli_cookies"]
        cookies = account["cookies"]
        api_user = account["api_user"]

        if len(notification_content) > 0:
            notification_content.append("\n-------------------------------")

        try:
            print(f"🌀 Processing {account_name}")

            # 创建 CheckIn 实例
            checkin = CheckIn(account_name, global_proxy=global_proxy)

            # 执行签到
            success, results = await checkin.execute(fuli_cookies, cookies, api_user)

            # 收集签到信息用于 hash 计算
            current_checkin_info[account_name] = results

            if success:
                success_count += 1
                print(f"✅ {account_name}: All check-in tasks completed")
                # 构建状态行
                wheel_count = results.get('wheel_count', 0)
                wheel_topup_success = results.get('wheel_topup_success_count', 0)
                status_line = (
                    f"✅ {account_name}: "
                    f"📝 Checkin: {'✓' if results.get('checkin') else '✗'} | "
                    f"💰 Topup: {'✓' if results.get('topup') else '✗'} | "
                    f"🎡 Wheel: {'✓' if results.get('wheel') else '✗'} ({wheel_count}) | "
                    f"🎁 Wheel Topup: {wheel_topup_success}/{wheel_count}"
                )
                # 添加 display 信息（如果有）
                display = results.get('display', '')
                if display:
                    notification_content.append(f"{status_line}\n{display}")
                else:
                    notification_content.append(status_line)
            else:
                # 部分成功或失败
                wheel_count = results.get('wheel_count', 0)
                wheel_topup_success = results.get('wheel_topup_success_count', 0)
                if results.get('checkin') or results.get('topup') or results.get('wheel'):
                    print(f"⚠️ {account_name}: Partial success")
                    status_line = (
                        f"⚠️ {account_name}: "
                        f"📝 Checkin: {'✓' if results.get('checkin') else '✗'} | "
                        f"💰 Topup: {'✓' if results.get('topup') else '✗'} | "
                        f"🎡 Wheel: {'✓' if results.get('wheel') else '✗'} | "
                        f"🎁 Wheel Topup: {wheel_topup_success}/{wheel_count}"
                    )
                    display = results.get('display', '')
                    if display:
                        notification_content.append(f"{status_line}\n{display}")
                    else:
                        notification_content.append(status_line)
                else:
                    print(f"❌ {account_name}: Check-in failed")
                    # errors 已经包含在 display 中
                    display = results.get('display', '')
                    if display:
                        notification_content.append(f"❌ {account_name}:\n{display}")
                    else:
                        notification_content.append(f"❌ {account_name}: Unknown error")

        except Exception as e:
            print(f"❌ {account_name} processing exception: {e}")
            notification_content.append(f"❌ {account_name} Exception: {str(e)[:100]}...")

    # 生成当前余额 hash
    current_balance_hash = generate_balance_hash(current_checkin_info)
    print(f"\nℹ️ Current balance hash: {current_balance_hash}, Last: {last_balance_hash}")

    # 判断是否需要发送通知
    need_notify = False
    if not last_balance_hash:
        need_notify = True
        print("🔔 First run detected, will send notification")
    elif current_balance_hash != last_balance_hash:
        need_notify = True
        print("🔔 Balance changes detected, will send notification")
    else:
        print("ℹ️ No balance changes detected, skipping notification")

    # 构建通知内容
    if need_notify and notification_content:
        summary = [
            "-------------------------------",
            "📢 Check-in result statistics:",
            f"🔵 Success: {success_count}/{total_count}",
            f"🔴 Failed: {total_count - success_count}/{total_count}",
        ]

        if success_count == total_count:
            summary.append("✅ All accounts check-in successful!")
        elif success_count > 0:
            summary.append("⚠️ Some accounts check-in successful")
        else:
            summary.append("❌ All accounts check-in failed")

        time_info = f'🕓 Execution time: {datetime.now().strftime("%Y-%m-%d %H:%M:%S")}'

        notify_content = "\n\n".join(
            [
                time_info,
                "📊 Check-in Summary:\n" + "\n".join(notification_content),
                "\n".join(summary)
            ]
        )

        print(notify_content)

        # 发送通知
        if success_count == total_count:
            notify.push_message("Runawaytime Check-in Success", notify_content, msg_type="text")
            print("🔔 Success notification sent")
        else:
            notify.push_message("Runawaytime Check-in Alert", notify_content, msg_type="text")
            print("🔔 Alert notification sent")

    # 保存当前余额 hash
    if current_balance_hash:
        save_balance_hash(current_balance_hash)

    # 设置退出码
    sys.exit(0 if success_count > 0 else 1)


def run_main():
    """运行主函数的包装函数"""
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        print("\n⚠️ Program interrupted by user")
        sys.exit(1)
    except Exception as e:
        print(f"\n❌ Error occurred during program execution: {e}")
        sys.exit(1)


if __name__ == "__main__":
    run_main()