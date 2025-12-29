#!/usr/bin/env python3
"""
CheckIn 类 for runawaytime
"""

import asyncio
import sys
import httpx
from pathlib import Path

# Add parent directory to Python path to find utils module
sys.path.insert(0, str(Path(__file__).parent.parent))
from utils.http_utils import proxy_resolve, response_resolve
from topup import topup


def get_user_info(
    account_name: str,
    headers: dict,
    cookies: dict,
    proxy: httpx.URL | None = None,
) -> dict:
    """获取用户信息（余额）

    Args:
        account_name: 账号名称（用于日志）
        headers: 请求头
        cookies: cookies 字典
        proxy: 代理配置（可选）

    Returns:
        包含 success 和 quota/used_quota 或 error 的字典
    """
    client = httpx.Client(http2=True, timeout=30.0, proxy=proxy)
    try:
        # 设置 cookies
        client.cookies.update(cookies)

        # 构建请求头
        user_info_headers = headers.copy()
        user_info_headers.update({
            "Accept": "application/json, text/plain, */*",
            "Cache-Control": "no-store",
            "Pragma": "no-cache",
        })

        response = client.get(
            "https://runanytime.hxi.me/api/user/self",
            headers=user_info_headers,
            timeout=30,
        )

        if response.status_code == 200:
            json_data = response_resolve(response, "get_user_info", account_name)
            if json_data is None:
                return {
                    "success": False,
                    "error": "Failed to get user info: Invalid response type (saved to logs)",
                }

            if json_data.get("success"):
                user_data = json_data.get("data", {})
                quota = round(user_data.get("quota", 0) / 500000, 2)
                used_quota = round(user_data.get("used_quota", 0) / 500000, 2)
                print(
                    f"✅ {account_name}: User info - "
                    f"Current Balance: ${quota}, Used: ${used_quota}"
                )
                return {
                    "success": True,
                    "quota": quota,
                    "used_quota": used_quota,
                    "display": f"Current Balance: ${quota}, Used: ${used_quota}",
                }
            else:
                error_msg = json_data.get("message", "Unknown error")
                print(f"❌ {account_name}: Get user info failed - {error_msg}")
                return {
                    "success": False,
                    "error": f"Get user info failed: {error_msg}",
                }
        else:
            print(f"❌ {account_name}: Get user info failed - HTTP {response.status_code}")
            return {
                "success": False,
                "error": f"Get user info failed: HTTP {response.status_code}",
            }
    except Exception as e:
        print(f"❌ {account_name}: Get user info error - {e}")
        return {
            "success": False,
            "error": f"Get user info failed: {e}",
        }
    finally:
        client.close()


class CheckIn:
    """runawaytime 签到管理类"""

    def __init__(
        self,
        account_name: str,
        global_proxy: dict | None = None,
    ):
        """初始化签到管理器

        Args:
            account_name: 账号名称
            global_proxy: 全局代理配置(可选)
        """
        self.account_name = account_name
        self.safe_account_name = "".join(c if c.isalnum() else "_" for c in account_name)
        self.global_proxy = global_proxy
        self.http_proxy_config = proxy_resolve(global_proxy)

    def get_checkin_status(
        self, client: httpx.Client, headers: dict, fuli_cookies: dict
    ) -> tuple[bool, bool]:
        """获取签到状态，检查今天是否已签到

        Args:
            client: httpx 客户端
            headers: 请求头
            fuli_cookies: fuli.hxi.me 站点的 cookies

        Returns:
            (是否成功获取状态, 是否已签到)
        """
        print(f"ℹ️ {self.account_name}: Getting checkin status")

        # 设置 cookies
        client.cookies.update(fuli_cookies)

        status_headers = headers.copy()
        status_headers.update(
            {
                "referer": "https://fuli.hxi.me/",
                "sec-fetch-dest": "empty",
                "sec-fetch-mode": "cors",
                "sec-fetch-site": "same-origin",
            }
        )

        response = client.get(
            "https://fuli.hxi.me/api/checkin/status", headers=status_headers, timeout=30
        )

        print(f"📨 {self.account_name}: Checkin status response status code {response.status_code}")

        if response.status_code == 200:
            json_data = response_resolve(response, "get_checkin_status", self.account_name)
            if json_data is None:
                return False, False

            checked = json_data.get("checked", False)
            streak = json_data.get("streak", 0)
            today_count = json_data.get("todayCount", 0)
            user_rank = json_data.get("userRank", 0)

            print(
                f"✅ {self.account_name}: Status - Checked: {checked}, "
                f"Streak: {streak}, Today Count: {today_count}, Rank: {user_rank}"
            )
            return True, checked

        return False, False

    def execute_checkin(
        self, client: httpx.Client, headers: dict, fuli_cookies: dict
    ) -> tuple[bool, str]:
        """执行签到请求

        Args:
            client: httpx 客户端
            headers: 请求头
            fuli_cookies: fuli.hxi.me 站点的 cookies

        Returns:
            (是否成功, code)
        """
        print(f"📝 {self.account_name}: Executing checkin")

        # 设置 cookies
        client.cookies.update(fuli_cookies)

        # 构建请求头
        checkin_headers = headers.copy()
        checkin_headers.update(
            {
                "content-length": "0",
                "origin": "https://fuli.hxi.me",
                "referer": "https://fuli.hxi.me/",
                "sec-fetch-dest": "empty",
                "sec-fetch-mode": "cors",
                "sec-fetch-site": "same-origin",
            }
        )

        response = client.post(
            "https://fuli.hxi.me/api/checkin", headers=checkin_headers, timeout=30
        )

        print(f"📨 {self.account_name}: Checkin response status code {response.status_code}")

        if response.status_code in [200, 400]:
            json_data = response_resolve(response, "execute_checkin", self.account_name)
            if json_data is None:
                print(f"❌ {self.account_name}: Checkin failed - Invalid response format")
                return False, ""

            message = json_data.get("message", json_data.get("msg", ""))

            if json_data.get("success"):
                code = json_data.get("code", "")
                streak = json_data.get("streak", 0)
                expire_seconds = json_data.get("expireSeconds", 0)
                print(
                    f"✅ {self.account_name}: Checkin successful! "
                    f"Code: {code}, Streak: {streak}, Expires in: {expire_seconds}s"
                )
                return True, code

            if "already" in message.lower() or "已经" in message or "已签" in message:
                print(f"✅ {self.account_name}: Already checked in today!")
                return True, ""

            error_msg = message if message else "Unknown error"
            print(f"❌ {self.account_name}: Checkin failed - {error_msg}")
            return False, ""

        print(f"❌ {self.account_name}: Checkin failed - HTTP {response.status_code}")
        return False, ""

    def get_wheel_status(
        self, client: httpx.Client, headers: dict, fuli_cookies: dict
    ) -> tuple[bool, int]:
        """获取大转盘状态，检查剩余抽奖次数

        Args:
            client: httpx 客户端
            headers: 请求头
            fuli_cookies: fuli.hxi.me 站点的 cookies

        Returns:
            (是否成功获取状态, 剩余次数)
        """
        print(f"🎡 {self.account_name}: Getting wheel status")

        # 设置 cookies
        client.cookies.update(fuli_cookies)

        status_headers = headers.copy()
        status_headers.update(
            {
                "referer": "https://fuli.hxi.me/wheel",
                "sec-fetch-dest": "empty",
                "sec-fetch-mode": "cors",
                "sec-fetch-site": "same-origin",
            }
        )

        response = client.get(
            "https://fuli.hxi.me/api/wheel/status", headers=status_headers, timeout=30
        )

        print(f"📨 {self.account_name}: Wheel status response status code {response.status_code}")

        if response.status_code == 200:
            json_data = response_resolve(response, "get_wheel_status", self.account_name)
            if json_data is None:
                return False, 0

            limit = json_data.get("limit", 0)
            remaining = json_data.get("remaining", 0)

            print(
                f"✅ {self.account_name}: Wheel Status - Limit: {limit}, Remaining: {remaining}"
            )
            return True, remaining

        return False, 0

    def execute_wheel(
        self, client: httpx.Client, headers: dict, fuli_cookies: dict
    ) -> tuple[bool, str, int]:
        """执行大转盘抽奖

        Args:
            client: httpx 客户端
            headers: 请求头
            fuli_cookies: fuli.hxi.me 站点的 cookies

        Returns:
            (是否成功, code, remaining)
        """
        print(f"🎡 {self.account_name}: Executing wheel spin")

        # 设置 cookies
        client.cookies.update(fuli_cookies)

        # 构建请求头
        wheel_headers = headers.copy()
        wheel_headers.update(
            {
                "content-length": "0",
                "origin": "https://fuli.hxi.me",
                "referer": "https://fuli.hxi.me/wheel",
                "sec-fetch-dest": "empty",
                "sec-fetch-mode": "cors",
                "sec-fetch-site": "same-origin",
            }
        )

        response = client.post(
            "https://fuli.hxi.me/api/wheel", headers=wheel_headers, timeout=30
        )

        print(f"📨 {self.account_name}: Wheel response status code {response.status_code}")

        if response.status_code in [200, 400]:
            json_data = response_resolve(response, "execute_wheel", self.account_name)
            if json_data is None:
                print(f"❌ {self.account_name}: Wheel failed - Invalid response format")
                return False, "", 0

            message = json_data.get("message", json_data.get("msg", ""))

            if json_data.get("success"):
                code = json_data.get("code", "")
                remaining = json_data.get("remaining", 0)
                expire_seconds = json_data.get("expireSeconds", 0)
                print(
                    f"✅ {self.account_name}: Wheel successful! "
                    f"Code: {code}, Remaining: {remaining}, Expires in: {expire_seconds}s"
                )
                return True, code, remaining

            if "already" in message.lower() or "已经" in message or "次数" in message:
                print(f"✅ {self.account_name}: No wheel spins remaining!")
                return True, "", 0

            error_msg = message if message else "Unknown error"
            print(f"❌ {self.account_name}: Wheel failed - {error_msg}")
            return False, "", 0

        print(f"❌ {self.account_name}: Wheel failed - HTTP {response.status_code}")
        return False, "", 0

    async def execute(
        self, fuli_cookies: dict, cookies: dict, api_user: str | int
    ) -> tuple[bool, dict]:
        """执行完整签到流程：先 checkin 再 topup，然后执行大转盘

        Args:
            fuli_cookies: fuli.hxi.me 站点的 cookies (用于 checkin 和 wheel)
            cookies: runanytime.hxi.me 站点的 cookies (用于 topup)
            api_user: API 用户 ID (用于 topup)

        Returns:
            (签到是否成功, 结果信息)
        """
        print(f"\n\n⏳ Starting to process {self.account_name}")
        print(
            f"ℹ️ {self.account_name}: Executing check-in "
            f"(using proxy: {'true' if self.http_proxy_config else 'false'})"
        )

        client = httpx.Client(http2=False, timeout=30.0, proxy=self.http_proxy_config)
        try:
            # 构建基础请求头
            headers = {
                "accept": "*/*",
                "accept-language": "en,en-US;q=0.9,zh;q=0.8,en-CN;q=0.7,zh-CN;q=0.6,am;q=0.5",
                "cache-control": "no-cache",
                "pragma": "no-cache",
                "priority": "u=1, i",
                "sec-ch-ua": '"Google Chrome";v="143", "Chromium";v="143", "Not A(Brand";v="24"',
                "sec-ch-ua-mobile": "?0",
                "sec-ch-ua-platform": '"macOS"',
                "user-agent": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) "
                "AppleWebKit/537.36 (KHTML, like Gecko) Chrome/143.0.0.0 Safari/537.36",
            }

            # 设置 cookie
            client.cookies.set("i18next", "en")

            results = {
                "checkin": False,
                "topup": False,
                "wheel": False,
                "wheel_count": 0,
                "wheel_topup_success_count": 0,  # wheel topup 成功次数
                "quota": 0,
                "used_quota": 0,
                "display": "",  # 最终显示信息
            }
            errors = []  # 收集错误信息（局部变量，不返回）
            topup_count = 0  # 记录 topup 次数，用于判断是否需要等待

            # Step 1: 检查签到状态
            status_success, already_checked = self.get_checkin_status(client, headers, fuli_cookies)

            if not status_success:
                print(f"⚠️ {self.account_name}: Failed to get checkin status, will try to checkin anyway")

            if not already_checked:
                # Step 2: 执行签到，获取 code
                checkin_success, code = self.execute_checkin(client, headers, fuli_cookies)
                results["checkin"] = checkin_success
                if not checkin_success:
                    errors.append("Checkin failed")

                # Step 3: 执行 topup (使用 cookies、api_user 和 code)
                if checkin_success and code:
                    print(f"💰 {self.account_name}: Executing topup with code: {code}")
                    # 构建 topup 请求头
                    topup_headers = headers.copy()
                    topup_headers.update({
                        "Referer": "https://runanytime.hxi.me/console/topup",
                        "Origin": "https://runanytime.hxi.me",
                        "new-api-user": f"{api_user}",
                    })
                    topup_result = topup(
                        account_name=self.account_name,
                        topup_url="https://runanytime.hxi.me/api/user/topup",
                        headers=topup_headers,
                        cookies=cookies,
                        key=code,
                        proxy=self.http_proxy_config,
                    )
                    results["topup"] = topup_result.get("success", False)
                    if not topup_result.get("success") and not topup_result.get("already_used"):
                        errors.append(topup_result.get("error", "Topup failed"))
                        # topup 失败时直接返回，不继续执行 wheel
                        print(f"❌ {self.account_name}: Checkin topup failed, stopping")
                        results["display"] = f"❗ Checkin topup failed: \n{'\n  '.join(errors)}"
                        return False, results
                    topup_count += 1
                elif checkin_success:
                    print(f"⚠️ {self.account_name}: No code available, skipping topup")
                    results["topup"] = True  # 没有 code 时跳过，不算失败
            else:
                print(f"✅ {self.account_name}: Already checked in today")
                results["checkin"] = True
                results["topup"] = True

            # Step 4: 执行大转盘
            wheel_status_success, remaining = self.get_wheel_status(client, headers, fuli_cookies)

            if wheel_status_success and remaining > 0:
                print(f"🎡 {self.account_name}: {remaining} wheel spins available")
                wheel_success_count = 0
                wheel_fail_count = 0

                while remaining > 0:
                    # 如果之前有 topup，等待 60 秒防止快速请求被拒
                    if topup_count > 0:
                        print(f"⏳ {self.account_name}: Waiting 60 seconds before next request...")
                        await asyncio.sleep(60)

                    # 执行大转盘，返回值包含 remaining
                    wheel_success, wheel_code, remaining = self.execute_wheel(client, headers, fuli_cookies)

                    if wheel_success and wheel_code:
                        results["wheel_count"] += 1

                        # 执行 topup
                        print(f"💰 {self.account_name}: Executing topup with wheel code: {wheel_code}")
                        # 构建 topup 请求头
                        wheel_topup_headers = headers.copy()
                        wheel_topup_headers.update({
                            "Referer": "https://runanytime.hxi.me/console/topup",
                            "Origin": "https://runanytime.hxi.me",
                            "new-api-user": f"{api_user}",
                        })
                        wheel_topup_result = topup(
                            account_name=self.account_name,
                            topup_url="https://runanytime.hxi.me/api/user/topup",
                            headers=wheel_topup_headers,
                            cookies=cookies,
                            key=wheel_code,
                            proxy=self.http_proxy_config,
                        )
                        topup_count += 1

                        if wheel_topup_result.get("success"):
                            wheel_success_count += 1
                            results["wheel_topup_success_count"] += 1
                        else:
                            print(f"⚠️ {self.account_name}: Wheel topup failed for code: {wheel_code}")
                            if not wheel_topup_result.get("already_used"):
                                errors.append(wheel_topup_result.get("error", "Wheel topup failed"))
                                # topup 失败时退出循环，避免浪费 wheel code
                                print(f"❌ {self.account_name}: Topup failed, stopping wheel spins")
                                break
                        # remaining 已经从 execute_wheel 返回值中获取，无需再次调用 get_wheel_status
                    elif wheel_success:
                        # 成功但没有 code，说明没有剩余次数了
                        break
                    else:
                        # 失败，记录失败次数但继续尝试（允许部分失败）
                        wheel_fail_count += 1
                        print(f"⚠️ {self.account_name}: Wheel spin failed, continuing...")
                        # 如果连续失败太多次，退出循环避免无限重试
                        if wheel_fail_count >= 3:
                            print(f"❌ {self.account_name}: Too many wheel failures, stopping")
                            break

                # 只要有成功的就算成功
                results["wheel"] = wheel_success_count > 0 or wheel_fail_count == 0
                print(f"🎡 {self.account_name}: Wheel completed, {wheel_success_count} successful spins, {wheel_fail_count} failed")
            else:
                print(f"ℹ️ {self.account_name}: No wheel spins available")
                results["wheel"] = True  # 没有次数不算失败

            # Step 5: 获取用户余额信息
            print(f"💰 {self.account_name}: Getting user balance info")
            user_info_headers = headers.copy()
            user_info_headers.update({
                "Referer": "https://runanytime.hxi.me/console",
                "Origin": "https://runanytime.hxi.me",
                "new-api-user": f"{api_user}",
            })
            user_info_result = get_user_info(
                account_name=self.account_name,
                headers=user_info_headers,
                cookies=cookies,
                proxy=self.http_proxy_config,
            )
            if user_info_result.get("success"):
                results["quota"] = user_info_result.get("quota", 0)
                results["used_quota"] = user_info_result.get("used_quota", 0)
            else:
                # 获取用户信息失败，添加错误信息
                error_msg = user_info_result.get("error", "Get user info failed")
                errors.append(error_msg)

            # 判断整体是否成功
            overall_success = results["checkin"] and results["topup"] and results["wheel"]

            # 构建 display 字符串（只包含余额信息和错误信息，状态信息由 main.py 构建）
            display_parts = []
            
            # 添加余额信息
            if user_info_result.get("success"):
                balance_display = user_info_result.get("display", "")
                if balance_display:
                    display_parts.append(f"💵 {balance_display}")
            
            # 拼接 errors（如果有）
            if errors:
                display_parts.append(f"❗ Errors: \n{'\n  '.join(errors)}")
            
            results["display"] = "\n".join(display_parts) if display_parts else ""

            if overall_success:
                print(f"✅ {self.account_name}: All tasks completed successfully")
            else:
                failed_tasks = []
                if not results["checkin"]:
                    failed_tasks.append("checkin")
                if not results["topup"]:
                    failed_tasks.append("topup")
                if not results["wheel"]:
                    failed_tasks.append("wheel")
                print(f"⚠️ {self.account_name}: Some tasks failed: {', '.join(failed_tasks)}")

            return overall_success, results

        except Exception as e:
            print(f"❌ {self.account_name}: Error occurred during check-in process - {e}")
            # 返回完整的 results 格式，保留已完成的部分任务状态
            results["display"] = f"❗ An error occurred: {str(e)} \n{'\n  '.join(errors)}"
            return False, results
        finally:
            client.close()