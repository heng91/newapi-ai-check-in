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
    ) -> tuple[bool, str, str]:
        """执行大转盘抽奖

        Args:
            client: httpx 客户端
            headers: 请求头
            fuli_cookies: fuli.hxi.me 站点的 cookies

        Returns:
            (是否成功, code, prize)
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
                return False, "", ""

            message = json_data.get("message", json_data.get("msg", ""))

            if json_data.get("success"):
                code = json_data.get("code", "")
                prize = json_data.get("prize", "")
                remaining = json_data.get("remaining", 0)
                expire_seconds = json_data.get("expireSeconds", 0)
                print(
                    f"✅ {self.account_name}: Wheel successful! "
                    f"Prize: {prize}, Code: {code}, Remaining: {remaining}, Expires in: {expire_seconds}s"
                )
                return True, code, prize

            if "already" in message.lower() or "已经" in message or "次数" in message:
                print(f"✅ {self.account_name}: No wheel spins remaining!")
                return True, "", ""

            error_msg = message if message else "Unknown error"
            print(f"❌ {self.account_name}: Wheel failed - {error_msg}")
            return False, "", ""

        print(f"❌ {self.account_name}: Wheel failed - HTTP {response.status_code}")
        return False, "", ""

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
                "wheel_prizes": [],
                "failed_keys": [],  # 收集失败的 keys 用于通知
                "code": ""
            }
            code = ""
            topup_count = 0  # 记录 topup 次数，用于判断是否需要等待

            # Step 1: 检查签到状态
            status_success, already_checked = self.get_checkin_status(client, headers, fuli_cookies)

            if not status_success:
                print(f"⚠️ {self.account_name}: Failed to get checkin status, will try to checkin anyway")

            if not already_checked:
                # Step 2: 执行签到，获取 code
                checkin_success, code = self.execute_checkin(client, headers, fuli_cookies)
                results["checkin"] = checkin_success
                results["code"] = code

                # Step 3: 执行 topup (使用 cookies、api_user 和 code)
                if code:
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
                        results["failed_keys"].append(code)
                    topup_count += 1
                else:
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
                results["wheel"] = True
                wheel_success_count = 0

                while remaining > 0:
                    # 如果之前有 topup，等待 60 秒防止快速请求被拒
                    if topup_count > 0:
                        print(f"⏳ {self.account_name}: Waiting 60 seconds before next request...")
                        await asyncio.sleep(60)

                    # 执行大转盘
                    wheel_success, wheel_code, prize = self.execute_wheel(client, headers, fuli_cookies)

                    if wheel_success and wheel_code:
                        results["wheel_count"] += 1
                        if prize:
                            results["wheel_prizes"].append(prize)

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
                        else:
                            print(f"⚠️ {self.account_name}: Wheel topup failed for code: {wheel_code}")
                            if not wheel_topup_result.get("already_used"):
                                results["failed_keys"].append(wheel_code)

                        # 更新剩余次数
                        _, remaining = self.get_wheel_status(client, headers, fuli_cookies)
                    elif wheel_success:
                        # 成功但没有 code，说明没有剩余次数了
                        break
                    else:
                        # 失败，退出循环
                        results["wheel"] = False
                        break

                print(f"🎡 {self.account_name}: Wheel completed, {wheel_success_count} successful spins")
            else:
                print(f"ℹ️ {self.account_name}: No wheel spins available")
                results["wheel"] = True  # 没有次数不算失败

            # 判断整体是否成功
            overall_success = results["checkin"] and results["topup"] and results["wheel"]

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
            return False, {"error": f"Check-in process error: {str(e)}"}
        finally:
            client.close()