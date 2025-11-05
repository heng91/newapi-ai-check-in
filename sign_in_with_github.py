#!/usr/bin/env python3
"""
使用 GitHub 账号执行登录授权
"""

import json
import os
import tempfile
from urllib.parse import urlparse
from datetime import datetime
from camoufox.async_api import AsyncCamoufox
from utils.browser_utils import filter_cookies
from utils.config import ProviderConfig
from utils.wait_for_secrets import WaitForSecrets


class GitHubSignIn:
    """使用 GitHub 登录授权类"""

    def __init__(
        self,
        account_name: str,
        provider_config: ProviderConfig,
        username: str,
        password: str,
    ):
        """初始化

        Args:
            account_name: 账号名称
            provider_config: 提供商配置
            username: GitHub 用户名
            password: GitHub 密码
        """
        self.account_name = account_name
        self.provider_config = provider_config
        self.username = username
        self.password = password

    async def _take_screenshot(self, page, reason: str) -> None:
        """截取当前页面的屏幕截图

        Args:
            page: Camoufox 页面对象
            reason: 截图原因描述
        """
        try:
            # 创建 screenshots 目录
            screenshots_dir = "screenshots"
            os.makedirs(screenshots_dir, exist_ok=True)

            # 生成文件名: 账号名_时间戳_原因.png
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            safe_account_name = "".join(c if c.isalnum() else "_" for c in self.account_name)
            safe_reason = "".join(c if c.isalnum() else "_" for c in reason)
            filename = f"{safe_account_name}_{timestamp}_{safe_reason}.png"
            filepath = os.path.join(screenshots_dir, filename)

            await page.screenshot(path=filepath, full_page=True)
            print(f"📸 {self.account_name}: Screenshot saved to {filepath}")
        except Exception as e:
            print(f"⚠️ {self.account_name}: Failed to take screenshot: {e}")

    async def signin(
        self,
        client_id: str,
        auth_state: str,
        auth_cookies: list,
        cache_file_path: str = "",
    ) -> tuple[bool, dict]:
        """使用 GitHub 账号执行登录授权

        Args:
            client_id: OAuth 客户端 ID
            auth_state: OAuth 认证状态
            auth_cookies: OAuth 认证 cookies
            cache_file_path: 缓存文件路径

        Returns:
            (成功标志, 结果字典)
        """
        print(f"ℹ️ {self.account_name}: Executing sign-in with GitHub account")
        print(f"ℹ️ {self.account_name}: Using client_id: {client_id}, auth_state: {auth_state}")

        with tempfile.TemporaryDirectory() as temp_dir:
            async with AsyncCamoufox(
                persistent_context=True,
                user_data_dir=temp_dir,
                headless=False,
                humanize=True,
                locale="en-US",
            ) as browser:
                # 检查缓存文件是否存在，从缓存文件中恢复会话 cookies
                if os.path.exists(cache_file_path):
                    print(f"ℹ️ {self.account_name}: Found cache file, restoring session state")
                    try:
                        with open(cache_file_path, "r", encoding="utf-8") as f:
                            cache_data = json.load(f)
                            cookies = cache_data.get("cookies", [])
                            if cookies:
                                # 获取域名用于设置 cookies
                                parsed_domain = urlparse(self.provider_config.origin).netloc
                                camoufox_cookies = []
                                for cookie in cookies:
                                    cookie_data = {
                                        "name": cookie["name"],
                                        "value": cookie["value"],
                                        "domain": cookie.get("domain", parsed_domain),
                                        "path": cookie.get("path", "/"),
                                        "expires": cookie.get("expires"),
                                        "httpOnly": cookie.get("httpOnly", False),
                                        "secure": cookie.get("secure", False),
                                        "sameSite": cookie.get("sameSite", "Lax"),
                                    }
                                    camoufox_cookies.append(cookie_data)

                                await browser.add_cookies(camoufox_cookies)
                                print(f"✅ {self.account_name}: Restored {len(camoufox_cookies)} cookies from cache")
                            else:
                                print(f"⚠️ {self.account_name}: No cookies found in cache file")
                    except json.JSONDecodeError as e:
                        print(f"⚠️ {self.account_name}: Invalid JSON in cache file: {e}")
                    except FileNotFoundError:
                        print(f"⚠️ {self.account_name}: Cache file not found: {cache_file_path}")
                    except Exception as e:
                        print(f"⚠️ {self.account_name}: Failed to restore cache: {e}")
                else:
                    print(f"ℹ️ {self.account_name}: No cache file found, proceeding with fresh login")

                # 设置从 auth_state 获取的 session cookies 到页面上下文
                if auth_cookies:
                    await browser.add_cookies(auth_cookies)
                    print(f"ℹ️ {self.account_name}: Set {len(auth_cookies)} auth cookies from provider")
                else:
                    print(f"ℹ️ {self.account_name}: No auth cookies to set")

                page = await browser.new_page()

                try:
                    # 检查是否已经登录（通过缓存恢复）
                    is_logged_in = False
                    oauth_url = f"https://github.com/login/oauth/authorize?response_type=code&client_id={client_id}&state={auth_state}&scope=user:email"

                    if os.path.exists(cache_file_path):
                        try:
                            print(f"ℹ️ {self.account_name}: Checking login status at {oauth_url}")
                            # 直接访问授权页面检查是否已登录
                            response = await page.goto(oauth_url, wait_until="domcontentloaded")
                            print(
                                f"ℹ️ {self.account_name}: redirected to app page {response.url if response else 'N/A'}"
                            )

                            # GitHub 登录后可能直接跳转回应用页面
                            if response and response.url.startswith(self.provider_config.origin):
                                is_logged_in = True
                                print(
                                    f"✅ {self.account_name}: Already logged in via cache, proceeding to authorization"
                                )
                            else:
                                # 检查是否出现授权按钮（表示已登录）
                                authorize_btn = await page.query_selector('button[type="submit"]')
                                if authorize_btn:
                                    is_logged_in = True
                                    print(
                                        f"✅ {self.account_name}: Already logged in via cache, proceeding to authorization"
                                    )
                                    await authorize_btn.click()
                                else:
                                    print(f"ℹ️ {self.account_name}: Approve button not found, need to login again")
                        except Exception as e:
                            print(f"⚠️ {self.account_name}: Failed to check login status: {e}")

                    # 如果未登录，则执行登录流程
                    if not is_logged_in:
                        try:
                            print(f"ℹ️ {self.account_name}: Starting to sign in GitHub")

                            await page.goto("https://github.com/login", wait_until="domcontentloaded")
                            await page.fill("#login_field", self.username)
                            await page.fill("#password", self.password)
                            await page.click('input[type="submit"][value="Sign in"]')
                            await page.wait_for_timeout(10000)

                            # 处理两步验证（如果需要）
                            try:
                                # 检查是否需要两步验证
                                otp_input = await page.query_selector('input[name="otp"]')
                                if otp_input:
                                    print(f"ℹ️ {self.account_name}: Two-factor authentication required")

                                    # 尝试通过 wait-for-secrets 自动获取 OTP
                                    otp_code = None
                                    try:
                                        print(
                                            f"🔐 {self.account_name}: Attempting to retrieve OTP via wait-for-secrets..."
                                        )
                                        # Define secret object
                                        wait_for_secrets = WaitForSecrets()
                                        secret_obj = {
                                            "OTP": {
                                                "name": "GitHub 2FA OTP",
                                                "description": "OTP from authenticator app",
                                            }
                                        }
                                        secrets = wait_for_secrets.get(secret_obj, timeout=5)
                                        if secrets and "OTP" in secrets:
                                            otp_code = secrets["OTP"]
                                            print(f"✅ {self.account_name}: Retrieved OTP via wait-for-secrets")
                                    except Exception as e:
                                        print(f"⚠️ {self.account_name}: wait-for-secrets failed: {e}")

                                    if otp_code:
                                        # 自动填充 OTP
                                        print(f"✅ {self.account_name}: Auto-filling OTP code")
                                        await otp_input.fill(otp_code)
                                        # 提交表单
                                        submit_btn = await page.query_selector('button[type="submit"]')
                                        if submit_btn:
                                            await submit_btn.click()
                                            print(f"✅ {self.account_name}: OTP submitted successfully")
                                        await page.wait_for_timeout(5000)  # 等待5秒确认提交
                                    else:
                                        # 回退到手动输入
                                        print(f"ℹ️ {self.account_name}: Please enter OTP manually in the browser")
                                        await page.wait_for_timeout(30000)  # 等待30秒让用户手动输入
                            except Exception as e:
                                print(f"⚠️ {self.account_name}: Error handling 2FA: {e}")
                                pass

                            # 保存新的会话状态
                            await browser.storage_state(path=cache_file_path)
                            print(f"✅ {self.account_name}: Session state saved to cache")

                        except Exception as e:
                            print(f"❌ {self.account_name}: Error occurred while signing in GitHub: {e}")
                            await self._take_screenshot(page, "github_signin_error")
                            return False, {"error": "GitHub sign-in error"}

                        # 登录后访问授权页面
                        try:
                            print(f"ℹ️ {self.account_name}: Navigating to authorization page: {oauth_url}")
                            response = await page.goto(oauth_url, wait_until="domcontentloaded")
                            print(
                                f"ℹ️ {self.account_name}: redirected to app page {response.url if response else 'N/A'}"
                            )

                            # GitHub 登录后可能直接跳转回应用页面
                            if response and response.url.startswith(self.provider_config.origin):
                                print(f"✅ {self.account_name}: logged in, proceeding to authorization")
                            else:
                                # 检查是否出现授权按钮（表示已登录）
                                authorize_btn = await page.query_selector('button[type="submit"]')
                                if authorize_btn:
                                    print(
                                        f"✅ {self.account_name}: Already logged in via cache, proceeding to authorization"
                                    )
                                    await authorize_btn.click()
                                else:
                                    print(f"ℹ️ {self.account_name}: Approve button not found")
                        except Exception as e:
                            print(f"❌ {self.account_name}: Error occurred while authorization approve: {e}")
                            await self._take_screenshot(page, "github_auth_approval_failed")
                            return False, {"error": "GitHub authorization approval failed"}

                    # 统一处理授权逻辑（无论是否通过缓存登录）
                    try:
                        print(f"ℹ️ {self.account_name}: Waiting for OAuth callback...")
                        await page.wait_for_url(f"**{self.provider_config.origin}/oauth/**", timeout=30000)

                        # 从 localStorage 获取 user 对象并提取 id
                        api_user = None
                        try:
                            # 等待5秒，登录完成后 localStorage 可能需要时间更新
                            await page.wait_for_timeout(5000)
                            user_data = await page.evaluate("() => localStorage.getItem('user')")
                            if user_data:
                                user_obj = json.loads(user_data)
                                api_user = user_obj.get("id")
                                if api_user:
                                    print(f"✅ {self.account_name}: Got api user: {api_user}")
                                else:
                                    print(f"⚠️ {self.account_name}: User id not found in localStorage")
                            else:
                                print(f"⚠️ {self.account_name}: User data not found in localStorage")
                        except Exception as e:
                            print(f"⚠️ {self.account_name}: Error reading user from localStorage: {e}")

                        if api_user:
                            print(f"✅ {self.account_name}: OAuth authorization successful")

                            # 提取 session cookie，只保留与 provider domain 匹配的
                            cookies = await browser.cookies()
                            user_cookies = filter_cookies(cookies, self.provider_config.origin)

                            return True, {"cookies": user_cookies, "api_user": api_user}
                        else:
                            print(f"❌ {self.account_name}: OAuth failed")
                            await self._take_screenshot(page, "github_oauth_failed_no_user_id")
                            return False, {"error": "GitHub OAuth failed - no user ID found"}

                    except Exception as e:
                        print(
                            f"❌ {self.account_name}: Error occurred during authorization: {e}\n\n"
                            f"Current page is: {page.url}"
                        )
                        await self._take_screenshot(page, "github_authorization_failed")
                        return False, {"error": "GitHub authorization failed"}

                except Exception as e:
                    print(f"❌ {self.account_name}: Error occurred while processing GitHub page: {e}")
                    await self._take_screenshot(page, "github_page_navigation_error")
                    return False, {"error": "GitHub page navigation error"}
                finally:
                    await page.close()
