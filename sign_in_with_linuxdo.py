#!/usr/bin/env python3
"""
使用 Camoufox 绕过 Cloudflare 验证执行 Linux.do 签到
"""

import json
import os
from urllib.parse import urlparse
import tempfile

from utils.browser_utils import filter_cookies, human_behavior
from utils.config import ProviderConfig


class LinuxDoSignIn:
    """使用 Linux.do 登录授权类"""

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
            username: Linux.do 用户名
            password: Linux.do 密码
        """
        self.account_name = account_name
        self.provider_config = provider_config
        self.username = username
        self.password = password

    async def signin(
        self,
        client_id: str,
        auth_state: str,
        auth_cookies: list,
        cache_file_path: str = "",
    ) -> tuple[bool, dict]:
        """使用 PlayWright 执行 Linux.do 签到

        Args:
            client_id: OAuth 客户端 ID
            auth_state: OAuth 认证状态
            auth_cookies: OAuth 认证 cookies
            cache_dir: 缓存目录

        Returns:
            (成功标志, 用户信息字典)
        """

        print(f"ℹ️ {self.account_name}: Executing check-in with Linux.do")
        print(f"ℹ️ {self.account_name}: Using client_id: {client_id}, auth_state: {auth_state}")


        from playwright.async_api import async_playwright

        async with async_playwright() as p:

            with tempfile.TemporaryDirectory() as temp_dir:
                context = await p.chromium.launch_persistent_context(
                    user_data_dir=temp_dir,
                    headless=False,
                    user_agent="Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36",
                    viewport={"width": 1920, "height": 1080},
                    args=[
                        "--disable-blink-features=AutomationControlled",
                        "--disable-dev-shm-usage",
                        "--disable-web-security",
                        "--disable-features=VizDisplayCompositor",
                        "--no-sandbox",
                    ],
                )

                # 检查缓存文件是否存在, 从缓存文件中恢复会话cookies
                if os.path.exists(cache_file_path):
                    print(f"ℹ️ {self.account_name}: Found cache file, restoring session state")
                    try:
                        with open(cache_file_path, "r", encoding="utf-8") as f:
                            cache_data = json.load(f)
                            cookies = cache_data.get("cookies", [])
                            if cookies:
                                # 获取域名用于设置 cookies
                                parsed_domain = urlparse(self.provider_config.origin).netloc
                                playwright_cookies = []
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
                                    playwright_cookies.append(cookie_data)

                                await context.add_cookies(playwright_cookies)
                                print(f"✅ {self.account_name}: Restored {len(playwright_cookies)} cookies from cache")
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
                auth_cookies = auth_state.get("cookies", [])
                if auth_cookies:
                    await context.add_cookies(auth_cookies)
                    print(f"ℹ️ {self.account_name}: Set {len(auth_cookies)} auth cookies from provider")
                else:
                    print(f"ℹ️ {self.account_name}: No auth cookies to set")

                page = await context.new_page()

                try:
                    # 检查是否已经登录（通过缓存恢复）
                    is_logged_in = False
                    oauth_url = f"https://connect.linux.do/oauth2/authorize?response_type=code&client_id={client_id['client_id']}&state={auth_state['auth_data']}"
                    if os.path.exists(cache_file_path):
                        try:
                            print(f"ℹ️ {self.account_name}: open {oauth_url}")
                            # 直接访问授权页面检查是否已登录
                            await page.goto(oauth_url, wait_until="domcontentloaded")

                            # 检查是否出现授权按钮（表示已登录）
                            allow_btn = await page.query_selector('a[href^="/oauth2/approve"]')
                            if allow_btn:
                                is_logged_in = True
                                print(
                                    f"✅ {self.account_name}: Already logged in via cache, proceeding to authorization"
                                )
                            else:
                                print(f"ℹ️ {self.account_name}: Cache session expired, need to login again")
                        except Exception as e:
                            print(f"⚠️ {self.account_name}: Failed to check login status: {e}")

                    # 如果未登录，则执行登录流程
                    if not is_logged_in:
                        try:
                            print(f"ℹ️ {self.account_name}: start to sign in linux.do")

                            await page.goto("https://linux.do/login", wait_until="domcontentloaded")
                            await human_behavior(page)
                            await page.fill("#login-account-name", self.username)
                            await human_behavior(page)
                            await page.wait_for_timeout(2000)
                            await page.fill("#login-account-password", self.password)
                            await human_behavior(page)
                            await page.wait_for_timeout(2000)
                            await page.click("#login-button")
                            await page.wait_for_timeout(10000)

                            # 检查是否遇到 Cloudflare 验证页面
                            current_url = page.url
                            if "linux.do/challenge" in current_url:
                                print(
                                    f"⚠️ {self.account_name}: Cloudflare challenge detected, "
                                    "waiting 60 seconds for manual intervention..."
                                )
                                await page.wait_for_selector('a[href^="/oauth2/approve"]', timeout=60000)

                                # 验证挑战是否已完成
                                current_url = page.url
                                if "linux.do/challenge" in current_url:
                                    print(
                                        f"❌ {self.account_name}: Cloudflare challenge not completed, "
                                        "still on challenge page"
                                    )
                                    return False, {"error": "Cloudflare challenge not completed"}

                                print(f"✅ {self.account_name}: Challenge completed successfully")

                            # 保存新的会话状态
                            await context.storage_state(path=cache_file_path)

                        except Exception as e:
                            print(f"❌ {self.account_name}: Error occurred while signing in linux.do: {e}")
                            return False, {"error": "Linux.do sign-in error"}

                        # 登录后访问授权页面
                        try:
                            print(f"ℹ️ {self.account_name}: open {oauth_url}")
                            await page.goto(oauth_url, wait_until="domcontentloaded")
                        except Exception as e:
                            print(f"❌ {self.account_name}: Failed to navigate to authorization page: {e}")
                            return False, {"error": "Linux.do authorization page navigation failed"}

                    # 统一处理授权逻辑（无论是否通过缓存登录）
                    try:
                        # 等待授权按钮出现，最多等待30秒
                        await page.wait_for_selector('a[href^="/oauth2/approve"]', timeout=30000)
                        allow_btn_ele = await page.query_selector('a[href^="/oauth2/approve"]')
                        if allow_btn_ele:
                            await allow_btn_ele.click()
                            await page.wait_for_url(f"**{self.provider_config.origin}/oauth/**", timeout=30000)

                            # 从 localStorage 获取 user 对象并提取 id
                            api_user = None
                            try:
                                # 等待5秒, 登录完成后 localStorage 可能需要时间更新
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
                                cookies = await page.context.cookies()
                                user_cookies = filter_cookies(cookies, self.provider_config.origin)

                                return True, {"cookies": user_cookies, "api_user": api_user}
                            else:
                                print(f"❌ {self.account_name}: OAuth failed")
                                return False, {"error": "Linux.do OAuth failed - no user ID found"}
                        else:
                            print(f"❌ {self.account_name}: Approve button not found")
                            return False, {"error": "Linux.do allow button not found"}
                    except Exception as e:
                        print(
                            f"❌ {self.account_name}: Error occurred while signing in linux.do: {e} \n\nCurrent page is : {page.url}"
                        )
                        return False, {"error": "Linux.do authorization failed"}
                except Exception as e:
                    print(f"❌ {self.account_name}: Error occurred while goto linux.do page: {e}")
                    return False, {"error": "Linux.do page navigation error"}
                finally:
                    await page.close()
                    await context.close()

    async def signin_bypass(
        self,
        client_id: str,
        auth_state: str,
        auth_cookies: list,
        cache_file_path: str = "",
    ) -> tuple[bool, dict]:
        """使用 Camoufox 绕过 Cloudflare 验证执行 Linux.do 签到

        Args:
            client_id: OAuth 客户端 ID
            auth_state: OAuth 认证状态
            auth_cookies: OAuth 认证 cookies
            cache_file_path: 缓存文件

        Returns:
            (成功标志, 用户信息字典)
        """
        print(f"ℹ️ {self.account_name}: Executing check-in with Linux.do (Camoufox bypass)")
        print(f"ℹ️ {self.account_name}: Using client_id: {client_id}, auth_state: {auth_state}")

        from camoufox.async_api import AsyncCamoufox

        try:
            with tempfile.TemporaryDirectory() as temp_dir:
                # 使用 Camoufox 启动浏览器
                async with AsyncCamoufox(
                    persistent_context=True,
                    user_data_dir=temp_dir,
                    headless=False,
                    humanize=True,
                    locale="en-US",
                ) as browser:  # 启用人性化行为
                    # 创建新的浏览器上下文
                    context = await browser.new_context()

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
                                    playwright_cookies = []
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
                                        playwright_cookies.append(cookie_data)

                                    await context.add_cookies(playwright_cookies)
                                    print(
                                        f"✅ {self.account_name}: Restored {len(playwright_cookies)} cookies from cache"
                                    )
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

                    # 设置从参数获取的 auth cookies 到页面上下文
                    if auth_cookies:
                        await context.add_cookies(auth_cookies)
                        print(f"ℹ️ {self.account_name}: Set {len(auth_cookies)} auth cookies from provider")
                    else:
                        print(f"ℹ️ {self.account_name}: No auth cookies to set")

                    page = await context.new_page()

                    try:
                        # 检查是否已经登录（通过缓存恢复）
                        is_logged_in = False
                        oauth_url = (
                            f"https://connect.linux.do/oauth2/authorize?"
                            f"response_type=code&client_id={client_id}&state={auth_state}"
                        )

                        if os.path.exists(cache_file_path):
                            try:
                                print(f"ℹ️ {self.account_name}: Checking login status at {oauth_url}")
                                # 直接访问授权页面检查是否已登录
                                await page.goto(oauth_url, wait_until="domcontentloaded")

                                # 检查是否出现授权按钮（表示已登录）
                                allow_btn = await page.query_selector('a[href^="/oauth2/approve"]')
                                if allow_btn:
                                    is_logged_in = True
                                    print(
                                        f"✅ {self.account_name}: Already logged in via cache, proceeding to authorization"
                                    )
                                else:
                                    print(f"ℹ️ {self.account_name}: Cache session expired, need to login again")
                            except Exception as e:
                                print(f"⚠️ {self.account_name}: Failed to check login status: {e}")

                        # 如果未登录，则执行登录流程
                        if not is_logged_in:
                            try:
                                print(f"ℹ️ {self.account_name}: Starting to sign in linux.do with Camoufox")

                                await page.goto("https://linux.do/login", wait_until="domcontentloaded")

                                await page.fill("#login-account-name", self.username)
                                await page.wait_for_timeout(2000)

                                await page.fill("#login-account-password", self.password)
                                await page.wait_for_timeout(2000)

                                await page.click("#login-button")

                                # Camoufox 应该能够自动绕过 Cloudflare 验证
                                # 但我们仍然检查是否遇到验证页面
                                print(
                                    f"ℹ️ {self.account_name}: Waiting for login completion (Cloudflare bypass active)..."
                                )

                                try:
                                    # 等待可能的 Cloudflare 验证完成
                                    # Camoufox 应该会自动处理，我们只需要等待
                                    await page.wait_for_timeout(10000)

                                    current_url = page.url
                                    if "linux.do/challenge" in current_url:
                                        print(
                                            f"⚠️ {self.account_name}: Cloudflare challenge detected, "
                                            "Camoufox should bypass it automatically. Waiting..."
                                        )
                                        # 等待 Cloudflare 验证完成
                                        await page.wait_for_selector('a[href^="/oauth2/approve"]', timeout=60000)
                                        print(f"✅ {self.account_name}: Cloudflare challenge bypassed successfully")

                                except Exception as e:
                                    print(f"⚠️ {self.account_name}: Possible Cloudflare challenge: {e}")
                                    # 即使超时，也尝试继续
                                    pass

                                # 保存新的会话状态
                                await context.storage_state(path=cache_file_path)
                                print(f"✅ {self.account_name}: Session state saved to cache")

                            except Exception as e:
                                print(f"❌ {self.account_name}: Error occurred while signing in linux.do: {e}")
                                return False, {"error": "Linux.do sign-in error"}

                            # 登录后访问授权页面
                            try:
                                print(f"ℹ️ {self.account_name}: Navigating to authorization page: {oauth_url}")
                                await page.goto(oauth_url, wait_until="domcontentloaded")
                            except Exception as e:
                                print(f"❌ {self.account_name}: Failed to navigate to authorization page: {e}")
                                return False, {"error": "Linux.do authorization page navigation failed"}

                        # 统一处理授权逻辑（无论是否通过缓存登录）
                        try:
                            # 等待授权按钮出现，最多等待30秒
                            print(f"ℹ️ {self.account_name}: Waiting for authorization button...")
                            await page.wait_for_selector('a[href^="/oauth2/approve"]', timeout=30000)
                            allow_btn_ele = await page.query_selector('a[href^="/oauth2/approve"]')

                            if allow_btn_ele:
                                print(f"ℹ️ {self.account_name}: Clicking authorization button...")
                                await allow_btn_ele.click()
                                await page.wait_for_url(f"**{self.provider_config.origin}/oauth/**", timeout=30000)

                                # 从 localStorage 获取 user 对象并提取 id
                                api_user = None
                                try:
                                    # 等待5秒, 登录完成后 localStorage 可能需要时间更新
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
                                    cookies = await page.context.cookies()
                                    user_cookies = filter_cookies(cookies, self.provider_config.origin)

                                    return True, {"cookies": user_cookies, "api_user": api_user}
                                else:
                                    print(f"❌ {self.account_name}: OAuth failed")
                                    return False, {"error": "Linux.do OAuth failed - no user ID found"}
                            else:
                                print(f"❌ {self.account_name}: Approve button not found")
                                return False, {"error": "Linux.do allow button not found"}

                        except Exception as e:
                            print(
                                f"❌ {self.account_name}: Error occurred during authorization: {e}\n\n"
                                f"Current page is: {page.url}"
                            )
                            return False, {"error": "Linux.do authorization failed"}

                    except Exception as e:
                        print(f"❌ {self.account_name}: Error occurred while processing linux.do page: {e}")
                        return False, {"error": "Linux.do page navigation error"}
                    finally:
                        await page.close()

        except Exception as e:
            print(f"❌ {self.account_name}: Error occurred during check-in process - {e}")
            return False, {"error": "Linux.do check-in process error"}
