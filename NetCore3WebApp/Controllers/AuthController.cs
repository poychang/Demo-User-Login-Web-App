using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Logging;
using NetCore3WebApp.Models;
using System.Security.Claims;
using System.Threading.Tasks;

namespace NetCore3WebApp.Controllers
{
    [AutoValidateAntiforgeryToken] // 資安要求，只要是 HTTP Post 都要驗證 Token
    public class AuthController : Controller
    {
        private readonly ILogger<AuthController> _logger;

        public AuthController(ILogger<AuthController> logger)
        {
            _logger = logger;
        }

        /// <summary>
        /// 登入頁
        /// </summary>
        /// <remarks>未登入者必須先登入，會被導至 /Auth/Login，網址後面會加上 QueryString:ReturnUrl (原始要求網址)</remarks>
        /// <returns></returns>
        public IActionResult Login(string returnUrl = "")
        {
            return View(new LoginFormModel { ReturnUrl = returnUrl });
        }

        /// <summary>
        /// 提交登入表單
        /// </summary>
        /// <param name="form"></param>
        /// <returns></returns>
        [HttpPost]
        public async Task<IActionResult> Login(LoginFormModel form)
        {
            // 帳號檢查請根據需求自行實作
            if ((form.Account == "admin" && form.Password == "admin") == false)
            {
                ViewBag.errMsg = "帳號或密碼輸入錯誤";
                return View();
            }

            // 帳密都輸入正確，產生身分聲明並存至 Cookie 中
            var claims = new[] {
                new Claim(ClaimTypes.Name, form.Account)
            };
            var claimsIdentity = new ClaimsIdentity(claims, CookieAuthenticationDefaults.AuthenticationScheme);
            var principal = new ClaimsPrincipal(claimsIdentity);

            await HttpContext.SignInAsync(principal,
                new AuthenticationProperties()
                {
                    // 瀏覽器關閉即刻登出
                    IsPersistent = false,
                    // 使用者操作逾期時間，此設定會覆蓋 Startup.cs 裡的逾期設定
                    // ExpiresUtc = DateTime.Now.AddMinutes(60)
                });

            // 加上 Url.IsLocalUrl 防止 Open Redirect 漏洞
            if (!string.IsNullOrEmpty(form.ReturnUrl) && Url.IsLocalUrl(form.ReturnUrl))
            {
                return Redirect(form.ReturnUrl); // 導到原始要求網址
            }
            else
            {
                return RedirectToAction("Index", "Home"); // 登入後的首頁
            }
        }

        /// <summary>
        /// 登出動作頁
        /// </summary>
        /// <returns></returns>
        public async Task<IActionResult> Logout()
        {
            await HttpContext.SignOutAsync();

            return RedirectToAction("Login", "Auth"); // 導至登入頁
        }
    }
}
