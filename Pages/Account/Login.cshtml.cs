using System.ComponentModel.DataAnnotations;
using System.Security.Claims;
using System.Security.Cryptography;
using System.Text;
using Demo.Data;
using Demo.Models;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;
using Microsoft.EntityFrameworkCore;

namespace Demo.Pages.Account
{
    public class LoginModel : PageModel
    {
        private readonly ApplicationDbContext _context;
        private readonly ILogger<LoginModel> _logger;

        public LoginModel(ApplicationDbContext context, ILogger<LoginModel> logger)
        {
            _context = context;
            _logger = logger;
        }

        [BindProperty]
        public InputModel Input { get; set; } = new();

        public string? ReturnUrl { get; set; }
        public string? Message { get; set; }
        public string? Error { get; set; }

        public class InputModel
        {
            [Required, EmailAddress]
            public string Email { get; set; } = string.Empty;

            [Required, DataType(DataType.Password)]
            public string Password { get; set; } = string.Empty;

            [Display(Name = "Remember me?")]
            public bool RememberMe { get; set; }
        }

        public void OnGet(string? returnUrl = null, string? message = null)
        {
            ReturnUrl = returnUrl;
            Message = message;
        }

        public async Task<IActionResult> OnPostAsync(string? returnUrl = null)
        {
            ReturnUrl = returnUrl ?? Url.Content("~/");

            if (!ModelState.IsValid)
            {
                return Page();
            }

            try
            {
                var user = await _context.Users
                    .FirstOrDefaultAsync(u => u.Email == Input.Email);

                if (user == null || user.PasswordHash != HashPassword(Input.Password))
                {
                    Error = "Invalid login attempt";
                    _logger.LogWarning("Invalid login attempt for {Email}", Input.Email);
                    return Page();
                }

                // Requirement 5: Check if user exists and isn't blocked before each request
                if (user.Status == UserStatus.Blocked)
                {
                    Error = "Account is blocked";
                    return Page();
                }

                if (user.Status == UserStatus.Deleted)
                {
                    Error = "Account not found";
                    return Page();
                }

                // Update last login
                user.LastLogin = DateTime.UtcNow;
                await _context.SaveChangesAsync();

                var claims = new List<Claim>
                {
                    new(ClaimTypes.NameIdentifier, user.Id.ToString()),
                    new(ClaimTypes.Name, user.Name),
                    new(ClaimTypes.Email, user.Email),
                    new("Status", user.Status.ToString())
                };

                var authProperties = new AuthenticationProperties
                {
                    IsPersistent = Input.RememberMe,
                    ExpiresUtc = Input.RememberMe ? DateTimeOffset.UtcNow.AddDays(30) : null
                };

                await HttpContext.SignInAsync(
                    CookieAuthenticationDefaults.AuthenticationScheme,
                    new ClaimsPrincipal(new ClaimsIdentity(claims, CookieAuthenticationDefaults.AuthenticationScheme)),
                    authProperties);

                _logger.LogInformation("User {Email} logged in at {Time}", user.Email, DateTime.UtcNow);

                return LocalRedirect(ReturnUrl);
            }
            catch (Exception ex)
            {
                Error = "An error occurred during login";
                _logger.LogError(ex, "Error during login for {Email}", Input.Email);
                return Page();
            }
        }

        private static string HashPassword(string password)
        {
            using var sha256 = SHA256.Create();
            var bytes = sha256.ComputeHash(Encoding.UTF8.GetBytes(password));
            return Convert.ToBase64String(bytes);
        }
    }
}