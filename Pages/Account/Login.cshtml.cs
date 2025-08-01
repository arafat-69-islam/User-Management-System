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

                // Check if user exists
                if (user == null)
                {
                    Error = "⚠️ User is not registered. Please register first to login.";
                    _logger.LogWarning("Login attempt for non-registered user: {Email}", Input.Email);
                    ModelState.AddModelError(string.Empty, Error);
                    return Page();
                }

                // Check if password is correct
                if (user.PasswordHash != HashPassword(Input.Password))
                {
                    Error = "❌ Invalid email or password. Please check your credentials and try again.";
                    _logger.LogWarning("Invalid password attempt for user: {Email}", Input.Email);
                    ModelState.AddModelError(string.Empty, Error);
                    return Page();
                }

                // Handle different user statuses
                switch (user.Status)
                {
                    case UserStatus.Deleted:
                        // For deleted users, remove them from database and ask to register again
                        _context.Users.Remove(user);
                        await _context.SaveChangesAsync();
                        Error = "🗑️ Your account has been deleted. Please register again to create a new account.";
                        _logger.LogInformation("Deleted user {Email} attempted login, user record removed from database", Input.Email);
                        ModelState.AddModelError(string.Empty, Error);
                        return Page();

                    case UserStatus.Blocked:
                        Error = "🚫 Your account has been blocked by the administrator. Please contact support for assistance.";
                        _logger.LogWarning("Blocked user {Email} attempted login", Input.Email);
                        ModelState.AddModelError(string.Empty, Error);
                        return Page();

                    case UserStatus.Active:
                        // User is active, proceed with login
                        break;

                    default:
                        Error = "❓ Account status is invalid. Please contact support.";
                        _logger.LogWarning("User {Email} has invalid status: {Status}", Input.Email, user.Status);
                        ModelState.AddModelError(string.Empty, Error);
                        return Page();
                }

                // Update last login time for active users
                user.LastLogin = DateTime.UtcNow;
                await _context.SaveChangesAsync();

                // Create authentication claims
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

                _logger.LogInformation("User {Email} logged in successfully at {Time}", user.Email, DateTime.UtcNow);

                return LocalRedirect(ReturnUrl);
            }
            catch (Exception ex)
            {
                Error = "💥 An error occurred during login. Please try again.";
                _logger.LogError(ex, "Error during login attempt for {Email}", Input.Email ?? "unknown");
                ModelState.AddModelError(string.Empty, Error);
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