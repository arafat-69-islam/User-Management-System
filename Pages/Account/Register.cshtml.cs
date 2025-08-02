using System.ComponentModel.DataAnnotations;
using System.Security.Cryptography;
using System.Text;
using Demo.Data;
using Demo.Models;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;
using Microsoft.EntityFrameworkCore;

namespace Demo.Pages.Account
{
    public class RegisterModel : PageModel
    {
        private readonly ApplicationDbContext _context;
        private readonly ILogger<RegisterModel> _logger;

        public RegisterModel(ApplicationDbContext context, ILogger<RegisterModel> logger)
        {
            _context = context;
            _logger = logger;
        }

        [BindProperty]
        public InputModel Input { get; set; } = new InputModel();

        public string? ReturnUrl { get; set; }
        public string? Message { get; set; }
        public string? Error { get; set; }

        public class InputModel
        {
            [Required, StringLength(100)]
            public string Name { get; set; } = string.Empty;

            [Required, DataType(DataType.Date)]
            public DateTime DateOfBirth { get; set; } = DateTime.Today;

            [Required, Phone, StringLength(20)]
            public string MobileNumber { get; set; } = string.Empty;

            [Required, EmailAddress, StringLength(100)]
            public string Email { get; set; } = string.Empty;

            [Required, StringLength(10)]
            public string Gender { get; set; } = string.Empty;

            [Required, DataType(DataType.Password), MinLength(1)]
            public string Password { get; set; } = string.Empty;
        }

        public void OnGet(string? returnUrl = null)
        {
            ReturnUrl = returnUrl;
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
                // Check if user already exists with this email
                var existingUser = await _context.Users
                    .FirstOrDefaultAsync(u => u.Email == Input.Email);

                if (existingUser != null)
                {
                    // Handle different user statuses
                    switch (existingUser.Status)
                    {
                        case UserStatus.Active:
                            ModelState.AddModelError("Input.Email", "Email is already registered and active. Please login instead.");
                            return Page();

                        case UserStatus.Blocked:
                            Error = "An account with this email is blocked. Please contact support for assistance.";
                            _logger.LogWarning("Registration attempt with blocked email: {Email}", Input.Email);
                            return Page();

                        case UserStatus.Deleted:
                            // This case should not occur since deleted users are removed from database during login
                            // But just in case, we handle it by removing the record and allowing re-registration
                            _context.Users.Remove(existingUser);
                            await _context.SaveChangesAsync();
                            _logger.LogInformation("Removed deleted user record for {Email} during registration", Input.Email);
                            break;
                    }
                }

                // Create new user account
                var user = new User
                {
                    Name = Input.Name,
                    DateOfBirth = Input.DateOfBirth,
                    MobileNumber = Input.MobileNumber,
                    Email = Input.Email,
                    Gender = Input.Gender,
                    PasswordHash = HashPassword(Input.Password),
                    Status = UserStatus.Active,
                    LastLogin = DateTime.UtcNow
                };

                _context.Users.Add(user);
                await _context.SaveChangesAsync();

                _logger.LogInformation("New user registered successfully: {Email}", Input.Email);
                Message = "Registration successful! Please login.";
                return RedirectToPage("./Login", new { message = Message, returnUrl = ReturnUrl });
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error during registration for {Email}", Input.Email);
                Error = "An error occurred during registration. Please try again.";
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