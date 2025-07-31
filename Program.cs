using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Authentication; // Add this using directive
using Pomelo.EntityFrameworkCore.MySql.Infrastructure;
using Demo.Data;
using Demo.Models;
using Microsoft.EntityFrameworkCore;
using System.Security.Cryptography;
using System.Text;
using System.Security.Claims;

var builder = WebApplication.CreateBuilder(args);

// Add services to the container.
builder.Services.AddRazorPages();
builder.Services.AddAuthentication(CookieAuthenticationDefaults.AuthenticationScheme)
    .AddCookie(options =>
    {
        options.LoginPath = "/Account/Login";
        options.AccessDeniedPath = "/Account/Login";
        options.LogoutPath = "/Account/Logout";
        options.ExpireTimeSpan = TimeSpan.FromHours(24);
        options.SlidingExpiration = true;
    });

builder.Services.AddDbContext<ApplicationDbContext>(options =>
    options.UseMySql(
        builder.Configuration.GetConnectionString("DefaultConnection"),
        new MySqlServerVersion(new Version(8, 0, 33)), // Specify your MySQL version
        mySqlOptions => mySqlOptions
            .EnableRetryOnFailure(
                maxRetryCount: 5,
                maxRetryDelay: TimeSpan.FromSeconds(30),
                errorNumbersToAdd: null)
    ));

// Add logging
builder.Services.AddLogging(logging =>
{
    logging.AddConsole();
    logging.AddDebug();
});

var app = builder.Build();

// Seed admin user with exact credentials: username "admin", password "123"
using (var scope = app.Services.CreateScope())
{
    var context = scope.ServiceProvider.GetRequiredService<ApplicationDbContext>();
    var logger = scope.ServiceProvider.GetRequiredService<ILogger<Program>>();
    
    try
    {
        await context.Database.EnsureCreatedAsync();
        logger.LogInformation("Database ensured created");

        // Check if admin user exists
        if (!await context.Users.AnyAsync(u => u.Email == "admin"))
        {
            var adminUser = new User
            {
                Name = "Administrator",
                Email = "admin", // Username is "admin"
                PasswordHash = HashPassword("123"), // Password is "123"
                DateOfBirth = new DateTime(1990, 1, 1),
                MobileNumber = "1234567890",
                Gender = "Other",
                Status = UserStatus.Active,
                LastLogin = DateTime.UtcNow
            };
            
            context.Users.Add(adminUser);
            await context.SaveChangesAsync();
            logger.LogInformation("Admin user created successfully with username 'admin' and password '123'");
        }
        else
        {
            logger.LogInformation("Admin user already exists");
        }
    }
    catch (Exception ex)
    {
        logger.LogError(ex, "Error during database initialization");
    }
}

// Configure the HTTP request pipeline.
if (!app.Environment.IsDevelopment())
{
    app.UseExceptionHandler("/Error");
    app.UseHsts();
}
else
{
    app.UseDeveloperExceptionPage();
}

app.UseHttpsRedirection();
app.UseStaticFiles();
app.UseRouting();
app.UseAuthentication();
app.UseAuthorization();

// Requirement 5: Check user status before each request (except login/register)
app.Use(async (context, next) =>
{
    var path = context.Request.Path.Value?.ToLower();
    var logger = context.RequestServices.GetRequiredService<ILogger<Program>>();

    // Skip check for login, register, logout, and static files
    if (path != null && (
        path.Contains("/account/login") ||
        path.Contains("/account/register") ||
        path.Contains("/account/logout") ||
        path.Contains(".css") ||
        path.Contains(".js") ||
        path.Contains(".ico") ||
        path.Contains("/lib/") ||
        path.Contains("/error")))
    {
        await next();
        return;
    }

    // Check if user is authenticated and validate status
    if (context.User.Identity?.IsAuthenticated == true)
    {
        var userIdClaim = context.User.FindFirst(ClaimTypes.NameIdentifier);
        if (userIdClaim != null && int.TryParse(userIdClaim.Value, out int userId))
        {
            using var scope = app.Services.CreateScope();
            var dbContext = scope.ServiceProvider.GetRequiredService<ApplicationDbContext>();

            try
            {
                var user = await dbContext.Users.FindAsync(userId);

                // Requirement 5: If user is blocked or deleted, redirect to login
                if (user == null || user.Status != UserStatus.Active)
                {
                    logger.LogWarning("User {UserId} is blocked or deleted, signing out", userId);
                    await context.SignOutAsync(CookieAuthenticationDefaults.AuthenticationScheme);
                    context.Response.Redirect("/Account/Login?message=Your account has been blocked or deleted");
                    return;
                }
            }
            catch (Exception ex)
            {
                logger.LogError(ex, "Error checking user status for user {UserId}", userId);
                // Continue without blocking in case of database issues
            }
        }
    }

    await next();
});

// Add security headers
app.Use(async (context, next) =>
{
    context.Response.Headers.Add("X-Frame-Options", "DENY");
    context.Response.Headers.Add("X-Content-Type-Options", "nosniff");
    context.Response.Headers.Add("Referrer-Policy", "strict-origin-when-cross-origin");
    await next();
});

app.MapRazorPages();

// Log application startup
var logger = app.Services.GetRequiredService<ILogger<Program>>();
logger.LogInformation("User Management System started successfully");
logger.LogInformation("Admin credentials: username='admin', password='123'");

app.Run();

static string HashPassword(string password)
{
    using var sha256 = SHA256.Create();
    var bytes = sha256.ComputeHash(Encoding.UTF8.GetBytes(password));
    return Convert.ToBase64String(bytes);
}