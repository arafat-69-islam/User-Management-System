using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Authentication;
using Pomelo.EntityFrameworkCore.MySql.Infrastructure;
using Demo.Data;
using Demo.Models;
using Demo.Middleware;
using Microsoft.EntityFrameworkCore;
using System.Security.Cryptography;
using System.Text;
using System.Security.Claims;
using System.Diagnostics;

class Program
{
    static async Task Main(string[] args)
    {
        // Start ngrok for external access
        StartNgrok();

        // Small delay to let ngrok initialize
        await Task.Delay(3000);

        // Create and configure the web application
        var builder = WebApplication.CreateBuilder(args);

        // Configure Kestrel for ngrok with HTTPS support
        builder.WebHost.ConfigureKestrel(options =>
        {
            // Listen on your specific IP and port for HTTPS
            options.Listen(System.Net.IPAddress.Parse("192.168.13.75"), 7272, listenOptions =>
            {
                listenOptions.UseHttps(); // Enable HTTPS
            });

            // Also listen on localhost for local development
            options.Listen(System.Net.IPAddress.Loopback, 7272, listenOptions =>
            {
                listenOptions.UseHttps(); // Enable HTTPS
            });

            // Listen on all IPs for ngrok compatibility
            options.ListenAnyIP(7272, listenOptions =>
            {
                listenOptions.UseHttps(); // Enable HTTPS
            });

            // Configure server limits for production
            options.Limits.MaxConcurrentConnections = 1000;
            options.Limits.MaxRequestBodySize = 10 * 1024 * 1024; // 10 MB
            options.Limits.KeepAliveTimeout = TimeSpan.FromMinutes(5);
            options.Limits.RequestHeadersTimeout = TimeSpan.FromMinutes(2);
        });

        // Configure URLs for ngrok compatibility
        builder.WebHost.UseUrls("https://192.168.31.8:7272", "https://localhost:7272", "https://0.0.0.0:7272");

        // Add services to the container
        builder.Services.AddRazorPages(options =>
        {
            options.Conventions.AuthorizePage("/Admin/Users");
            options.Conventions.AllowAnonymousToPage("/Account/Login");
            options.Conventions.AllowAnonymousToPage("/Account/Register");
            options.Conventions.AllowAnonymousToPage("/Account/Logout");
            options.Conventions.AllowAnonymousToPage("/Error");
        });

        // Configure authentication with ngrok-compatible settings
        builder.Services.AddAuthentication(CookieAuthenticationDefaults.AuthenticationScheme)
            .AddCookie(options =>
            {
                options.LoginPath = "/Account/Login";
                options.AccessDeniedPath = "/Account/Login";
                options.LogoutPath = "/Account/Logout";
                options.ExpireTimeSpan = TimeSpan.FromHours(24);
                options.SlidingExpiration = true;

                // Cookie settings for ngrok and HTTPS
                options.Cookie.Name = "UserManagementAuth";
                options.Cookie.HttpOnly = true;
                options.Cookie.SecurePolicy = CookieSecurePolicy.Always; // Always secure for HTTPS
                options.Cookie.SameSite = SameSiteMode.None; // Required for ngrok tunneling
                options.Cookie.IsEssential = true;
            });

        // Configure Entity Framework with optimized connection for ngrok
        builder.Services.AddDbContext<ApplicationDbContext>(options =>
            options.UseMySql(
                builder.Configuration.GetConnectionString("DefaultConnection"),
                new MySqlServerVersion(new Version(8, 0, 33)),
                mySqlOptions => mySqlOptions
                    .EnableRetryOnFailure(
                        maxRetryCount: 10,
                        maxRetryDelay: TimeSpan.FromSeconds(30),
                        errorNumbersToAdd: null)
                    .EnableSensitiveDataLogging(false)
                    .EnableServiceProviderCaching()
            ));

        // Add CORS for ngrok and external access
        builder.Services.AddCors(options =>
        {
            options.AddDefaultPolicy(policy =>
            {
                policy.AllowAnyOrigin()
                      .AllowAnyHeader()
                      .AllowAnyMethod();
            });
        });

        // Add memory cache and response compression
        builder.Services.AddMemoryCache();
        builder.Services.AddResponseCompression(options =>
        {
            options.EnableForHttps = true;
        });

        // Configure logging for ngrok environment
        builder.Services.AddLogging(logging =>
        {
            logging.ClearProviders();
            logging.AddConsole();
            logging.AddDebug();
            logging.SetMinimumLevel(LogLevel.Information);
        });

        // Build the application
        var app = builder.Build();

        // Database initialization and seeding
        using (var scope = app.Services.CreateScope())
        {
            var context = scope.ServiceProvider.GetRequiredService<ApplicationDbContext>();
            var initialLogger = scope.ServiceProvider.GetRequiredService<ILogger<Program>>();

            try
            {
                initialLogger.LogInformation("Initializing database...");
                await context.Database.EnsureCreatedAsync();
                initialLogger.LogInformation("Database ensured created");

                // Seed admin user
                if (!await context.Users.AnyAsync(u => u.Email == "admin@gmail.com"))
                {
                    var adminUser = new User
                    {
                        Name = "Administrator",
                        Email = "admin@gmail.com",
                        PasswordHash = HashPassword("123"),
                        DateOfBirth = new DateTime(1990, 1, 1),
                        MobileNumber = "1234567890",
                        Gender = "Other",
                        Status = UserStatus.Active,
                        LastLogin = DateTime.UtcNow
                    };

                    context.Users.Add(adminUser);
                    await context.SaveChangesAsync();
                    initialLogger.LogInformation("Admin user created successfully");
                }
                else
                {
                    initialLogger.LogInformation("Admin user already exists");
                }
            }
            catch (Exception ex)
            {
                initialLogger.LogError(ex, "Error during database initialization");
                initialLogger.LogWarning("Database initialization failed, but continuing...");
            }
        }

        // Configure the HTTP request pipeline for ngrok
        if (app.Environment.IsDevelopment())
        {
            app.UseDeveloperExceptionPage();
        }
        else
        {
            app.UseExceptionHandler("/Error");
            app.UseHsts();
        }

        // Enable CORS for ngrok
        app.UseCors();

        // Force HTTPS
        app.UseHttpsRedirection();

        // Enable response compression
        app.UseResponseCompression();

        // Add security headers for ngrok tunneling
        app.Use(async (context, next) =>
        {
            context.Response.Headers.Add("X-Frame-Options", "SAMEORIGIN");
            context.Response.Headers.Add("X-Content-Type-Options", "nosniff");
            context.Response.Headers.Add("X-XSS-Protection", "1; mode=block");
            context.Response.Headers.Add("Referrer-Policy", "strict-origin-when-cross-origin");

            // Allow ngrok tunneling
            context.Response.Headers.Remove("X-Frame-Options");
            context.Response.Headers.Add("X-Frame-Options", "ALLOWALL");

            await next();
        });

        // Enable static files with caching
        app.UseStaticFiles(new StaticFileOptions
        {
            OnPrepareResponse = ctx =>
            {
                ctx.Context.Response.Headers.Append("Cache-Control", "public,max-age=86400");
            }
        });

        // Configure routing
        app.UseRouting();

        // Authentication and authorization
        app.UseAuthentication();
        app.UseAuthorization();

        // Test endpoints for ngrok verification
        app.MapGet("/", () => Results.Redirect("/Account/Login"));

        app.MapGet("/health", () => new
        {
            Status = "Healthy",
            Timestamp = DateTime.UtcNow,
            Server = Environment.MachineName,
            Version = "1.0.0",
            Environment = app.Environment.EnvironmentName
        });

        app.MapGet("/test-ngrok", async (HttpContext context) =>
        {
            return new
            {
                Message = "Ngrok tunnel is working!",
                RequestUrl = $"{context.Request.Scheme}://{context.Request.Host}{context.Request.Path}",
                Headers = context.Request.Headers.ToDictionary(h => h.Key, h => h.Value.ToString()),
                RemoteIP = context.Connection.RemoteIpAddress?.ToString(),
                LocalIP = context.Connection.LocalIpAddress?.ToString(),
                Timestamp = DateTime.UtcNow
            };
        });

        // Custom middleware for user status checking
        app.UseMiddleware<UserStatusCheckMiddleware>();

        // Additional security middleware
        app.Use(async (context, next) =>
        {
            var path = context.Request.Path.Value?.ToLower();
            var statusLogger = context.RequestServices.GetRequiredService<ILogger<Program>>();

            // Skip check for specific paths
            if (path != null && (
                path.Contains("/account/login") ||
                path.Contains("/account/register") ||
                path.Contains("/account/logout") ||
                path.Contains("/health") ||
                path.Contains("/test") ||
                path == "/" ||
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

                        if (user == null || user.Status != UserStatus.Active)
                        {
                            statusLogger.LogWarning("User {UserId} is blocked or deleted, signing out", userId);
                            await context.SignOutAsync(CookieAuthenticationDefaults.AuthenticationScheme);
                            context.Response.Redirect("/Account/Login?message=Your account has been blocked or deleted");
                            return;
                        }
                    }
                    catch (Exception ex)
                    {
                        statusLogger.LogError(ex, "Error checking user status for user {UserId}", userId);
                    }
                }
            }

            await next();
        });

        // Map Razor Pages
        app.MapRazorPages();

        // Log startup information
        var logger = app.Services.GetRequiredService<ILogger<Program>>();
        logger.LogInformation("=== User Management System with Ngrok Started ===");
        logger.LogInformation("Environment: {Environment}", app.Environment.EnvironmentName);
        logger.LogInformation("Local HTTPS URL: https://192.168.31.8:7272");
        logger.LogInformation("Localhost HTTPS URL: https://localhost:7272");
        logger.LogInformation("Ngrok tunnel should be active on port 7272");
        logger.LogInformation("Admin credentials: admin@gmail.com / 123");
        logger.LogInformation("Test endpoints:");
        logger.LogInformation("  - Health check: /health");
        logger.LogInformation("  - Ngrok test: /test-ngrok");
        logger.LogInformation("=== Application Ready for Ngrok Tunneling ===");

        // Run the application
        await app.RunAsync();
    }

    static void StartNgrok()
    {
        try
        {
            var process = new Process();
            process.StartInfo.FileName = "ngrok";
            process.StartInfo.Arguments = "http https://192.168.31.8:7272"; // Updated for HTTPS
            process.StartInfo.UseShellExecute = false;
            process.StartInfo.RedirectStandardOutput = true;
            process.StartInfo.RedirectStandardError = true;
            process.StartInfo.CreateNoWindow = true;

            process.Start();

            Console.WriteLine("🚀 Starting Ngrok tunnel...");
            Console.WriteLine("📡 Ngrok is forwarding your HTTPS application");
            Console.WriteLine("🌐 Tunneling https://192.168.31.8:7272");
            Console.WriteLine("⏳ Please wait for ngrok to establish connection...");
            Console.WriteLine("📊 Check ngrok dashboard at: http://localhost:4040");

            // Don't wait for output as it might block
            Task.Run(() =>
            {
                try
                {
                    string output;
                    while ((output = process.StandardOutput.ReadLine()) != null)
                    {
                        if (output.Contains("started tunnel"))
                        {
                            Console.WriteLine("✅ Ngrok tunnel established successfully!");
                        }
                    }
                }
                catch (Exception ex)
                {
                    Console.WriteLine($"⚠️ Ngrok output monitoring error: {ex.Message}");
                }
            });
        }
        catch (Exception ex)
        {
            Console.WriteLine($"❌ Failed to start Ngrok: {ex.Message}");
            Console.WriteLine("💡 Make sure ngrok is installed and in your PATH");
            Console.WriteLine("📥 Install ngrok from: https://ngrok.com/download");
        }
    }

    static string HashPassword(string password)
    {
        using var sha256 = SHA256.Create();
        var bytes = sha256.ComputeHash(Encoding.UTF8.GetBytes(password));
        return Convert.ToBase64String(bytes);
    }
}