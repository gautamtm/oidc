using System;
using System.Collections.Generic;
using System.Linq;
using System.Net;
using System.Net.Http;
using System.Security.Claims;
using System.Threading.Tasks;
using AzureOIDC.Service;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.AzureAD.UI;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Authentication.OpenIdConnect;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.HttpsPolicy;
using Microsoft.AspNetCore.Mvc.Authorization;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Microsoft.Identity.Web;
using Microsoft.IdentityModel.Logging;
using Microsoft.IdentityModel.Tokens;

namespace AzureOIDC
{
    public class Startup
    {
        public Startup(IConfiguration configuration)
        {
            Configuration = configuration;
        }

        public IConfiguration Configuration { get; }

        // This method gets called by the runtime. Use this method to add services to the container.
        public void ConfigureServices(IServiceCollection services)
        {
            IdentityModelEventSource.ShowPII = true;
            services.AddScoped<IUserService, UserService>();
            services.AddScoped<IDatabaseContextFactory>(options =>
            {
                return new DatabaseContextFactory(Configuration.GetConnectionString("OIDCConnectionString"));
            });
            services.AddScoped<IDatabaseContext>(options =>
            {
                return new OIDCDbContext(Configuration.GetConnectionString("OIDCConnectionString"));

            });
            //services.AddAuthentication(defaultScheme: AzureADDefaults.AuthenticationScheme)
            //    .AddAzureAD(options => Configuration.Bind("AzureAd", options))
            //    .AddCookie("Test.App");

            //       services.AddAuthentication(OpenIdConnectDefaults.AuthenticationScheme)
            //.AddMicrosoftIdentityWebApp(Configuration.GetSection("AzureAd"));

            services.AddAuthentication(options =>
            {
                options.DefaultScheme = CookieAuthenticationDefaults.AuthenticationScheme;
                options.DefaultChallengeScheme = OpenIdConnectDefaults.AuthenticationScheme;
                options.DefaultSignInScheme = CookieAuthenticationDefaults.AuthenticationScheme;
            }).AddCookie("Test")
                .AddMicrosoftIdentityWebApp(cfg =>
                {
                    cfg.TenantId = Configuration.GetValue<string>("AzureAd:TenantId");
                    cfg.Instance = Configuration.GetValue<string>("AzureAd:Instance");
                    cfg.ClientId = Configuration.GetValue<string>("AzureAd:ClientID");
                    cfg.ClientSecret = Configuration.GetValue<string>("AzureAd:ClientSecret");
                    cfg.UsePkce = true;
                    cfg.ResponseType = "code";
                    // cfg.CallbackPath = "/oauth/callback";
                    var defaultBackChannel = new HttpClient();
                    // defaultBackChannel.DefaultRequestHeaders.Add("Origin", "https://localhost:44398/");
                    cfg.Backchannel = defaultBackChannel;
                    cfg.CallbackPath = "/signin-oidc";
                    cfg.SignedOutRedirectUri = "/Home";
                    cfg.Events = new OpenIdConnectEvents
                    {
                        OnTokenValidated = async ctx =>
                        {
                            string oid = ctx.Principal.FindFirstValue("http://schemas.microsoft.com/identity/claims/objectidentifier");
                            var service = ctx.HttpContext.RequestServices.GetService(typeof(IUserService)) as IUserService;
                            var appIdentity = ctx.Principal.Identity as ClaimsIdentity;
                            var username = appIdentity.Claims.Where(c => c.Type == "preferred_username").SingleOrDefault().Value;
                            var user = await service.GetUserByEmail(username);
                            if (user != null)
                            {
                                appIdentity.AddClaim(new Claim("userGuid", user.UserGuid.ToString()));
                                appIdentity.AddClaim(new Claim("displayName", user.DisplayName));
                                ctx.Principal.AddIdentity(appIdentity);
                            }
                        }
                    };
                });


            //    services.AddAuthentication(OpenIdConnectDefaults.AuthenticationScheme)
            //.AddMicrosoftIdentityWebApp(Configuration.GetSection("AzureAd"), "OpenIdConnect", "Xylontech", true);

            //services.AddAuthentication(options =>
            //{
            //    options.DefaultScheme = CookieAuthenticationDefaults.AuthenticationScheme;
            //    options.DefaultChallengeScheme = OpenIdConnectDefaults.AuthenticationScheme;
            //    options.DefaultSignInScheme = CookieAuthenticationDefaults.AuthenticationScheme;
            //})
            //.AddCookie()
            //.AddOpenIdConnect(option =>
            //{
            //    option.SignInScheme = CookieAuthenticationDefaults.AuthenticationScheme;

            //    option.ClientId = Configuration.GetValue<string>("AzureAd:ClientID");
            //    option.ClientSecret = Configuration.GetValue<string>("AzureAd:ClientSecret");
            //    option.Authority = Configuration.GetValue<string>("AzureAd:Instance");
            //    option.ResponseType = "code";
            //    option.GetClaimsFromUserInfoEndpoint = true;
                
            //    option.BackchannelHttpHandler = new HttpClientHandler()
            //    {
            //        ServerCertificateCustomValidationCallback = HttpClientHandler.DangerousAcceptAnyServerCertificateValidator,
            //        Proxy = new WebProxy(Configuration["System:Proxy"])
            //    };
            //    //option.SaveTokens = true;
            //    //option.GetClaimsFromUserInfoEndpoint = true;
            //    //option.RequireHttpsMetadata = false;
            //    //option.Scope.Add("openid");
            //    //option.Scope.Add("profile");
            //    //option.Scope.Add("offline_access");
            //    //option.TokenValidationParameters = new TokenValidationParameters()
            //    //{
            //    //    NameClaimType = "name",
            //    //    RoleClaimType = "role"
            //    //};

            //    option.Events = new OpenIdConnectEvents
            //    {
            //        OnTokenValidated = async ctx =>
            //        {
            //            //Get user's immutable object id from claims that came from Azure AD
            //            string oid = ctx.Principal.FindFirstValue("http://schemas.microsoft.com/identity/claims/objectidentifier");

            //            //var db = ctx.HttpContext.RequestServices.GetRequiredService<AuthorizationDbContext>();

            //            //Check is user a super admin
            //            //    bool isSuperAdmin = await db.SuperAdmins.AnyAsync(a => a.ObjectId == oid);
            //            //    if (isSuperAdmin)
            //            //    {
            //            //        //Add claim if they are
            //            //        var claims = new List<Claim>
            //            //{
            //            //    new Claim(ClaimTypes.Role, "superadmin")
            //            //};
            //            //        var appIdentity = new ClaimsIdentity(claims);

            //            //        ctx.Principal.AddIdentity(appIdentity);
            //            //    }
            //        }
            //    };
            //}
            //);
            services.AddHealthChecks();

            //        services
            //.AddAuthentication(sharedOptions =>
            //{
            //    sharedOptions.DefaultScheme = CookieAuthenticationDefaults.AuthenticationScheme;
            //    sharedOptions.DefaultChallengeScheme = OpenIdConnectDefaults.AuthenticationScheme;
            //    sharedOptions.DefaultSignInScheme = CookieAuthenticationDefaults.AuthenticationScheme;
            //})
            //.AddCookie("Test", options =>
            //{
            //    options.SlidingExpiration = true;
            //    // There is no redirection to a login page for APIs and SignalR Hubs, I just made a call to /Api/Login/SignIn with credential
            //    options.AccessDeniedPath = new PathString("/Api/Login/AccessDenied"); // Action who just returns an Unauthorized
            //})
            //.AddMicrosoftIdentityWebApp(Configuration.GetSection("AzureAd"));

            //services.AddAuthentication(defaultScheme: CookieAuthenticationDefaults.AuthenticationScheme)
            //      .AddCookie(options =>
            //     {
            //         options.AccessDeniedPath = "/Home/AccessDenied";
            //         options.ExpireTimeSpan = TimeSpan.FromHours(6);
            //         options.Cookie.Name = "Xylontech.App";
            //         options.Cookie.HttpOnly = true;
            //         options.SlidingExpiration = true;
            //         options.CookieManager = new ChunkingCookieManager();
            //     })
            //    .AddOpenIdConnect(cfg =>
            //  {
            //      //cfg.TenantId = Configuration.GetValue<string>("AzureAd:TenantId");
            //      cfg.Authority = Configuration.GetValue<string>("AzureAd:Instance");
            //      cfg.ClientId = Configuration.GetValue<string>("AzureAd:ClientID");
            //      cfg.ClientSecret = Configuration.GetValue<string>("AzureAd:ClientSecret");
            //      cfg.UsePkce = true;
            //      cfg.ResponseType = "code";
            //      // cfg.CallbackPath = "/oauth/callback";
            //      var defaultBackChannel = new HttpClient();
            //      // defaultBackChannel.DefaultRequestHeaders.Add("Origin", "https://localhost:44398/");
            //      cfg.Backchannel = defaultBackChannel;
            //      cfg.CallbackPath = "/signin-oidc";
            //  });

            //services.AddAuthentication(sharedOptions =>
            //{
            //    sharedOptions.DefaultScheme = CookieAuthenticationDefaults.AuthenticationScheme;
            //    sharedOptions.DefaultChallengeScheme = OpenIdConnectDefaults.AuthenticationScheme;
            //})
            //.AddOpenIdConnect(OpenIdConnectDefaults.AuthenticationScheme, "Test", option =>
            //{
            //    option.SignInScheme = CookieAuthenticationDefaults.AuthenticationScheme;
            //    option.UsePkce = true;

            //    option.Authority = "https://login.microsoftonline.com/common/v2.0";
            //    option.RequireHttpsMetadata = false; // dev only

            //    option.AuthenticationMethod = OpenIdConnectRedirectBehavior.RedirectGet;
            //    option.ClientId = Configuration.GetValue<string>("AzureAd:ClientID");
            //    option.ClientSecret = Configuration.GetValue<string>("AzureAd:ClientSecret");
            //    option.ResponseType = "Code";
            //    //o.ResponseMode = OpenIdConnectResponseMode.Query;
            //    option.CallbackPath = "/auth/microsoft/callback";

            //    option.TokenValidationParameters.ValidateAudience = true;
            //    option.TokenValidationParameters.ValidateIssuer = true;
            //    option.TokenValidationParameters.ValidAudience = Configuration.GetValue<string>("AzureAd:ClientID");
            //    option.TokenValidationParameters.ValidIssuers = new List<string>
            //    {
            //        "https://login.microsoftonline.com/e0a1f85c-1c25-4be2-a171-3129e6e534e8/v2.0", // for personal account login
            //        // add other tenant ID's here
            //    };
            //})
            //.AddCookie(auth =>
            //{
            //    auth.Events.OnRedirectToAccessDenied = context =>
            //    {
            //        // Return an Access Denied code rather than the Cookie default of /Account/AccessDenied page
            //        context.HttpContext.Response.StatusCode = 401;
            //        return Task.CompletedTask;
            //    };
            //});



            services.AddControllersWithViews(options =>
            {
                var policy = new AuthorizationPolicyBuilder()
                    .RequireAuthenticatedUser()
                    .Build();
                options.Filters.Add(new AuthorizeFilter(policy));
            });
            services.AddRazorPages();
            //        //.AddMicrosoftIdentityUI();
        }

        // This method gets called by the runtime. Use this method to configure the HTTP request pipeline.
        public void Configure(IApplicationBuilder app, IWebHostEnvironment env)
        {
            if (env.IsDevelopment())
            {
                app.UseDeveloperExceptionPage();
            }
            else
            {
                app.UseExceptionHandler("/Home/Error");
                // The default HSTS value is 30 days. You may want to change this for production scenarios, see https://aka.ms/aspnetcore-hsts.
                app.UseHsts();
            }
            app.UseHttpsRedirection();
            app.UseStaticFiles();

            app.UseRouting();

            app.UseAuthentication();
            app.UseAuthorization();

            app.UseEndpoints(endpoints =>
            {
                endpoints.MapControllerRoute(
                    name: "default",
                    pattern: "{controller=Home}/{action=Index}/{id?}");
            });
        }
    }
}
