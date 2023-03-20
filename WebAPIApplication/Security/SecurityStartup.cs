using Microsoft.AspNetCore.Authentication.Google;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.Tokens;
using System.IdentityModel.Tokens.Jwt;
using System.Text;

namespace WebAPIApplication.Security
{
    public static class SecurityStartup
    {
        public const string UserNameClaimType = JwtRegisteredClaimNames.Sub;

        public static IServiceCollection AddSecurityModule(this IServiceCollection services)
        {
            //TODO Retrieve the signing key properly (DRY with TokenProvider)
            var opt = services.BuildServiceProvider().GetRequiredService<IOptions<SecuritySettings>>();
            var securitySettings = opt.Value;
            var secret = securitySettings.Jwt.SecretKey;

            byte[] keyBytes = Encoding.UTF8.GetBytes(securitySettings.Jwt.SecretKey);

           // JwtSecurityTokenHandler.DefaultInboundClaimTypeMap.Clear(); // => remove default claims


            services
                .AddAuthentication(JwtBearerDefaults.AuthenticationScheme)
                .AddJwtBearer(cfg =>
                {
                    cfg.TokenValidationParameters = new TokenValidationParameters
                    {

                        ValidateIssuer = false, //Validate the server that generates the token.
                        ValidateAudience = true,//Validate the recipient of the token is authorized to receive
                        ValidateLifetime = true,//Check if the token is not expired and the signing key of the issuer is valid
                        ValidateIssuerSigningKey = true,//Validate signature of the token 
                        IssuerSigningKey = new SymmetricSecurityKey(keyBytes),
                        ValidAudiences = securitySettings.Jwt.ValidAudiences.Split(';')
                    };
                    cfg.SaveToken = true;
                })
                .AddGoogle(GoogleDefaults.AuthenticationScheme, options =>
                {
                    options.ClientId = securitySettings.GoogleAuth.ClientId;
                    options.ClientSecret = securitySettings.GoogleAuth.ClientSecret;
                    options.Scope.Add("email");
                    options.Scope.Add("profile");
                });

            services.AddScoped<ITokenProvider, TokenProvider>();
            return services;
        }
        public static IApplicationBuilder UseApplicationSecurity(this IApplicationBuilder app)
        {
            IServiceProvider serviceProvider = app.ApplicationServices;
            var securitySettingsOptions = serviceProvider.GetRequiredService<IOptions<SecuritySettings>>();
            var securitySettings = securitySettingsOptions.Value;

            if (securitySettings.EnforceHttps)
            {
                app.UseHsts();
                app.UseHttpsRedirection();
            }
            app.UseAuthentication();
            app.UseAuthorization();

            return app;
        }

    }
}
