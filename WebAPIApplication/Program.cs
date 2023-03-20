using Serilog;
using WebAPIApplication.Configurations;
using WebAPIApplication.Security;

namespace WebAPIApplication
{
    public class Program
    {
        public static void Main(string[] args)
        {
            try
            {
                var builder = WebApplication.CreateBuilder(args);
                builder.Host.UseSerilog();
                // Add services to the container.
                IConfigurationRoot configuration = new ConfigurationBuilder().AddJsonFile($"appsettings.{Environment.GetEnvironmentVariable("ASPNETCORE_ENVIRONMENT")}.json", optional: false).Build();
                builder.Logging.AddApplicationLogging(configuration);

                builder.Services.AddAppSettingsModule(configuration);
                builder.Services.AddSecurityModule();

                builder.Services.AddControllers();
                builder.Services.AddEndpointsApiExplorer();
                builder.Services.AddSwaggerGen();

                var app = builder.Build();

                // Configure the HTTP request pipeline.
                if (app.Environment.IsDevelopment())
                {
                    app.UseSwagger();
                    app.UseSwaggerUI();
                }
                app.UseApplicationLogging();
                app.UseApplicationSecurity();

                app.MapControllers();

                app.Run();
            }
            catch (Exception ex)
            {
                throw;
            }
        }
    }
}