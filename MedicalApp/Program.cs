
using E_Commerce.Service;
using MedicalApp.Data;
using MedicalApp.Identity;
using MedicalApp.Model;
using MedicalApp.Service;
using Microsoft.AspNetCore.Identity;
using Microsoft.Data.SqlClient;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Caching.Memory;
using Microsoft.Extensions.Configuration;

namespace MedicalApp
{
    public class Program
    {
        public static void Main(string[] args)
        {
            var builder = WebApplication.CreateBuilder(args);

            // Add services to the container.
            builder.Services.AddControllers();
            builder.Services.Configure<MailSettings>(builder.Configuration.GetSection("MailSettings"));
            builder.Services.AddEndpointsApiExplorer();
            builder.Services.AddSwaggerGen();
            builder.Services.AddDbContext<AppDBContext>(options =>
            options.UseSqlServer(
        builder.Configuration.GetConnectionString("DefaultConnection")));

            builder.Services.AddIdentity<UserApp, IdentityRole>(options =>
            {
				options.Tokens.EmailConfirmationTokenProvider = TokenOptions.DefaultEmailProvider;
			})
                .AddEntityFrameworkStores<AppDBContext>()
                .AddDefaultTokenProviders();

            builder.Services.AddMemoryCache();
            builder.Services.AddScoped<ITokenService, TokenService>();
            builder.Services.AddScoped<IMailService, MailService>();

            var app = builder.Build();

            
            //if (app.Environment.IsDevelopment())
            {
                app.UseSwagger();
                app.UseSwaggerUI();
            }

            app.UseHttpsRedirection();

            app.UseAuthorization();


            app.MapControllers();

            app.Run();
        }
    }
}
