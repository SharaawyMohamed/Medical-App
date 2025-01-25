using Azure;
using ECommerce.Repository.Helper;
using MedicalApp.DTO;
using MedicalApp.Identity;
using MedicalApp.Service;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Identity.UI.Services;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Caching.Memory;
using System.Net;
using System.Runtime.CompilerServices;

namespace MedicalApp.Controllers
{
	[Route("api/[controller]")]
	[ApiController]
	public class AccountController : ControllerBase
	{

		private readonly UserManager<UserApp> _userManager;
		private readonly SignInManager<UserApp> _signInManager;
		private readonly IConfiguration _configuration;
		private readonly ITokenService _tokenService;
		private readonly IMailService _emailSender;
		private readonly IMemoryCache memo;

		public AccountController(UserManager<UserApp> userManager, SignInManager<UserApp> signInManager, IConfiguration configuration, ITokenService tokenService, IMemoryCache memo, IMailService emailSender)
		{
			_userManager = userManager;
			_signInManager = signInManager;
			_configuration = configuration;
			_tokenService = tokenService;
			this.memo = memo;
			_emailSender = emailSender;
		}

		[HttpPost("register")]
		public async Task<ActionResult> Register([FromForm] RegisterDTO registerDTO)
		{
			var emailExists = await CheckEmailExists(registerDTO.Email);

			if (emailExists is OkObjectResult resul && (bool)resul.Value)
			{
				return BadRequest("The Email is already in use");
			}
			if (registerDTO.Password != registerDTO.confirmPassword)
			{
				return BadRequest("Password and Confirm Password donot the same ");
			}

			var user = new UserApp
			{
				UserName = registerDTO.Email.Split("@")[0],
				Email = registerDTO.Email,
				FName = registerDTO.FName,
				Phone = registerDTO.Phone,
				LName = registerDTO.LName,
				Age = registerDTO.Age,
				NationaID = registerDTO.NationaID,
				gender = (UserApp.Gender)registerDTO.gender,

			};
			user.File = Files.UploadFile(registerDTO.File, "User");
			var result = await _userManager.CreateAsync(user, registerDTO.Password);

			if (!result.Succeeded)
			{
				return BadRequest(result.Errors);
			}
			var res = new TokenDTO()
			{
				Email = registerDTO.Email,

				Token = await _tokenService.CreateToken(user)
			};
			return Ok(res);
		}

		[HttpPost("login")]
		public async Task<ActionResult> Login([FromBody] LogInDTO loginDto)
		{
			var user = await _userManager.FindByEmailAsync(loginDto.Email);
			if (user == null) return Unauthorized("Invalid email or password");

			var result = await _signInManager.CheckPasswordSignInAsync(user, loginDto.Password, false);
			if (!result.Succeeded) return Unauthorized("Invalid email or password");

			var res = new TokenDTO()
			{
				Email = loginDto.Email,

				Token = await _tokenService.CreateToken(user)
			};
			return Ok(res);
		}


		[HttpGet("CheckEmailExists")]
		public async Task<ActionResult> CheckEmailExists(string email)
		{
			var res = await _userManager.FindByEmailAsync(email);
			return Ok(res is not null);
		}


		[HttpGet("ForgetPassword")]
		public async Task<ActionResult> ForgetPassword(string email)
		{
			var user = await _userManager.FindByEmailAsync(email);
			if (user == null) return NotFound("Your email is not found.");

			var otp = new Random().Next(100000, 999999).ToString();
			memo.Set("UserOTP", otp, TimeSpan.FromMinutes(10));
			await _emailSender.SendEmailAsync(email, otp, "Your Otp:");
			return Ok(new ForgotPasswordDTO
			{
				Token = await _userManager.GeneratePasswordResetTokenAsync(user),
				Message = "Check your mail!"
			});

		}

		[HttpGet("VerifyOTP")]
		public async Task<ActionResult> VerifyOTP(string otp, string email)
		{
			var user = await _userManager.FindByEmailAsync(email);
			if (user == null) return NotFound($"Email '{email}' is not found.");

			var cachedOtp = memo.Get("UserOTP")!.ToString();
			if (otp != cachedOtp)
			{
				return BadRequest("InValid OTP");
			}
			return Ok("OTP Verified successfully.");
		}

		[HttpPut("ResetPassword")]
		public async Task<ActionResult> ResetPassword(ResetPasswordDto resetPassword)
		{
			if (resetPassword.NewPassword != resetPassword.ConfirmNewPassword)
			{
				return BadRequest("Password and Password confirmation are not matched");
			}

			var user = await _userManager.FindByEmailAsync(resetPassword.Email);
			if (user == null)
			{
				return NotFound("Email is not found!");
			}

			var result = await _userManager.ResetPasswordAsync(user, resetPassword.Token, resetPassword.NewPassword);
			if (!result.Succeeded)
			{
				return BadRequest(result.Errors.ToList());
			}

			return Ok("Password updated successfully.");
		}

	}
}
