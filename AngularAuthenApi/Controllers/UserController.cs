using AngularAuthenApi.Context;
using AngularAuthenApi.Helper;
using AngularAuthenApi.Models;
using AngularAuthenApi.Models.Dto;
using AngularAuthenApi.UtilityService;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.WebUtilities;
using Microsoft.EntityFrameworkCore;
using Microsoft.IdentityModel.Tokens;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Security.Cryptography;
using System.Text;
using System.Text.RegularExpressions;



namespace AngularAuthenApi.Controllers
{
    [Route("api/[controller]")]
    [ApiController]
    public class UserController : ControllerBase
    {

    
        private readonly AppDbContext _authDbcontext;
        private readonly IEmailService _emailService;
        private readonly IConfiguration _config;



        public UserController(AppDbContext appDbContext, IConfiguration config, IEmailService emailService , ILogger<UserController> logger)
        {
            _authDbcontext = appDbContext;
            _config = config;
            _emailService = emailService;

        }



        //Login Authenticate*
        [HttpPost("authenticate")]
        public async Task<IActionResult> Authenticate([FromBody] User userObj)
        {
            if (userObj == null)
                return BadRequest();

            //return 400 error NotFound

            var user = await _authDbcontext.Users.FirstOrDefaultAsync
                (x => x.UserName == userObj.UserName);


            if (user == null)
                return NotFound(new { Message = "User Not Found!" });

            // Use this if statment after hashed the password(second step).                        
            if (!PasswordHasher.VerifyPassword(userObj.password, user.password))
            {
                return BadRequest(new { Message = "Password is Incorrect!" });
            }

            user.Token = CreateJwt(user);  //  TOKEN created when user Success to login

            var newAccessToken = user.Token;
            var newRefreshToken = CreateRefreshToken();
            user.RefreshToken = newRefreshToken;
            user.RefreshTokenExpireTime = DateTime.Now.AddDays(5); // Refresh Token Time Limit
            await _authDbcontext.SaveChangesAsync();

            return Ok(new TokenApiDto()
            {
                AccessToken = newAccessToken,
                RefreshToken = newRefreshToken
            }
            //Token = user.Token,
            // Message = "Login Success!"


            );

        }





        //Signup Register*
        [HttpPost("register")]

        public async Task<IActionResult> Register([FromBody] User userObj)

        {
            StringBuilder sb = new StringBuilder();

            if (userObj == null)
                return BadRequest();  //return 400 error NotFound

            //Check username 
            if (await CheackUserNameExistAsync(userObj.UserName))
                return BadRequest(new { Message = "Sorry UserName Already Exist!" });

            //check Email 

            if (await CheackEmailExistAsync(userObj.Email))
                return BadRequest(new { Message = "Sorry Email Already Exist!" });



            //check password strength

            var pass = CheckPasswordStrength(userObj.password);
            if (!string.IsNullOrEmpty(pass))
                return BadRequest(new { Message = pass.ToString() });


            userObj.password = PasswordHasher.HashPassword(userObj.password); // Call HashPassword class in Helper Folder,
                                                                              // and Hashing the Password with send to the Database.(first Step)
            userObj.Role = "User";
            userObj.Token = "";

            await _authDbcontext.Users.AddAsync(userObj);
            await _authDbcontext.SaveChangesAsync();

            return Ok(new
            {
                Token = userObj.Token,
                Message = "User Registered!"
            });
        }



        private Task<bool> CheackUserNameExistAsync(string userName)
            => _authDbcontext.Users.AnyAsync(x => x.UserName == userName);

        private Task<bool> CheackEmailExistAsync(string email)
          => _authDbcontext.Users.AnyAsync(x => x.Email == email);



        private string CheckPasswordStrength(string password)
        {
            StringBuilder sb = new StringBuilder();
            //check The passsword should be more than 8 char
            if (password.Length < 8)
                sb.Append("Minimum password length should be 8 " + Environment.NewLine);

            //check The passsword should be Alphanumeric
            if (!(Regex.IsMatch(password, "[a-z]") && Regex.IsMatch(password, "[A-Z]") && Regex.IsMatch(password, "[0-9]")))
                sb.Append("Password should be Alphanumeric " + Environment.NewLine);

            // Password should be contain special chars      
            if (!Regex.IsMatch(password, "[-,~,`,!,@,\t,#,$,%,^,&,*,(,) ,+,=,{,},[,:,\\,/,;,\",',<,>,.,?,=,_]"))
                sb.Append("Password should contain special chars! " + Environment.NewLine);

            return sb.ToString();
        }




       // [Authorize] //protect the Api FROM USER TO ACCSESS TO THE DATABASE
        [HttpGet("allUsers")]
        //this is the Api TO Get all users data from DataBase 
        public async Task<ActionResult<User>> GetAllUsers()
        {
            return Ok(await _authDbcontext.Users.ToListAsync());
        }



        //CREATE JSON WEB TOKEN(JWT) fIRST-STEP, THEN-> STEP TWO CONFIGURATION IN Program.cs -> builder.Services.AddAuthentication(...)
        private string CreateJwt(User user)
        {
            var jwtTokenHandler = new JwtSecurityTokenHandler();
            var key = Encoding.ASCII.GetBytes("veryverysecret......");
            // var fullName = user.FirstName + " " + user.LastName;
            var identity = new ClaimsIdentity(new Claim[]
            {
                 new Claim(ClaimTypes.Role, user.Role),
                 new Claim(ClaimTypes.Name, $"{user.UserName}")

            });

            var credentials = new SigningCredentials(new SymmetricSecurityKey(key), SecurityAlgorithms.HmacSha256);
            var tokenDescriptor = new SecurityTokenDescriptor
            {
                Subject = identity,
                Expires = DateTime.Now.AddSeconds(10), //you maybe need to Add config in program.cs ( ClockSkew )
                SigningCredentials = credentials
            };
            var token = jwtTokenHandler.CreateToken(tokenDescriptor);

            return jwtTokenHandler.WriteToken(token);
        }



        private string CreateRefreshToken()
        {
            var tokenBytes = RandomNumberGenerator.GetBytes(64);
            var refreshToken = Convert.ToBase64String(tokenBytes);
       

            var tokenInUser = _authDbcontext.Users
                .Any(a => a.RefreshToken == refreshToken);

            if (tokenInUser)
            {
                return CreateRefreshToken();
            }
            return refreshToken;
        }




        //Give a new refresh Token
        [HttpPost("refresh")]
        public async Task<IActionResult> Refresh(TokenApiDto tokenApiDto)
        {
            if (tokenApiDto is null)
                return BadRequest("Invalid Client Request");


            string asscesToken = tokenApiDto.AccessToken;
            string refreshToken = tokenApiDto.RefreshToken;

            var principal = GetPrincipleFromExpiredToken(asscesToken);
            var username = principal.Identity.Name;
            var user = await _authDbcontext.Users.FirstOrDefaultAsync(x => x.UserName == username);

            if (user is null || user.RefreshToken != refreshToken || user.RefreshTokenExpireTime <= DateTime.Now)
                return BadRequest("Invaild Request");
            var newAccessToken = CreateJwt(user);
            var newRefreshToken = CreateRefreshToken();
            user.RefreshToken = newRefreshToken;
            await _authDbcontext.SaveChangesAsync();

            return Ok(new TokenApiDto
            {
                AccessToken = newAccessToken,
                RefreshToken = newRefreshToken
            });
        }





        //get The principal Value like payload value from the token
        private ClaimsPrincipal GetPrincipleFromExpiredToken(string token)
        {
            var key = Encoding.ASCII.GetBytes("veryverysecret......");
            var tokenValidationParameters = new TokenValidationParameters
            {
                ValidateAudience = false,
                ValidateIssuer = false,
                ValidateIssuerSigningKey = true,
                IssuerSigningKey = new SymmetricSecurityKey(key),
                ValidateLifetime = false
            };
            var tokenHandler = new JwtSecurityTokenHandler();
            SecurityToken securityToken;


            var principal = tokenHandler.ValidateToken(token, tokenValidationParameters, out securityToken);
            var jwtSecurityToken = securityToken as JwtSecurityToken;
            if (jwtSecurityToken == null || !jwtSecurityToken.Header.Alg.Equals(SecurityAlgorithms.HmacSha256, StringComparison.InvariantCultureIgnoreCase))
                throw new SecurityTokenException("This is Invalid token ");

            return principal;
        }





        //Send Reset Email
        [HttpPost("send-reset-email/{email}")]
        public async Task<IActionResult> SendEmail(string email)
        {
            var user = await _authDbcontext.Users.FirstOrDefaultAsync(a => a.Email == email);

            if (user is null)
            {
                return NotFound(new
                {
                    StatusCode = 404,
                    Message = "Email doesn't exist"
                });

            }

            var tokenBytes = RandomNumberGenerator.GetBytes(64);
            var emailToken = Convert.ToBase64String(tokenBytes);
            user.ResetPasswordToken = emailToken;

            user.ResetPasswordExpiry = DateTime.Now.AddMinutes(15);
            user.RefreshTokenExpireTime = DateTime.Now.AddMinutes(15);


            string from = _config["EmailSetting : From"];
            var emailModel = new EmailModel(email, "Reset Password!!", EmailBody.EmailStringBody(email, emailToken));
            _emailService.SendEmail(emailModel);
            _authDbcontext.Entry(user).State = EntityState.Modified;
            await _authDbcontext.SaveChangesAsync();

            return Ok(new
            {
                StatusCode = 200,
                Message = " Email Sent Successfully!"
            });

        }


        //Reset the Password 
        [HttpPost("reset-password")]
        public async Task<IActionResult> ResetPassword(ResetPasswordDto resetPasswordDto )
        {

            //Check Password Strength before store in database 
            var newPass =  CheckPasswordStrength(resetPasswordDto.NewPassword);
            var confPass = CheckPasswordStrength(resetPasswordDto.ConfirmPassword);
           


            var newToken = resetPasswordDto.EmailToken.Replace(" ", "+");
            var user = await _authDbcontext.Users.AsNoTracking().FirstOrDefaultAsync(a => a.Email == resetPasswordDto.Email);

            if (user is null)
            {
                return NotFound(new
                {
                    StatusCode = 404,
                    Message = "User does not exist."
                });

            }

            var tokenCode = user.ResetPasswordToken; //from DataBase 
            DateTime emailTokenExpiry = user.ResetPasswordExpiry; 
            DateTime now = DateTime.Now; // now 

            if (tokenCode != resetPasswordDto.EmailToken)
            {
                return BadRequest(new
                {
                    StatusCode = 400,
                    Message = "Invalid reset link: the reset link provided is incorrect."
                });
            }


            if (emailTokenExpiry < now) 
            {
                return BadRequest(new
                {
                  StatusCode = 400,
                   Message = "Expired reset link: the reset link has expired. Please request a new reset link.",
                   
               });



            }


            if (!string.IsNullOrEmpty(newPass) && !string.IsNullOrEmpty(confPass))
            {
                return BadRequest(
                    new
                    {
                        Message = "Password is too weak! Please use a stronger password."
                    });
            }


            user.password = PasswordHasher.HashPassword(resetPasswordDto.NewPassword);
            _authDbcontext.Entry(user).State = EntityState.Modified;
            await _authDbcontext.SaveChangesAsync();

            return Ok(new
            {
                StatusCode = 200,
                Message = "Password reset successful!"
            });
        }






    }

}





