using System;
using System.Collections.Generic;
using System.IdentityModel.Tokens.Jwt;
using System.Linq;
using System.Security.Claims;
using System.Text;
using System.Threading.Tasks;
using blog_api.Configuration;
using blog_api.Database;
using blog_api.Entities;
using blog_api.Models;
using blog_api.Models.Users;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.Tokens;

namespace blog_api.Controllers
{   
    [Route("api/[controller]")]
    [ApiController]
    public class UsersController: ControllerBase
    {
        private readonly UserManager<IdentityUser> _userManager;
        private readonly JwtConfig _jwtConfig;
        private readonly TokenValidationParameters _tokenValidationParams;
        private readonly DataContext _context;

        public UsersController(UserManager<IdentityUser> userManager,
         IOptionsMonitor<JwtConfig> optionsMonitor,
         TokenValidationParameters tokenValidationParams,
         DataContext context)
        {
            _userManager = userManager;
            _jwtConfig = optionsMonitor.CurrentValue;
            _tokenValidationParams = tokenValidationParams;
            _context = context;
        }  

        [HttpPost]
        [Route("register")]
        public async Task<IActionResult> Register([FromBody] UserRegistration user) 
        {
            if (ModelState.IsValid)
            {
                var existingUser = await _userManager.FindByEmailAsync(user.Email);

                if (existingUser != null)
                {
                    return BadRequest(new RegistrationResponse(){
                        Errors =  new List<string>(){
                            "Email already in use"
                        },
                        Success = false
                    });
                }

                var newUser = new IdentityUser() {Email = user.Email, UserName = user.Username};

                var isCreated = await _userManager.CreateAsync(newUser, user.Password);

                if (isCreated.Succeeded)
                {
                    var jwtToken = await GenerateJwtToken(newUser);

                    return Ok(jwtToken);

                } else {
                    return BadRequest(new RegistrationResponse(){
                        Errors = isCreated.Errors.Select(x => x.Description).ToList(),
                        Success = false
                    });                    
                }

            }   
            return BadRequest(new RegistrationResponse(){
                Errors =  new List<string>(){
                    "Invalid payload"
                },
                Success = false
            });
        }

        [HttpPost]
        [Route("login")]
        public async Task<IActionResult> Login([FromBody] Login user) 
        {
            if(ModelState.IsValid)
            {
                var existingUser =  await _userManager.FindByEmailAsync(user.Email);

                if (existingUser == null)
                {
                    return BadRequest(new RegistrationResponse(){
                        Errors =  new List<string>(){
                        "Invalid Login Request"
                        },
                        Success = false
                    });
                }

                var isCorrect = await _userManager.CheckPasswordAsync(existingUser, user.Password);

                if (!isCorrect)
                {
                    return BadRequest(new RegistrationResponse(){
                        Errors =  new List<string>(){
                        "Invalid Login Request"
                        },
                        Success = false
                    });                    
                }

                var jwtToken = await GenerateJwtToken(existingUser);

                return Ok(jwtToken);
            }

            return BadRequest(new RegistrationResponse(){
                Errors =  new List<string>(){
                "Invalid payload"
                },
                Success = false
            });
        }

        [HttpPost]
        [Route("refresh")]
        public async Task<IActionResult> Refresh([FromBody] TokenRequest tokenRequest)
        {
            if(ModelState.IsValid)
            {
                var result = await VerifyAndGenerateToken(tokenRequest);
                
                if (result == null)
                {
                    return BadRequest(new RegistrationResponse {
                        Success = false,
                        Errors = new List<String>(){
                            "Bad Request"
                        }
                    });
                }

                return Ok(result);
            }

            return BadRequest(new RegistrationResponse(){
                Errors = new List<string>() {
                    "Invalid payload"
                },
                Success = false
            });
        }
        private async Task<AuthResult> GenerateJwtToken(IdentityUser user)
        {
            var jwtTokenHandler = new JwtSecurityTokenHandler(); //helps to generate tokens

            var key = Encoding.ASCII.GetBytes(_jwtConfig.Secret);

            //claims which are user information
            var tokenDescriptor = new SecurityTokenDescriptor
            {
                Subject = new ClaimsIdentity(new []
                {
                    new Claim("Id", user.Id),
                    new Claim(JwtRegisteredClaimNames.Email, user.Email),
                    new Claim(JwtRegisteredClaimNames.Sub, user.Email),
                    new Claim(JwtRegisteredClaimNames.Jti, Guid.NewGuid().ToString()), //refresh tokens
                }),
                Expires = DateTime.UtcNow.AddSeconds(10),
                SigningCredentials = new SigningCredentials(new SymmetricSecurityKey(key), SecurityAlgorithms.HmacSha256Signature) 
            };

            var token = jwtTokenHandler.CreateToken(tokenDescriptor);
            var jwtToken = jwtTokenHandler.WriteToken(token);

            var refreshToken = new RefreshToken()
            {
                JwtId = token.Id,
                IsUsed = false,
                IsRevoked = false,
                UserId = user.Id,
                AddedDate = DateTime.UtcNow,
                ExpiryDate = DateTime.UtcNow.AddMonths(6),
                Token = RandomString(35) + Guid.NewGuid()
            };

            await _context.RefreshTokens.AddAsync(refreshToken);
            await _context.SaveChangesAsync();

            return new AuthResult() {
                Token = jwtToken,
                Success = true,
                RefreshToken = refreshToken.Token
            };
        }

        private async Task<AuthResult> VerifyAndGenerateToken(TokenRequest tokenRequest)
        {
            var jwtTokenHandler = new JwtSecurityTokenHandler();

            try
            {   
                var key = Encoding.ASCII.GetBytes(_jwtConfig.Secret);
                //validate the jwt token
                var tokenInVerification = jwtTokenHandler.ValidateToken(tokenRequest.Token, new TokenValidationParameters {
                    ValidateIssuerSigningKey = true,
                    IssuerSigningKey = new SymmetricSecurityKey(key),
                    ValidateIssuer = false,
                    ValidateAudience = false,
                    RequireExpirationTime = false,
                    ValidateLifetime = false,
                    //token expires at exact time
                    ClockSkew = new TimeSpan(0),
                }, out var validatedToken);

                //check if it encrypted using our model
                if(validatedToken is JwtSecurityToken jwtSecurityToken)
                {
                    var result = jwtSecurityToken.Header.Alg.Equals(SecurityAlgorithms.HmacSha256, StringComparison.InvariantCultureIgnoreCase);

                    if (result == false)
                    {
                        return null;
                    }
                }

                //expiry validation
                var utcExpiryDate = long.Parse(tokenInVerification.Claims.FirstOrDefault(x => x.Type == JwtRegisteredClaimNames.Exp).Value);

                var expiryDate = UnixTimeStampToDateTime(utcExpiryDate);

                if (expiryDate > DateTime.UtcNow)
                {
                    return new AuthResult() {
                        Success = false,
                        Errors = new List<String>(){
                            "Token has not yet expired."
                        }
                    };
                }

                //validation of existence of token in db
                var storedToken = await _context.RefreshTokens.FirstOrDefaultAsync(x => x.Token == tokenRequest.RefreshToken);

                if (storedToken == null) {
                    return new AuthResult() {
                        Success = false,
                        Errors = new List<String>(){
                            "Token does not exist"
                        }
                    };
                }


                //validate if it is used
                if (storedToken.IsUsed)
                {
                    return new AuthResult() {
                        Success = false,
                        Errors = new List<String>(){
                            "Token has been used"
                        }
                    };
                }


                //validate if it is revoked
                if (storedToken.IsRevoked)
                {
                    return new AuthResult() {
                        Success = false,
                        Errors = new List<String>(){
                            "Token has been revoked"
                        }
                    };
                }

                //validate the id
                var jti = tokenInVerification.Claims.FirstOrDefault(x => x.Type == JwtRegisteredClaimNames.Jti).Value;

                if (storedToken.JwtId != jti )
                {
                    return new AuthResult() {
                        Success = false,
                        Errors = new List<String>(){
                            "Token does not match"
                        }
                    };
                }

                //update current token
                storedToken.IsUsed = true;
                _context.RefreshTokens.Update(storedToken);
                await _context.SaveChangesAsync();

                //generate new token
                var dbUser = await _userManager.FindByIdAsync(storedToken.UserId);

                return await GenerateJwtToken(dbUser);

            }
            catch
            {
                return null;
            }
        }

        private string RandomString(int length)
        {
            var random =  new Random();
            var chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
            return new string(Enumerable.Repeat(chars, length)
            .Select(x => x[random.Next(x.Length)]).ToArray());
        }

        private DateTime UnixTimeStampToDateTime(double unixTimeStamp)
        {
            var dateTimevalue = new DateTime(1970, 1, 1, 0, 0, 0, 0, DateTimeKind.Utc);
            dateTimevalue = dateTimevalue.AddSeconds(unixTimeStamp).ToUniversalTime();
            return dateTimevalue;
        }
    }
}