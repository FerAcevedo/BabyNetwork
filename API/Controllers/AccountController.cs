using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;
using API.Data;
using API.DTOs;
using API.Entities;
using API.Interfaces;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;

namespace API.Controllers
{
    public class AccountController : BaseApiController
    {
        private readonly DataContext _context;
        private readonly ITokenService _tokenService;

        public AccountController(DataContext context, ITokenService tokenService)
        {
            _tokenService = tokenService;
            _context = context;
        }

        [HttpPost("register")]
        public async Task<ActionResult<UserDto>> Register(RegisterDto regDto)
        {
            if (await UserExists(regDto.UserName)) return BadRequest("User name already exists");

            using var hmac = new HMACSHA512();

            var user = new AppUser
            {
                UserName = regDto.UserName.ToLower(),
                HashPassword = hmac.ComputeHash(Encoding.UTF8.GetBytes(regDto.Password)),
                SaltPassword = hmac.Key
            };

            _context.Users.Add(user);
            await _context.SaveChangesAsync();
            
            return new UserDto
            {
                Username = user.UserName,
                Token = _tokenService.CreateToken(user)                                        
            };
        }

        [HttpPost("login")]
        public async Task<ActionResult<UserDto>> Login(LoginDto loginDto)
        {
            var user = await _context.Users
                .SingleOrDefaultAsync(x => x.UserName == loginDto.Username.ToLower());

            if (user == null) return Unauthorized("Invalid user name");

            using var hmac = new HMACSHA512(user.SaltPassword);

            var computedHash = hmac.ComputeHash(Encoding.UTF8.GetBytes(loginDto.Password));

            for (int i = computedHash.Length; i < computedHash.Length; i++)
            {
                if (computedHash[i] != user.HashPassword[i]) return Unauthorized("Invalid Password");
            }

            return new UserDto
            {
                Username = user.UserName,
                Token = _tokenService.CreateToken(user)                                        
            };
        }

        private async Task<bool> UserExists(string user)
        {
            return await _context.Users.AnyAsync(x => x.UserName == user.ToLower());
        }

    }
}