using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using JwtApiWithRefreshToken.DataAccess;
using JwtApiWithRefreshToken.Models;
using JwtApiWithRefreshToken.Repository;
using JwtApiWithRefreshToken.Repository.IRepository;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Configuration;

namespace JwtApiWithRefreshToken.Controllers
{
    [Route("api/[controller]/[action]")]
    [ApiController]
    public class LoginController : ControllerBase
    {
        private readonly ApplicationDbContext _db;
        private readonly IConfiguration _configuration;
        private readonly ITokenHandler _tokenHandler;

        public LoginController(IConfiguration configuration, ApplicationDbContext db,ITokenHandler tokenHandler)
        {
            _db = db;
            _tokenHandler = tokenHandler;
            _configuration = configuration;
        }

        [HttpPost]        
        public IActionResult Create([FromForm]User user)
        {
            if(user != null)
            {
                _db.Users.Add(user);
                _db.SaveChanges();
                return Ok("İşlem başarıyla gerçekleşti");
            }

            return Unauthorized(new { message = "Username or password is incorrect" });
        }

        [HttpPost]
        public IActionResult Login([FromForm]UserLogin userLogin)
        {
            var userFromDb = _db.Users.FirstOrDefault(x => x.Email == userLogin.Email && x.Password == userLogin.Password);

            if(userFromDb != null)
            {

                Token token = _tokenHandler.CreateAccessToken();

                userFromDb.RefreshToken = token.RefreshToken;
                userFromDb.RefreshTokenEndDate = token.Expiration.AddMinutes(5);

                _db.SaveChanges();

                return Ok(token);
            }

            return Unauthorized(new { message = "Username or password is incorrect" });
        }

        [HttpPost]
        public IActionResult RefreshTokenLogin([FromForm]string refreshToken)
        {
            var userFromDb = _db.Users.FirstOrDefault(x => x.RefreshToken == refreshToken);

            if(userFromDb != null && userFromDb.RefreshTokenEndDate > DateTime.Now)
            {
                Token token = _tokenHandler.CreateAccessToken();

                userFromDb.RefreshToken = token.RefreshToken;
                userFromDb.RefreshTokenEndDate = token.Expiration.AddMinutes(5);

                _db.SaveChanges();

                return Ok(token);
            }

            return Unauthorized(new { message = "Refresh token is invalid " });
        }

        [Authorize]
        [HttpPost]        
        public IActionResult RevokeRefreshToken([FromForm]string refreshToken)
        {
            var userFromDb = _db.Users.FirstOrDefault(x => x.RefreshToken == refreshToken);

            if (userFromDb != null && userFromDb.RefreshTokenEndDate > DateTime.Now)
            {
                
                userFromDb.RefreshToken = "Revoked";
                userFromDb.RefreshTokenEndDate = DateTime.Now;

                _db.SaveChanges();

                return Ok("Refresh token revoked");
            }

            return Unauthorized(new { message = "Refresh token is invalid " });
        }
            
    }
}