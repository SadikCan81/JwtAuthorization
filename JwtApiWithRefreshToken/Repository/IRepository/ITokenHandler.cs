using JwtApiWithRefreshToken.Models;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;

namespace JwtApiWithRefreshToken.Repository.IRepository
{
    public interface ITokenHandler
    {
        Token CreateAccessToken();
    }
}
