using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using API.Entities;

namespace API.Interfaces
{
    public interface iTokenService
    {
        string CreateToken(AppUser user);
    }
}