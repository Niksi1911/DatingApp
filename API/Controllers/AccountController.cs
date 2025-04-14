using System.Security.Cryptography;
using System.Text;
using API.Data;
using API.DTOs;
using API.Entities;
using API.Interfaces;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;

namespace API.Controllers;

public class AccountController(DataContext context,iTokenService tokenService) : BaseAPIController
{
  [HttpPost("register")] //account/register
  public async Task<ActionResult<UserDto>> Register(RegisterDTO registerDTO){
      
      if(await UserExists(registerDTO.Username)){
        return BadRequest("User allready exsists !");
      }
      using var hmac = new HMACSHA512(); // Koristimo za Hashat pw

      var user = new AppUser{
        UserName = registerDTO.Username.ToLower(),
        PasswordHash = hmac.ComputeHash(Encoding.UTF8.GetBytes(registerDTO.Password)),
        PasswordSalt =hmac.Key
      };

     context.Users.Add(user);
     await context.SaveChangesAsync();

     return new UserDto{
      UserName = user.UserName,
      Token = tokenService.CreateToken(user)
     };

  }

  [HttpPost("login")]//account/login
  public async Task<ActionResult<UserDto>> Login(LoginDTO loginDTO){
      var user = await context.Users.FirstOrDefaultAsync(x =>
       x.UserName ==loginDTO.Username.ToLower());

       if (user== null){
        return Unauthorized("Invalid username");
       }

    using var hmac = new HMACSHA512(user.PasswordSalt);
    var computedHash = hmac.ComputeHash(Encoding.UTF8.GetBytes(loginDTO.Password));

    for (int i = 0; i < computedHash.Length; i++)
    {
      if(computedHash[i] !=user.PasswordHash[i]){
        return Unauthorized("Invalid password");
      }
    }
    return new UserDto{
      UserName = user.UserName,
      Token = tokenService.CreateToken(user)

    };
  }


  private async Task<bool> UserExists(string username){

    return await context.Users.AnyAsync(x => x.UserName.ToLower() == username.ToLower());
  }
}
