﻿using Microsoft.AspNetCore.Identity;

namespace JWTAuthentication.Model
{
    public class ApplicationUser:IdentityUser
    {
        public string RefreshToken { get; set; }
        public DateTime RefreshTokenExpiryTime { get; set; }

    }
}
