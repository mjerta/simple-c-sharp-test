using System;
using System.Collections.Generic;
using System.IdentityModel.Tokens; // The official 4.5 namespace
using System.Security.Claims;
using System.Text;

class DecodeJWTMicrosoftWay
{
    private const string DefaultIssuer = "XPI";
    private static string ErrorMessage = "";

    public static void Main(string[] args)
    {
        string tokenBeingUsed = "";
        // Check for the -t flag
        if (args.Length >= 2 && args[0] == "-t")
        {
            tokenBeingUsed = args[1];
        }
        else
        {
            Console.WriteLine("No token flag detected. Please paste your JWT token here:");
            tokenBeingUsed = Console.ReadLine();
        }

        string secret = "a-string-secret-at-least-256-bits-long";

        VerifyTheMicrosoftWay(tokenBeingUsed, secret);

        if (ErrorMessage.Length == 0)
        {
            Claim[] claims = ExtractClaims(tokenBeingUsed, secret);
            if (claims.Length > 0)
            {
                Console.WriteLine("Claims extracted (Microsoft way):");
                foreach (var claim in claims)
                {
                    Console.WriteLine("Error: " + claim.Value);
                }
            }
        }
        else
        {
            Console.WriteLine(ErrorMessage);
        }
    }

    public static void VerifyTheMicrosoftWay(string token, string secret)
    {
        try
        {
            ValidateTokenAndGetPrincipal(token, secret);
        }
        catch (Exception ex)
        {
            ErrorMessage = "Error: " + ex.Message;
        }
    }

    public static Claim[] ExtractClaims(string token, string secret)
    {
        try
        {
            ClaimsPrincipal principal = ValidateTokenAndGetPrincipal(token, secret);
            var claims = new List<Claim>();
            foreach (var claim in principal.Claims)
            {
                claims.Add(claim);
            }

            return claims.ToArray();
        }
        catch (Exception ex)
        {
            Console.WriteLine("Claim extraction error: " + ex.Message);
            return new Claim[0];
        }
    }

    private static ClaimsPrincipal ValidateTokenAndGetPrincipal(string token, string secret)
    {
        var tokenHandler = new JwtSecurityTokenHandler();
        var key = Encoding.UTF8.GetBytes(secret);

        var validationParameters = new TokenValidationParameters
        {
            ValidateIssuerSigningKey = true,
            IssuerSigningKey = new InMemorySymmetricSecurityKey(key),
            ValidateIssuer = true,
            ValidIssuer = DefaultIssuer,
            ValidateAudience = false,
            ValidateLifetime = true,
            RequireExpirationTime = true,
            ClockSkew = TimeSpan.FromMinutes(1),
        };

        SecurityToken validatedToken;
        return tokenHandler.ValidateToken(token, validationParameters, out validatedToken);
    }
}
