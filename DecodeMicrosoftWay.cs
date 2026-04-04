using System;
using System.Collections.Generic;
using System.IdentityModel.Tokens; // The official 4.5 namespace
using System.Security.Claims;
using System.Text;

class DecodeMicrosoftWay
{
    public static void Main(string[] args)
    {
        string tokenWithExpAndIss = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJ4cGkiLCJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiYWRtaW4iOnRydWUsImlhdCI6MTc3NTMyNDYxMSwiZXhwIjoxNzc1MzI4MjExfQ.au4P-kXMBF10df6E4TCNf62MOYBGacHht8-TzvcFYbw";
        string tokenWithExpOnly = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJleHAiOjE3NDY0MDMyMDAsImlhdCI6MTc3Nzg1MjgwMCwic3ViIjoiMTIzNDU2Nzg5MCIsIm5hbWUiOiJKb2huIERvZSIsImFkbWluIjp0cnVlfQ.2jPUL-5EAlaUnbD7qLTKHkZjOfP1Rp4MWcD1PAPtHFI";

        bool useTokenWithExpOnly = args != null && Array.Exists(args, a => a.Equals("--use-exp-only", StringComparison.OrdinalIgnoreCase));
        string tokenBeingUsed = useTokenWithExpOnly ? tokenWithExpOnly : tokenWithExpAndIss;
        string secret = "a-string-secret-at-least-256-bits-long";

        string validationMessage = VerifyTheMicrosoftWay(tokenBeingUsed, secret);
        Console.WriteLine(validationMessage);
        bool isValid = validationMessage.StartsWith("Token is valid", StringComparison.OrdinalIgnoreCase);

        if (isValid)
        {
            Claim[] claims = ExtractClaims(tokenBeingUsed, secret);
            if (claims.Length > 0)
            {
                Console.WriteLine("Claims extracted (Microsoft way):");
                foreach (var claim in claims)
                {
                    Console.WriteLine(" - " + claim.Type + ": " + claim.Value);
                }
            }
        }
    }

    public static string VerifyTheMicrosoftWay(string token, string secret)
    {
        try
        {
            ValidateTokenAndGetPrincipal(token, secret);
            return "Token is valid (Microsoft way).";
        }
        catch (Exception ex)
        {
            return "Validation error: " + ex.Message;
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
            ValidateAudience = false, // Update when you have a real audience
            ValidateLifetime = true,
            RequireExpirationTime = true,
            ClockSkew = TimeSpan.FromMinutes(1),
            IssuerValidator = (issuer, securityToken, parameters) =>
            {
                if (string.IsNullOrWhiteSpace(issuer))
                {
                    throw new SecurityTokenInvalidIssuerException("Issuer claim is required when ValidateIssuer is true.");
                }

                return issuer; // Accept any non-empty issuer for now
            }
        };

        SecurityToken validatedToken;
        return tokenHandler.ValidateToken(token, validationParameters, out validatedToken);
    }
}
