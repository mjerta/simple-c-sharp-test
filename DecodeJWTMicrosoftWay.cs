using System;
using System.Collections.Generic;
using System.IdentityModel.Tokens; // The official 4.5 namespace
using System.Security.Claims;
using System.Text;

class DecodeJWTMicrosoftWay
{
    private const string DefaultIssuer = "XPI";
    private const string DefaultSecret = "a-string-secret-at-least-256-bits-long";

    public static void Main(string[] args)
    {
        System.IdentityModel.Tokens.JwtSecurityTokenHandler.InboundClaimTypeMap.Clear();

        string tokenFromArgs = null;
        string secretFromArgs = null;

        for (int i = 0; i < args.Length; i++)
        {
            if (args[i] == "-t" && i + 1 < args.Length)
            {
                tokenFromArgs = args[i + 1];
            }
            else if (args[i] == "-s" && i + 1 < args.Length)
            {
                secretFromArgs = args[i + 1];
            }
        }

        if (string.IsNullOrEmpty(tokenFromArgs))
        {
            Console.WriteLine("Usage:-t <token>, optional  -s <secret>");
            return;
        }

        string tokenBeingUsed = SecureToken(tokenFromArgs);
        if (string.IsNullOrWhiteSpace(tokenBeingUsed))
        {
            WriteError("No token provided.");
            return;
        }

        string secretBeingUsed = secretFromArgs ?? DefaultSecret;

        try
        {
            Claim[] claims = ExtractClaims(tokenBeingUsed, secretBeingUsed);
            var claimsDict = new Dictionary<string, string>();
            foreach (var c in claims)
            {
                claimsDict[c.Type] = c.Value;
            }

            string jsonOutput = Newtonsoft.Json.JsonConvert.SerializeObject(claimsDict);
            Console.WriteLine(jsonOutput);
        }
        catch (Exception ex)
        {
            WriteError(ex.Message);
        }
    }

    public static Claim[] ExtractClaims(string token, string secret)
    {
        ClaimsPrincipal principal = ValidateTokenAndGetPrincipal(token, secret);
        var claims = new List<Claim>();
        foreach (var claim in principal.Claims)
        {
            claims.Add(claim);
        }

        return claims.ToArray();
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

    private static string SecureToken(string token)
    {
        if (string.IsNullOrWhiteSpace(token))
        {
            return null;
        }

        string trimmed = token.Trim();
        return string.Copy(trimmed);
    }

    private static void WriteError(string message)
    {
        string payload = Newtonsoft.Json.JsonConvert.SerializeObject(new
        {
            error = message ?? string.Empty
        });

        Console.WriteLine(payload);
    }
}
