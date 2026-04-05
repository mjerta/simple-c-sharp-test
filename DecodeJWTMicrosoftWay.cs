using System;
using System.Collections.Generic;
using System.IdentityModel.Tokens; // The official 4.5 namespace
using System.Security.Claims;
using System.Text;

class DecodeJWTMicrosoftWay
{
    private const string DefaultIssuer = "XPI";

    public static void Main(string[] args)
    {
        System.IdentityModel.Tokens.JwtSecurityTokenHandler.InboundClaimTypeMap.Clear();

        string tokenInput = ExtractTokenFromArgs(args);
        string tokenBeingUsed = SecureToken(tokenInput);

        if (string.IsNullOrWhiteSpace(tokenBeingUsed))
        {
            WriteError("No token provided.");
            return;
        }

        string secret = "a-string-secret-at-least-256-bits-long";

        try
        {
            Claim[] claims = ExtractClaims(tokenBeingUsed, secret);
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

    private static string ExtractTokenFromArgs(string[] args)
    {
        if (args != null && args.Length >= 2 && args[0] == "-t")
        {
            return args[1];
        }

        return null;
    }

    private static void WriteError(string message)
    {
        Console.WriteLine("{\"error\":\"" + EscapeForJson(message) + "\"}");
    }

    private static string EscapeForJson(string value)
    {
        if (string.IsNullOrEmpty(value))
        {
            return string.Empty;
        }

        var builder = new StringBuilder(value.Length);
        foreach (char c in value)
        {
            switch (c)
            {
                case '"':
                    builder.Append("\\\"");
                    break;
                case '\\':
                    builder.Append("\\\\");
                    break;
                case '\b':
                    builder.Append("\\b");
                    break;
                case '\f':
                    builder.Append("\\f");
                    break;
                case '\n':
                    builder.Append("\\n");
                    break;
                case '\r':
                    builder.Append("\\r");
                    break;
                case '\t':
                    builder.Append("\\t");
                    break;
                default:
                    if (char.IsControl(c))
                    {
                        builder.AppendFormat("\\u{0:x4}", (int)c);
                    }
                    else
                    {
                        builder.Append(c);
                    }
                    break;
            }
        }

        return builder.ToString();
    }
}
