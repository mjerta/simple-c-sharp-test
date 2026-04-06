using System;
using System.IdentityModel.Tokens;
using System.Text;

class GenerateJwtMicrosoftWay
{
    static void Main(string[] args)
    {
        try
        {
            string secret = "a-string-secret-at-least-256-bits-long";
            string subjectFromArgs = "";
            string secretFromArgs = null;

            for (int i = 0; i < args.Length; i++)
            {
                if (args[i] == "-gib" && i + 1 < args.Length)
                {
                    subjectFromArgs = args[i + 1];
                }
                else if (args[i] == "-s" && i + 1 < args.Length)
                {
                    secretFromArgs = args[i + 1];
                }
            }

            string secretBeingUsed = secretFromArgs ?? secret;
            var now = DateTimeOffset.UtcNow.ToUnixTimeSeconds();
            var options = new Options(
                secret: secretBeingUsed,
                issuer: "XPI",
                subject: subjectFromArgs,
                issuedAt: now,
                expiresAt: now + 3600);

            var tokenHandler = new JwtSecurityTokenHandler();
            var keyBytes = Encoding.UTF8.GetBytes(options.Secret);
            var securityKey = new InMemorySymmetricSecurityKey(keyBytes);
            var signingCredentials = new SigningCredentials(
                securityKey,
                SecurityAlgorithms.HmacSha256Signature,
                SecurityAlgorithms.Sha256Digest);

            var header = new JwtHeader(signingCredentials);
            object alg = null;
            if (header.TryGetValue("alg", out var existingAlg))
            {
                alg = existingAlg;
            }
            header.Clear();
            header.Add("alg", alg ?? signingCredentials.SignatureAlgorithm);
            header.Add("typ", "JWT");

            var payload = new JwtPayload
            {
                { "iss", options.Issuer },
                { "sub", options.Subject },
                { "iat", options.IssuedAt },
                { "exp", options.ExpiresAt }
            };

            var securityToken = new JwtSecurityToken(header, payload);
            string token = tokenHandler.WriteToken(securityToken);

            Console.WriteLine(token);
        }
        catch (Exception ex)
        {
            WriteError(ex.Message);
        }
    }

    private static void WriteError(string message)
    {
        string payload = Newtonsoft.Json.JsonConvert.SerializeObject(new
        {
            error = message ?? string.Empty
        });

        Console.WriteLine(payload);
    }

    private class Options
    {
        public string Secret { get; }
        public string Issuer { get; }
        public string Subject { get; }
        public long IssuedAt { get; }
        public long ExpiresAt { get; }

        public Options(string secret, string issuer, string subject, long issuedAt, long expiresAt)
        {
            Secret = secret;
            Issuer = issuer;
            Subject = subject;
            IssuedAt = issuedAt;
            ExpiresAt = expiresAt;
        }
    }
}
