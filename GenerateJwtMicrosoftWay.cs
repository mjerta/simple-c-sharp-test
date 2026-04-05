using System;
using System.IdentityModel.Tokens;
using System.Text;

class GenerateJwtMicrosoftWay
{
    static void Main(string[] args)
    {
        var now = DateTimeOffset.UtcNow.ToUnixTimeSeconds();
        var options = new Options(
            secret: "a-string-secret-at-least-256-bits-long",
            issuer: "XPI",
            subject: "1234567890",
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

        Console.WriteLine("Generated JWT (Microsoft way):\n" + token);
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
