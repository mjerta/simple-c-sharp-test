using System;
using System.Security.Cryptography;
using System.Text;

class GenerateJwt
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

        string secret = options.Secret;

        string headerJson = "{\"alg\":\"HS256\",\"typ\":\"JWT\"}";
        string payloadJson = $"{{\"iss\":\"{options.Issuer}\",\"sub\":\"{options.Subject}\",\"iat\":{options.IssuedAt},\"exp\":{options.ExpiresAt}}}";

        string token = BuildToken(headerJson, payloadJson, secret);

        Console.WriteLine("Generated JWT:\n" + token);
    }

    private static string BuildToken(string headerJson, string payloadJson, string secret)
    {
        string header = Base64UrlEncode(Encoding.UTF8.GetBytes(headerJson));
        string payload = Base64UrlEncode(Encoding.UTF8.GetBytes(payloadJson));
        string message = header + "." + payload;

        using (var hmac = new HMACSHA256(Encoding.UTF8.GetBytes(secret)))
        {
            byte[] signatureBytes = hmac.ComputeHash(Encoding.UTF8.GetBytes(message));
            string signature = Base64UrlEncode(signatureBytes);
            return message + "." + signature;
        }
    }

    private static string Base64UrlEncode(byte[] input)
    {
        return Convert.ToBase64String(input)
            .TrimEnd('=')
            .Replace('+', '-')
            .Replace('/', '_');
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
