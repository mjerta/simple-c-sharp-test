using System;
using System.Security.Cryptography;
using System.Text;

class GenerateJwt
{
    static void Main(string[] args)
    {
        var options = Options.Parse(args);
        string secret = options.Secret;

        string headerJson = "{\"alg\":\"HS256\",\"typ\":\"JWT\"}";
        string payloadJson = $"{{\"iss\":\"{options.Issuer}\",\"sub\":\"{options.Subject}\",\"name\":\"{options.Name}\",\"admin\":{options.Admin.ToString().ToLowerInvariant()},\"iat\":{options.IssuedAt},\"exp\":{options.ExpiresAt}}}";

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
        public string Secret { get; private set; }
        public string Issuer { get; private set; }
        public string Subject { get; private set; }
        public string Name { get; private set; }
        public bool Admin { get; private set; }
        public long IssuedAt { get; private set; }
        public long ExpiresAt { get; private set; }

        public static Options Parse(string[] args)
        {
            var options = new Options
            {
                Secret = "a-string-secret-at-least-256-bits-lon",
                Issuer = "xpi",
                Subject = "1234567890",
                Name = "John Doe",
                Admin = true,
                IssuedAt = UnixTimeNow(),
                ExpiresAt = UnixTimeNow() + 3600
            };

            foreach (string arg in args)
            {
                var parts = arg.Split('=');
                if (parts.Length != 2) continue;

                string key = parts[0].TrimStart('-').ToLowerInvariant();
                string value = parts[1];

                switch (key)
                {
                    case "secret":
                        options.Secret = value;
                        break;
                    case "iss":
                    case "issuer":
                        options.Issuer = value;
                        break;
                    case "sub":
                    case "subject":
                        options.Subject = value;
                        break;
                    case "name":
                        options.Name = value;
                        break;
                    case "admin":
                        if (bool.TryParse(value, out var admin))
                        {
                            options.Admin = admin;
                        }
                        break;
                    case "iat":
                        if (long.TryParse(value, out var iat))
                        {
                            options.IssuedAt = iat;
                        }
                        break;
                    case "exp":
                        if (long.TryParse(value, out var exp))
                        {
                            options.ExpiresAt = exp;
                        }
                        break;
                }
            }

            if (options.ExpiresAt <= options.IssuedAt)
            {
                options.ExpiresAt = options.IssuedAt + 3600;
            }

            return options;
        }

        private static long UnixTimeNow()
        {
            return DateTimeOffset.UtcNow.ToUnixTimeSeconds();
        }
    }
}
