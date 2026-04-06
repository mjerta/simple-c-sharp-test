using System;
using System.Security.Cryptography;
using System.Text;

class GenerateJwt
{
    static void Main(string[] args)
    {
        try
        {
            string defaultSecret = "a-string-secret-at-least-256-bits-long";
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

            if (secretFromArgs.Length < 16)
            {
                throw new ArgumentException("The secret need to be at least 16 characters");
            }
            string secretBeingUsed = secretFromArgs ?? defaultSecret;
            var now = DateTimeOffset.UtcNow.ToUnixTimeSeconds();
            var options = new Options(
                secret: secretBeingUsed,
                issuer: "XPI",
                subject: subjectFromArgs,
                issuedAt: now,
                expiresAt: now + 3600);

            string secret = options.Secret;

            string headerJson = "{\"alg\":\"HS256\",\"typ\":\"JWT\"}";
            string payloadJson = $"{{\"iss\":\"{options.Issuer}\",\"sub\":\"{options.Subject}\",\"iat\":{options.IssuedAt},\"exp\":{options.ExpiresAt}}}";

            string token = BuildToken(headerJson, payloadJson, secret);

            Console.WriteLine(token);
        }
        catch (Exception ex)
        {
            WriteError(ex.Message);
        }
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
