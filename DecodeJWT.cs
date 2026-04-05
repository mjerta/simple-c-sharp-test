using System;
using System.Text;
using System.Globalization;
using System.Security.Cryptography;

class Program
{
    static void Main(string[] args)
    {
        string secret = "a-string-secret-at-least-256-bits-long";
        try
        {
            string tokenInput = ExtractTokenFromArgs(args);

            string tokenBeingUsed = SecureToken(tokenInput);

            if (string.IsNullOrWhiteSpace(tokenBeingUsed))
            {
                WriteError("No token provided.");
                return;
            }

            if (!isPartLengthCorrect(tokenBeingUsed))
            {
                WriteError("Token must contain header, payload, and signature (two dots).");
                return;
            }

            if (!VerifyHS256(tokenBeingUsed, secret))
            {
                WriteError("Signature mismatch or invalid format.");
                return;
            }

            if (!VerifyPayload(tokenBeingUsed))
            {
                return;
            }

            string payload = ExtractPayload(tokenBeingUsed);
            Console.WriteLine(payload);
        }
        catch (Exception ex)
        {
            WriteError(ex.Message);
        }
    }


    public static bool isPartLengthCorrect(string token)
    {
        string[] parts = token.Split('.');
        return parts.Length == 3;
    }

    public static string ExtractPayload(string token)
    {
        string[] parts = token.Split('.');
        byte[] data = DecodeBase64UrlToBytes(parts[1]);
        return Encoding.UTF8.GetString(data);
    }
    private static byte[] DecodeBase64UrlToBytes(string input)
    {
        string base64 = input.Replace('-', '+').Replace('_', '/');
        int mod4 = base64.Length % 4;
        if (mod4 > 0)
        {
            base64 += new string('=', 4 - mod4);
        }
        return Convert.FromBase64String(base64);
    }

    public static bool VerifyHS256(string token, string secret)
    {
        string[] parts = token.Split('.');

        string headerAndPayload = parts[0] + "." + parts[1];
        string incomingSignature = parts[2];

        byte[] keyBytes = Encoding.UTF8.GetBytes(secret);
        byte[] messageBytes = Encoding.UTF8.GetBytes(headerAndPayload);

        using (var hmac = new HMACSHA256(keyBytes))
        {
            byte[] computedHash = hmac.ComputeHash(messageBytes);
            // string computedSignature = EncodeBase64Url(computedHash);
            // Console.WriteLine(computedSignature);
            // Console.WriteLine(incomingSignature);

            byte[] incomingBytes = DecodeBase64UrlToBytes(incomingSignature);
            // return computedSignature == incomingSignature;

            return FixedTimeEquals(computedHash, incomingBytes);
        }
    }

    private static string EncodeBase64Url(byte[] input)
    {
        return Convert.ToBase64String(input)
            .Split('=')[0]
            .Replace('+', '-')
            .Replace('/', '_');
    }

    private static bool FixedTimeEquals(byte[] left, byte[] right)
    {
        if (left.Length != right.Length) return false;

        int result = 0;
        for (int i = 0; i < left.Length; i++)
        {
            // XOR returns 0 if they match. 
            // OR accumulates any non-zero bits.
            result |= left[i] ^ right[i];
        }
        // If result is still 0, every single byte matched.
        return result == 0;
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

    private static bool VerifyPayload(string token)
    {
        string payload = ExtractPayload(token);
        if (string.IsNullOrEmpty(payload))
        {
            WriteError("Token payload missing.");
            return false;
        }

        const string expKey = "\"exp\"";
        int keyIndex = payload.IndexOf(expKey, StringComparison.Ordinal);
        if (keyIndex == -1)
        {
            WriteError("Token missing exp claim.");
            return false;
        }

        int colonIndex = payload.IndexOf(':', keyIndex + expKey.Length);
        if (colonIndex == -1)
        {
            WriteError("Token exp claim malformed.");
            return false;
        }

        int valueStart = colonIndex + 1;
        while (valueStart < payload.Length && char.IsWhiteSpace(payload[valueStart]))
        {
            valueStart++;
        }

        int valueEnd = valueStart;
        while (valueEnd < payload.Length && (char.IsDigit(payload[valueEnd]) || payload[valueEnd] == '-'))
        {
            valueEnd++;
        }

        if (valueEnd == valueStart)
        {
            WriteError("Token exp claim missing value.");
            return false;
        }

        string numericText = payload.Substring(valueStart, valueEnd - valueStart);
        if (!long.TryParse(numericText, NumberStyles.Integer, CultureInfo.InvariantCulture, out long expValue))
        {
            WriteError("Token exp claim invalid.");
            return false;
        }

        long now = DateTimeOffset.UtcNow.ToUnixTimeSeconds();
        if (now >= expValue)
        {
            WriteError("Token already expired.");
            return false;
        }

        return true;
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
