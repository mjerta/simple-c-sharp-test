using System;
using System.Text;
using System.Security.Cryptography;

class Program
{
    static void Main(string[] args)
    {
        string secret = "a-string-secret-at-least-256-bits-long";
        string tokenInput = ExtractTokenFromArgs(args);
        if (string.IsNullOrWhiteSpace(tokenInput))
        {
            Console.WriteLine("No token flag detected. Please paste your JWT token here:");
            tokenInput = Console.ReadLine();
        }

        string tokenBeingUsed = SecureToken(tokenInput);

        if (string.IsNullOrWhiteSpace(tokenBeingUsed))
        {
            Console.WriteLine("No token provided. Usage: mono DecodeJWT.exe -t <jwt-token>");
            return;
        }

        Console.WriteLine("\nCheck if the jwt is long enough in the first place...");
        if (!isPartLengthCorrect(tokenBeingUsed))
        {
            Console.WriteLine("\nThe String was not with 2 dots.");
            return;
        }
        else
        {
            Console.WriteLine("\nThe string was at least with 2 dots.");
        }

        Console.WriteLine("\nVerifying Signature...");
        if (VerifyHS256(tokenBeingUsed, secret))
        {
            Console.WriteLine("SUCCESS: Signature matches!");
        }
        else
        {
            Console.WriteLine("FAILURE: Signature mismatch or invalid format.");
            return;
        }

        Console.WriteLine("Decoding Payload...");
        string payload = ExtractPayload(tokenBeingUsed);
        Console.WriteLine("Payload: " + payload);

    }


    public static bool isPartLengthCorrect(string token)
    {
        string[] parts = token.Split('.');
        return parts.Length == 3;
    }

    public static string ExtractPayload(string token)
    {
        try
        {
            string[] parts = token.Split('.');
            byte[] data = DecodeBase64UrlToBytes(parts[1]);
            return Encoding.UTF8.GetString(data);
        }
        catch (Exception ex)
        {
            return "Error: " + ex.Message;
        }
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
}
