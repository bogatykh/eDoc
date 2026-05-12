using Org.BouncyCastle.Utilities.Encoders;

namespace eDocLib.Internal;

/// <summary>Base64 → raw octets via BouncyCastle (line-wrapped Base64 is accepted).</summary>
internal static class Base64Bytes
{
    /// <summary>Decodes a Base64 string (no trim); returns false when empty or invalid.</summary>
    public static bool TryDecode(string base64Text, out byte[] bytes)
    {
        bytes = [];
        if (string.IsNullOrEmpty(base64Text))
        {
            return false;
        }

        try
        {
            bytes = Base64.Decode(base64Text);
            return bytes.Length > 0;
        }
        catch (Exception)
        {
            return false;
        }
    }

    /// <summary>Decodes RFC-style Base64 after whitespace trim; returns false when empty or invalid.</summary>
    public static bool TryFromBase64Trimmed(string text, out byte[] bytes)
    {
        bytes = [];
        if (string.IsNullOrEmpty(text))
        {
            return false;
        }

        var trimmed = text.Trim();
        if (trimmed.Length == 0)
        {
            return false;
        }

        return TryDecode(trimmed, out bytes);
    }
}
