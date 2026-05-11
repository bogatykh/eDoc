using System.Xml;
using eDocLib.Asic.Xades;

namespace eDocLib.Validation;

internal static partial class SignatureTimestampVerifier
{
    private static bool TryGetSignatureValueOctets(XmlDocument signatureDocument, out byte[] octets, out string? error) =>
        SignatureValueReader.TryReadOctets(signatureDocument, out octets, out error);

    private static bool TryGetEncapsulatedTimestampDer(XmlDocument signatureDocument, out byte[] tokenDer, out string? error)
    {
        tokenDer = [];
        error = null;

        // Two distinct error paths: element missing entirely vs. element present but base64-malformed.
        // The latter must not silently fall through; tampered unsigned properties whose base64 was corrupted
        // would otherwise look identical to a properly absent timestamp and skip imprint verification.
        if (!XadesUnsignedEmbeddedValues.HasEncapsulatedSignatureTimeStamp(signatureDocument))
        {
            error = "No xades:SignatureTimeStamp/xades:EncapsulatedTimeStamp element found.";
            return false;
        }

        var sigTs = XadesUnsignedEmbeddedValues.ReadEncapsulatedSignatureTimeStamps(signatureDocument);
        if (sigTs.Count == 0)
        {
            error = "xades:EncapsulatedTimeStamp content is not valid Base64.";
            return false;
        }

        tokenDer = sigTs[0];
        return true;
    }
}
