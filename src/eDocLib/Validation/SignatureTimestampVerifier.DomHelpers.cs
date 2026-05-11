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

        var sigTs = XadesUnsignedEmbeddedValues.ReadEncapsulatedSignatureTimeStamps(signatureDocument);
        if (sigTs.Count == 0)
        {
            error = "No xades:SignatureTimeStamp/xades:EncapsulatedTimeStamp element found.";
            return false;
        }

        tokenDer = sigTs[0];
        return true;
    }
}
