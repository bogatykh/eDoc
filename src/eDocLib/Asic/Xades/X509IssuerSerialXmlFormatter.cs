using System.Globalization;
using System.Numerics;
using System.Security.Cryptography.X509Certificates;

namespace eDocLib.Asic.Xades;

/// <summary>XML-DSig <c>X509SerialNumber</c> (decimal) formatting for <c>xades:IssuerSerial</c>.</summary>
internal static class X509IssuerSerialXmlFormatter
{
    /// <summary>Formats the serial number as a decimal string.</summary>
    internal static string SerialNumberDecimalString(X509Certificate2 certificate)
    {
        var le = certificate.GetSerialNumber();
        if (le.Length == 0)
        {
            return "0";
        }

        Span<byte> be = stackalloc byte[le.Length];
        le.CopyTo(be);
        be.Reverse();
        var value = new BigInteger(be, isUnsigned: true, isBigEndian: true);
        return value.ToString(CultureInfo.InvariantCulture);
    }
}
