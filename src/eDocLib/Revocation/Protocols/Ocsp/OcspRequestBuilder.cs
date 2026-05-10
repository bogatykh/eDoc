using System.Security.Cryptography.X509Certificates;
using Org.BouncyCastle.Asn1.Oiw;
using Org.BouncyCastle.Ocsp;
using eDocLib.Revocation.Protocols.Der;

namespace eDocLib.Revocation.Protocols.Ocsp;

/// <summary>Builds RFC 6960 OCSP requests (DER) for a certificate and its issuer.</summary>
internal static class OcspRequestBuilder
{
    /// <summary>Encodes an OCSP request for <paramref name="subject"/> using <paramref name="issuer"/> for the <c>CertID</c> (SHA-1 issuer name/key hashes, PKIX default).</summary>
    public static byte[] BuildDer(X509Certificate2 subject, X509Certificate2 issuer)
    {
        ArgumentNullException.ThrowIfNull(subject);
        ArgumentNullException.ThrowIfNull(issuer);

        var subjectCert = X509DerReaders.ReadCertificate(subject.RawData);
        var issuerCert = X509DerReaders.ReadCertificate(issuer.RawData);
        var serial = subjectCert.SerialNumber;

#pragma warning disable CS0618 // BouncyCastle 2.4: replacement factory not yet adopted; PKIX OCSP CertID with SHA-1 is still widely used.
        var certId = new CertificateID(OiwObjectIdentifiers.IdSha1.Id, issuerCert, serial);
#pragma warning restore CS0618
        var gen = new OcspReqGenerator();
        gen.AddRequest(certId);
        var req = gen.Generate();
        return req.GetEncoded();
    }
}
