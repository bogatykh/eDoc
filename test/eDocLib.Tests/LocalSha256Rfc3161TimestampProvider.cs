using System.Security.Cryptography.X509Certificates;
using eDocLib.Timestamp;
using Org.BouncyCastle.Asn1.Nist;
using Org.BouncyCastle.Asn1.X509;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Generators;
using Org.BouncyCastle.Crypto.Operators;
using Org.BouncyCastle.Cms;
using Org.BouncyCastle.Math;
using Org.BouncyCastle.Security;
using Org.BouncyCastle.Tsp;
using Org.BouncyCastle.X509;

namespace eDocLib;

/// <summary>
/// In-process RFC 3161-style time-stamp for tests: issues a CMS time-stamp token whose SHA-256 imprint matches the request.
/// </summary>
internal sealed class LocalSha256Rfc3161TimestampProvider : ITimestampProvider
{
    private static readonly Lazy<TsaState> State = new(CreateState);
    private static long _responseSerial;

    /// <summary>Public TSA certificate used by this test provider (for PKIX tests).</summary>
    internal static X509Certificate2 EmbeddedTsaCertificate =>
        new(State.Value.TsaSigningCertificate.GetEncoded());

    public Task<byte[]> GetTimestampAsync(ReadOnlyMemory<byte> messageImprint, CancellationToken cancellationToken = default)
    {
        cancellationToken.ThrowIfCancellationRequested();
        if (messageImprint.Length != 32)
        {
            throw new ArgumentException("Expected SHA-256 imprint (32 octets).", nameof(messageImprint));
        }

        var s = State.Value;
        var req = new TimeStampRequestGenerator().Generate(NistObjectIdentifiers.IdSha256, messageImprint.ToArray());
        var serial = BigInteger.ValueOf(Interlocked.Increment(ref _responseSerial));
        var resp = s.ResponseGenerator.Generate(req, serial, DateTime.UtcNow);
        if (resp.Status != 0 || resp.TimeStampToken == null)
        {
            throw new InvalidOperationException($"Local TSA rejected request (status {resp.Status}).");
        }

        // Default generator output omits the certificate set; embed the TSA cert so verifiers can resolve the signer.
        var cms = resp.TimeStampToken.ToCmsSignedData();
        var certStore = new CertificateListStore(new[] { s.TsaSigningCertificate });
        var crlStore = new EmptyCrlListStore();
        var merged = CmsSignedData.ReplaceCertificatesAndCrls(cms, certStore, crlStore);
        var tst = new TimeStampToken(merged);
        return Task.FromResult(tst.GetEncoded());
    }

    private sealed class TsaState
    {
        public required TimeStampResponseGenerator ResponseGenerator { get; init; }

        public required Org.BouncyCastle.X509.X509Certificate TsaSigningCertificate { get; init; }
    }

    private static TsaState CreateState()
    {
        var keyGen = new RsaKeyPairGenerator();
        keyGen.Init(new KeyGenerationParameters(new SecureRandom(), 2048));
        var kp = keyGen.GenerateKeyPair();

        var certGen = new X509V3CertificateGenerator();
        certGen.SetSerialNumber(BigInteger.One);
        var dn = new X509Name("CN=eDocLib Test TSA");
        certGen.SetIssuerDN(dn);
        certGen.SetSubjectDN(dn);
        certGen.SetNotBefore(DateTime.UtcNow.AddDays(-1));
        certGen.SetNotAfter(DateTime.UtcNow.AddYears(10));
        certGen.SetPublicKey(kp.Public);
        certGen.AddExtension(X509Extensions.ExtendedKeyUsage, true, new ExtendedKeyUsage(KeyPurposeID.id_kp_timeStamping));
        var factory = new Asn1SignatureFactory("SHA256WithRSA", kp.Private);
        var cert = certGen.Generate(factory);

        var tokenGen = new TimeStampTokenGenerator(kp.Private, cert, TspAlgorithms.Sha256, TspAlgorithms.Sha256);
        var respGen = new TimeStampResponseGenerator(tokenGen, new List<string> { TspAlgorithms.Sha256 });
        return new TsaState { ResponseGenerator = respGen, TsaSigningCertificate = cert };
    }
}
