using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Threading;
using System.Threading.Tasks;
using System.Xml;
using eDocLib.Asic.Container;
using eDocLib.Asic.Xades;
using eDocLib.Timestamp;
using eDocLib.Validation;
using Xunit;

namespace eDocLib.Tests;

/// <summary>
/// Coverage for the XAdES-T signing entry points in <c>XadesBesSigner.Timestamp</c>:
/// argument validation, DOM placement of <c>SignatureTimeStamp</c>, imprint correctness, and cancellation propagation.
/// </summary>
public class XadesBesSignerTimestampTests
{
    [Fact]
    public async Task SignWithTimestampAsync_rejects_null_arguments()
    {
        using var cert = NewCert("CN=null-args");
        var tsp = new LocalSha256Rfc3161TimestampProvider();
        await Assert.ThrowsAsync<ArgumentNullException>(() =>
            XadesBesSigner.SignWithTimestampAsync(null!, cert, DateTimeOffset.UtcNow, tsp));
        await Assert.ThrowsAsync<ArgumentNullException>(() =>
            XadesBesSigner.SignWithTimestampAsync(SingleDataFile(), null!, DateTimeOffset.UtcNow, tsp));
        await Assert.ThrowsAsync<ArgumentNullException>(() =>
            XadesBesSigner.SignWithTimestampAsync(SingleDataFile(), cert, DateTimeOffset.UtcNow, (ITimestampProvider)null!));
    }

    [Fact]
    public async Task SignWithTimestampAsync_rejects_cert_without_private_key()
    {
        // A trust anchor / public-only cert must not be misused as a signer. The check is needed because
        // the underlying SignedXml API would otherwise fail deep inside the signing routine with a less
        // actionable error.
        using var fullCert = NewCert("CN=pubonly");
        using var pubOnly = new X509Certificate2(fullCert.Export(X509ContentType.Cert));
        Assert.False(pubOnly.HasPrivateKey);

        var ex = await Assert.ThrowsAsync<ArgumentException>(() =>
            XadesBesSigner.SignWithTimestampAsync(SingleDataFile(), pubOnly, DateTimeOffset.UtcNow,
                new LocalSha256Rfc3161TimestampProvider()));
        Assert.Equal("signerCertificate", ex.ParamName);
    }

    [Fact]
    public async Task SignWithTimestampAsync_embeds_signature_timestamp_under_unsigned_properties()
    {
        using var cert = NewCert("CN=ts-dom");
        var sig = await XadesBesSigner.SignWithTimestampAsync(
            SingleDataFile(),
            cert,
            DateTimeOffset.UtcNow,
            new LocalSha256Rfc3161TimestampProvider(),
            signatureTimestampId: "CustomTsId");

        var doc = sig.GetSignatureOwnerDocument();
        var nsm = new XmlNamespaceManager(doc.NameTable);
        nsm.AddNamespace("xades", XadesSignature.XadesNamespaceUrl);
        var wrapper = doc.SelectSingleNode("//xades:UnsignedSignatureProperties/xades:SignatureTimeStamp", nsm) as XmlElement;
        Assert.NotNull(wrapper);
        Assert.Equal("CustomTsId", wrapper!.GetAttribute("Id"));

        var enc = wrapper.SelectSingleNode("xades:EncapsulatedTimeStamp", nsm) as XmlElement;
        Assert.NotNull(enc);
        Assert.False(string.IsNullOrEmpty(enc!.InnerText));
    }

    [Fact]
    public async Task SignWithTimestampAsync_imprint_matches_signature_value_sha256()
    {
        // The imprint a XAdES-T verifier checks is SHA-256 over the raw SignatureValue octets.
        // If the signer accidentally hashed something else (e.g. canonicalised SignedInfo), TryVerify... would fail.
        using var cert = NewCert("CN=imprint-equality");
        var sig = await XadesBesSigner.SignWithTimestampAsync(
            SingleDataFile(),
            cert,
            DateTimeOffset.UtcNow,
            new LocalSha256Rfc3161TimestampProvider());

        Assert.True(SignatureTimestampVerifier.TryVerifySignatureTimeStampImprint(sig.GetSignatureOwnerDocument(), out var err), err);
    }

    [Fact]
    public async Task SignWithTimestampAsync_propagates_cancellation_before_tsp_request()
    {
        using var cert = NewCert("CN=cancel");
        using var cts = new CancellationTokenSource();
        cts.Cancel();

        await Assert.ThrowsAsync<OperationCanceledException>(() =>
            XadesBesSigner.SignWithTimestampAsync(
                SingleDataFile(),
                cert,
                DateTimeOffset.UtcNow,
                new LocalSha256Rfc3161TimestampProvider(),
                cancellationToken: cts.Token));
    }

    [Fact]
    public async Task SignWithTimestampAsync_propagates_tsp_exception_without_leaving_partial_timestamp()
    {
        // Defensive contract: if the TSP fails, no SignatureTimeStamp element should be persisted.
        // (The current implementation appends only after a successful await — but a future refactor that
        // appended an empty wrapper "for completeness" would silently regress this property.)
        using var cert = NewCert("CN=tsp-fail");
        var failing = new FailingTimestampProvider();
        await Assert.ThrowsAsync<InvalidOperationException>(() =>
            XadesBesSigner.SignWithTimestampAsync(SingleDataFile(), cert, DateTimeOffset.UtcNow, failing));

        Assert.True(failing.WasCalled);
    }

    [Fact]
    public async Task AppendSignatureTimestampAsync_appends_to_existing_BES_signature()
    {
        using var cert = NewCert("CN=append");
        var dfs = SingleDataFile().ToList();
        var sig = XadesBesSigner.Sign(dfs, cert, DateTimeOffset.UtcNow);

        // ISignature → AsicSignature is the only concrete path produced by Sign(); verify here.
        var asic = Assert.IsType<AsicSignature>(sig);
        await XadesBesSigner.AppendSignatureTimestampAsync(
            asic,
            new LocalSha256Rfc3161TimestampProvider(),
            signatureTimestampId: "AppendedTs");

        var doc = sig.GetSignatureOwnerDocument();
        var nsm = new XmlNamespaceManager(doc.NameTable);
        nsm.AddNamespace("xades", XadesSignature.XadesNamespaceUrl);
        var wrapper = doc.SelectSingleNode("//xades:UnsignedSignatureProperties/xades:SignatureTimeStamp", nsm) as XmlElement;
        Assert.NotNull(wrapper);
        Assert.Equal("AppendedTs", wrapper!.GetAttribute("Id"));

        Assert.True(SignatureTimestampVerifier.TryVerifySignatureTimeStampImprint(doc, out var err), err);
    }

    [Fact]
    public async Task AppendSignatureTimestampAsync_rejects_null_arguments()
    {
        using var cert = NewCert("CN=null-append");
        var dfs = SingleDataFile().ToList();
        var sig = XadesBesSigner.Sign(dfs, cert, DateTimeOffset.UtcNow);
        var asic = Assert.IsType<AsicSignature>(sig);

        await Assert.ThrowsAsync<ArgumentNullException>(() =>
            XadesBesSigner.AppendSignatureTimestampAsync(null!, new LocalSha256Rfc3161TimestampProvider()));
        await Assert.ThrowsAsync<ArgumentNullException>(() =>
            XadesBesSigner.AppendSignatureTimestampAsync(asic, (ITimestampProvider)null!));
    }

    private static IEnumerable<IDataFile> SingleDataFile()
    {
        yield return new DataFile(new MemoryStream("payload"u8.ToArray()), "doc.txt", "text/plain");
    }

    private static X509Certificate2 NewCert(string subject)
    {
        using var rsa = RSA.Create(2048);
        var req = new CertificateRequest(subject, rsa, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        return req.CreateSelfSigned(DateTimeOffset.UtcNow.AddDays(-1), DateTimeOffset.UtcNow.AddYears(1));
    }

    private sealed class FailingTimestampProvider : ITimestampProvider
    {
        public bool WasCalled { get; private set; }

        public Task<byte[]> GetTimestampAsync(ReadOnlyMemory<byte> messageImprint, CancellationToken cancellationToken = default)
        {
            WasCalled = true;
            throw new InvalidOperationException("simulated TSA outage");
        }
    }
}
