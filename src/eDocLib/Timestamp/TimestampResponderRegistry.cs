using System.Collections.Concurrent;
using System.Net.Http;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using eDocLib.Configuration;

namespace eDocLib.Timestamp;

/// <summary>
/// Maps signing-certificate SHA-1 thumbprints (hex, with or without separators) to RFC 3161 time-stamp authority (TSA) HTTP endpoints.
/// Lookups prefer the end-entity certificate thumbprint, then the issuer certificate thumbprint derived from a built chain.
/// </summary>
public sealed class TimestampResponderRegistry
{
    private readonly ConcurrentDictionary<string, Uri> _byEndEntityThumbprint = new(StringComparer.OrdinalIgnoreCase);
    private readonly ConcurrentDictionary<string, Uri> _byIssuerThumbprint = new(StringComparer.OrdinalIgnoreCase);

    /// <summary>Registers a TSA URL for the given end-entity (leaf signer) certificate thumbprint.</summary>
    /// <param name="sha1ThumbprintHex">SHA-1 thumbprint of the signer certificate in hexadecimal.</param>
    /// <param name="tspHttpEndpoint">HTTP(S) base URI of the RFC 3161 endpoint.</param>
    public void RegisterByEndEntityThumbprint(string sha1ThumbprintHex, Uri tspHttpEndpoint)
    {
        ArgumentException.ThrowIfNullOrEmpty(sha1ThumbprintHex);
        ArgumentNullException.ThrowIfNull(tspHttpEndpoint);
        _byEndEntityThumbprint[NormalizeHex(sha1ThumbprintHex)] = tspHttpEndpoint;
    }

    /// <summary>Registers a TSA URL for any signer whose issuing CA matches the given issuer certificate thumbprint.</summary>
    /// <param name="sha1ThumbprintHex">SHA-1 thumbprint of the issuer (CA) certificate in hexadecimal.</param>
    /// <param name="tspHttpEndpoint">HTTP(S) base URI of the RFC 3161 endpoint.</param>
    public void RegisterByIssuerThumbprint(string sha1ThumbprintHex, Uri tspHttpEndpoint)
    {
        ArgumentException.ThrowIfNullOrEmpty(sha1ThumbprintHex);
        ArgumentNullException.ThrowIfNull(tspHttpEndpoint);
        _byIssuerThumbprint[NormalizeHex(sha1ThumbprintHex)] = tspHttpEndpoint;
    }

    /// <summary>
    /// Registers TSP HTTP endpoints from <paramref name="config"/>'s timestamp routes. Does not clear existing registrations.
    /// </summary>
    public void RegisterFrom(EdocLibConfig config)
    {
        ArgumentNullException.ThrowIfNull(config);
        foreach (var route in config.TimestampResponders ?? [])
        {
            var uri = new Uri(route.HttpEndpoint, UriKind.Absolute);
            var tp = route.Kind.Trim();
            if (tp.Equals("issuerThumbprint", StringComparison.OrdinalIgnoreCase))
            {
                RegisterByIssuerThumbprint(route.ThumbprintSha1Hex, uri);
            }
            else if (tp.Equals("endEntityThumbprint", StringComparison.OrdinalIgnoreCase))
            {
                RegisterByEndEntityThumbprint(route.ThumbprintSha1Hex, uri);
            }
            else
            {
                throw new InvalidOperationException(
                    $"Unknown timestamp responder kind '{route.Kind}'. Expected issuerThumbprint or endEntityThumbprint.");
            }
        }
    }

    /// <summary>End-entity match wins; otherwise issuer thumbprint of <paramref name="signerCertificate"/>.</summary>
    public bool TryGetResponderUri(X509Certificate2 signerCertificate, [System.Diagnostics.CodeAnalysis.NotNullWhen(true)] out Uri? endpoint)
    {
        ArgumentNullException.ThrowIfNull(signerCertificate);
        var ee = NormalizeHex(signerCertificate.Thumbprint);
        if (_byEndEntityThumbprint.TryGetValue(ee, out endpoint!))
        {
            return true;
        }

        if (TryGetIssuerThumbprint(signerCertificate, out var issuerTp)
            && _byIssuerThumbprint.TryGetValue(issuerTp, out endpoint!))
        {
            return true;
        }

        endpoint = null;
        return false;
    }

    /// <summary>
    /// Creates an <see cref="Rfc3161HttpTimestampProvider"/> for <paramref name="signerCertificate"/> when a route exists.
    /// </summary>
    public bool TryCreateHttpProvider(
        X509Certificate2 signerCertificate,
        [System.Diagnostics.CodeAnalysis.NotNullWhen(true)] out Rfc3161HttpTimestampProvider? provider,
        HttpClient? httpClient = null)
    {
        if (!TryGetResponderUri(signerCertificate, out var uri))
        {
            provider = null;
            return false;
        }

        provider = new Rfc3161HttpTimestampProvider(uri, httpClient);
        return true;
    }

    /// <summary>
    /// Same as <see cref="TryCreateHttpProvider"/> but throws when no route exists for <paramref name="signerCertificate"/>.
    /// </summary>
    public Rfc3161HttpTimestampProvider CreateHttpProviderOrThrow(X509Certificate2 signerCertificate, HttpClient? httpClient = null)
    {
        ArgumentNullException.ThrowIfNull(signerCertificate);
        if (!TryCreateHttpProvider(signerCertificate, out var provider, httpClient) || provider is null)
        {
            throw new InvalidOperationException(
                "No RFC 3161 TSP HTTP endpoint registered for this signer certificate (try issuer or end-entity SHA-1 thumbprint routes). "
                + $"Signer thumbprint: {signerCertificate.Thumbprint}. "
                + $"Use {nameof(RegisterByIssuerThumbprint)} / {nameof(RegisterByEndEntityThumbprint)}, or call "
                + $"{nameof(TimestampResponderRegistry)}.{nameof(RegisterFrom)}({nameof(EdocLibConfig)}.{nameof(EdocLibConfig.Default)}).");
        }

        return provider;
    }

    private static bool TryGetIssuerThumbprint(X509Certificate2 leaf, out string normalizedIssuerThumbprint)
    {
        normalizedIssuerThumbprint = string.Empty;
        try
        {
            using var chain = new X509Chain();
            chain.ChainPolicy.RevocationMode = X509RevocationMode.NoCheck;
            chain.ChainPolicy.VerificationFlags = X509VerificationFlags.AllowUnknownCertificateAuthority;
            if (!chain.Build(leaf) || chain.ChainElements.Count < 2)
            {
                return false;
            }

            normalizedIssuerThumbprint = NormalizeHex(chain.ChainElements[1].Certificate.Thumbprint);
            return true;
        }
        catch (CryptographicException)
        {
            return false;
        }
    }

    /// <summary>Normalizes hex.</summary>
    private static string NormalizeHex(string thumbprint)
    {
        var s = thumbprint.Replace(" ", "", StringComparison.Ordinal).Replace(":", "", StringComparison.Ordinal);
        return s.ToUpperInvariant();
    }
}
