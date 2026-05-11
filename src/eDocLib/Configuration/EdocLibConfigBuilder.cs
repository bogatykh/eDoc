using eDocLib.Timestamp;
using eDocLib.Validation;

namespace eDocLib.Configuration;

/// <summary>
/// Fluent builder for <see cref="EdocLibConfig"/>.
/// Call <see cref="Build"/> to obtain an immutable snapshot, then use <see cref="Edoc.Open(EdocLibConfig, System.IO.Stream)"/> / <see cref="Edoc.OpenAndValidateAsync(EdocLibConfig, System.IO.Stream, SignatureTrustPolicy?, System.Threading.CancellationToken)"/>.
/// </summary>
public sealed class EdocLibConfigBuilder
{
    private string? _tslRelayUriPrefix;
    private long? _payloadMemoryThresholdBytes;
    private string? _payloadSpillTempDirectory;
    private EdocLibOnlineRevocationSettings? _onlineRevocation;
    private List<EdocLibTimestampRoute>? _timestampResponders;

    /// <summary>Runs a configuration delegate (chainable).</summary>
    public EdocLibConfigBuilder Configure(Action<EdocLibConfigBuilder> configure)
    {
        ArgumentNullException.ThrowIfNull(configure);
        configure(this);
        return this;
    }

    /// <summary>Starts a builder with empty network/TSP state (ASiC read fields unset until you set them).</summary>
    public static EdocLibConfigBuilder Create() => new();

    /// <summary>
    /// Starts a builder with the same starter TSL relay prefix and TSP route as <see cref="EdocLibConfig.Default"/>.
    /// </summary>
    public static EdocLibConfigBuilder CreateDefault()
    {
        const string defaultTslRelayUriPrefix = "https://epout.eparaksts.lv/tsl-proxy/responder?uri=";
        const string defaultTspHttpEndpoint = "https://tsa.eparaksts.lv";
        const string defaultTspIssuerThumbprintSha1Hex = "0eff893e7f5e6debb567a20ae7b3785cfb93bce9";

        return new EdocLibConfigBuilder()
            .WithTslRelayUriPrefix(defaultTslRelayUriPrefix)
            .WithOnlineRevocation(new EdocLibOnlineRevocationSettings { FetchDeltaCrlViaFreshestCdp = false })
            .WithTimestampResponders(
            [
                new EdocLibTimestampRoute
                {
                    Kind = "issuerThumbprint",
                    ThumbprintSha1Hex = defaultTspIssuerThumbprintSha1Hex,
                    HttpEndpoint = defaultTspHttpEndpoint,
                },
            ]);
    }

    /// <summary>HTTP relay prefix when fetching publication-scheme trusted lists.</summary>
    public EdocLibConfigBuilder WithTslRelayUriPrefix(string? tslRelayUriPrefix)
    {
        _tslRelayUriPrefix = tslRelayUriPrefix;
        return this;
    }

    /// <summary>Replaces the timestamp responder route list (copied on <see cref="Build"/>).</summary>
    public EdocLibConfigBuilder WithTimestampResponders(List<EdocLibTimestampRoute>? routes)
    {
        _timestampResponders = routes;
        return this;
    }

    /// <summary>
    /// Maximum uncompressed payload ZIP entry size kept in memory when opening ASiC-E; see <see cref="EdocLibConfig.PayloadMemoryThresholdBytes"/>.
    /// </summary>
    public EdocLibConfigBuilder WithPayloadMemoryThresholdBytes(long? bytes)
    {
        _payloadMemoryThresholdBytes = bytes;
        return this;
    }

    /// <summary>Directory for payload spill files when opening containers.</summary>
    public EdocLibConfigBuilder WithPayloadSpillTempDirectory(string? directory)
    {
        _payloadSpillTempDirectory = directory;
        return this;
    }

    /// <summary>Optional online-revocation hints for composing <see cref="SignatureTrustPolicy"/>.</summary>
    public EdocLibConfigBuilder WithOnlineRevocation(EdocLibOnlineRevocationSettings? settings)
    {
        _onlineRevocation = settings;
        return this;
    }

    /// <summary>Builds an immutable <see cref="EdocLibConfig"/>.</summary>
    public EdocLibConfig Build() => new(this);

    internal string? TslRelayUriPrefix => _tslRelayUriPrefix;

    internal long? PayloadMemoryThresholdBytes => _payloadMemoryThresholdBytes;

    internal string? PayloadSpillTempDirectory => _payloadSpillTempDirectory;

    internal EdocLibOnlineRevocationSettings? OnlineRevocation => _onlineRevocation;

    internal IReadOnlyList<EdocLibTimestampRoute>? SnapshotTimestampResponders() =>
        _timestampResponders is null ? null : new List<EdocLibTimestampRoute>(_timestampResponders);
}
