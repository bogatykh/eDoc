namespace eDocLib.Configuration;

/// <summary>
/// Immutable library configuration: TSL/TSP hints, paths, ASiC read behaviour, revocation hints.
/// Create with <see cref="EdocLibConfigBuilder"/> (or use <see cref="Default"/>). Use <see cref="Edoc.Open(EdocLibConfig, System.IO.Stream)"/> to open containers; use <see cref="eDocLib.Timestamp.TimestampResponderRegistry.RegisterFrom(EdocLibConfig)"/> for TSP routes from this snapshot.
/// </summary>
public sealed class EdocLibConfig
{
    private static readonly Lazy<EdocLibConfig> DefaultLazy = new(() => EdocLibConfigBuilder.CreateDefault().Build());

    /// <summary>
    /// Thread-safe singleton from <see cref="EdocLibConfigBuilder.CreateDefault"/>. Replace network endpoints for your environment.
    /// </summary>
    public static EdocLibConfig Default => DefaultLazy.Value;

    /// <summary>Optional HTTP relay prefix when fetching publication scheme trusted lists.</summary>
    public string? TslRelayUriPrefix { get; }

    /// <summary>Optional starter routes from certificate thumbprints to RFC 3161 HTTP endpoints.</summary>
    public IReadOnlyList<EdocLibTimestampRoute>? TimestampResponders { get; }

    /// <summary>ASiC payload memory threshold; <c>null</c> uses library default.</summary>
    public long? PayloadMemoryThresholdBytes { get; }

    /// <summary>Directory for temporary spill files when opening containers.</summary>
    public string? PayloadSpillTempDirectory { get; }

    /// <summary>Optional knobs for application-controlled online revocation.</summary>
    public EdocLibOnlineRevocationSettings? OnlineRevocation { get; }

    internal EdocLibConfig(EdocLibConfigBuilder b)
    {
        TslRelayUriPrefix = b.TslRelayUriPrefix;
        TimestampResponders = b.SnapshotTimestampResponders();
        PayloadMemoryThresholdBytes = b.PayloadMemoryThresholdBytes;
        PayloadSpillTempDirectory = b.PayloadSpillTempDirectory;
        OnlineRevocation = CloneOnlineRevocation(b.OnlineRevocation);
    }

    /// <summary>
    /// Whether hosts should set <see cref="Validation.SignatureTrustPolicy.RevocationFetchDeltaCrlViaFreshestCdp"/> when composing policy from this config.
    /// </summary>
    public static bool ResolveFetchDeltaCrlViaFreshestCdp(EdocLibConfig? config) =>
        config?.OnlineRevocation?.FetchDeltaCrlViaFreshestCdp == true;

    private static EdocLibOnlineRevocationSettings? CloneOnlineRevocation(EdocLibOnlineRevocationSettings? s) =>
        s is null ? null : new EdocLibOnlineRevocationSettings { FetchDeltaCrlViaFreshestCdp = s.FetchDeltaCrlViaFreshestCdp };
}
