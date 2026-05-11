using eDocLib;
using eDocLib.Asic.Container;
using eDocLib.Validation;
using Xunit;

namespace eDocLib.Tests;

/// <summary>Committed broken containers under <c>Fixtures/bes-invalid/</c> (see <c>tools/BesInvalidFixtureGen</c>).</summary>
public class BesInvalidFixtureFileTests
{
    private static string InvalidFixturePath(string name) =>
        Path.Combine(AppContext.BaseDirectory, "Fixtures", "bes-invalid", name);

    private const string MissingHint = "Missing fixture; regenerate: dotnet run --project tools/BesInvalidFixtureGen/BesInvalidFixtureGen.csproj";

    [Fact]
    public void Wrong_first_zip_entry_rejected_on_load()
    {
        var path = InvalidFixturePath("invalid-wrong-first-entry.edoc");
        Assert.True(File.Exists(path), MissingHint);

        using var fs = File.OpenRead(path);
        var ex = Assert.Throws<AsicException>(() => new Edoc(fs));
        Assert.Contains("First ZIP entry", ex.Message, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public void Wrong_mimetype_body_rejected_on_load()
    {
        var path = InvalidFixturePath("invalid-mimetype-content.edoc");
        Assert.True(File.Exists(path), MissingHint);

        using var fs = File.OpenRead(path);
        var ex = Assert.Throws<AsicException>(() => new Edoc(fs));
        Assert.Contains("Invalid MIME type", ex.Message, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public void Manifest_ghost_path_rejected_on_load()
    {
        var path = InvalidFixturePath("invalid-manifest-ghost-file.edoc");
        Assert.True(File.Exists(path), MissingHint);

        using var fs = File.OpenRead(path);
        var ex = Assert.Throws<AsicException>(() => new Edoc(fs));
        Assert.Contains("ghost-not-in-zip.dat", ex.Message, StringComparison.OrdinalIgnoreCase);
        Assert.Contains("not present in the container", ex.Message, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public void Duplicate_payload_entry_name_rejected_on_load()
    {
        var path = InvalidFixturePath("invalid-duplicate-payload-name.edoc");
        Assert.True(File.Exists(path), MissingHint);

        using var fs = File.OpenRead(path);
        var ex = Assert.Throws<AsicException>(() => new Edoc(fs));
        Assert.Contains("Duplicate", ex.Message, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public void Truncated_zip_fails_during_read()
    {
        var path = InvalidFixturePath("invalid-truncated-zip.edoc");
        Assert.True(File.Exists(path), MissingHint);

        using var fs = File.OpenRead(path);
        Assert.ThrowsAny<Exception>(() => new Edoc(fs));
    }

    [Fact]
    public void Payload_digest_mismatch_fails_validation_not_reader()
    {
        var path = InvalidFixturePath("invalid-digest-mismatch.edoc");
        Assert.True(File.Exists(path), MissingHint);

        using var fs = File.OpenRead(path);
        var report = EdocValidation.OpenAndValidate(fs, SignatureTrustPolicy.CryptographyOnly);
        Assert.False(report.AllSignaturesValid);
        Assert.Contains(
            "Digest mismatch",
            report.Signatures[0].Result.Error ?? string.Empty,
            StringComparison.Ordinal);
    }

    [Fact]
    public void Second_mimetype_entry_with_bad_body_rejected_on_load()
    {
        var path = InvalidFixturePath("invalid-two-mimetype-entries.edoc");
        Assert.True(File.Exists(path), MissingHint);

        using var fs = File.OpenRead(path);
        var ex = Assert.Throws<AsicException>(() => new Edoc(fs));
        Assert.Contains("Duplicate", ex.Message, StringComparison.OrdinalIgnoreCase);
        Assert.Contains("mimetype", ex.Message, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public void Missing_manifest_rejected_on_load()
    {
        var path = InvalidFixturePath("invalid-missing-manifest.edoc");
        Assert.True(File.Exists(path), MissingHint);

        using var fs = File.OpenRead(path);
        var ex = Assert.Throws<AsicException>(() => new Edoc(fs));
        Assert.Contains("META-INF", ex.Message, StringComparison.OrdinalIgnoreCase);
        Assert.Contains("manifest", ex.Message, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public void Signature_uri_not_matching_zip_payload_name_fails_validation()
    {
        var path = InvalidFixturePath("invalid-signature-uri-mismatch.edoc");
        Assert.True(File.Exists(path), MissingHint);

        using var fs = File.OpenRead(path);
        var report = EdocValidation.OpenAndValidate(fs, SignatureTrustPolicy.CryptographyOnly);
        Assert.False(report.AllSignaturesValid);
        Assert.Contains(
            "wrong-uri.bin",
            report.Signatures[0].Result.Error ?? string.Empty,
            StringComparison.Ordinal);
        Assert.Contains(
            "Missing payload",
            report.Signatures[0].Result.Error ?? string.Empty,
            StringComparison.Ordinal);
    }

    [Fact]
    public void Mimetype_body_declares_asic_s_rejected_on_load_and_probe()
    {
        var path = InvalidFixturePath("invalid-mimetype-asic-s-body.edoc");
        Assert.True(File.Exists(path), MissingHint);

        using var fs = File.OpenRead(path);
        var ex = Assert.Throws<AsicException>(() => new Edoc(fs));
        Assert.Contains("Invalid MIME type", ex.Message, StringComparison.OrdinalIgnoreCase);
        Assert.Contains("asic-s", ex.Message, StringComparison.OrdinalIgnoreCase);

        fs.Position = 0;
        Assert.False(AsicContainerFormatProbe.TryDetectAsicE(fs, out var probe));
        Assert.Contains("Unexpected mimetype content", probe.RejectionReason ?? string.Empty, StringComparison.Ordinal);
        Assert.Contains("asic-s", probe.RejectionReason ?? string.Empty, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public void Payload_entry_not_listed_in_manifest_rejected_on_load()
    {
        var path = InvalidFixturePath("invalid-orphan-payload-not-in-manifest.edoc");
        Assert.True(File.Exists(path), MissingHint);

        using var fs = File.OpenRead(path);
        var ex = Assert.Throws<AsicException>(() => new Edoc(fs));
        Assert.Contains("orphan-extra.bin", ex.Message, StringComparison.OrdinalIgnoreCase);
        Assert.Contains("not listed", ex.Message, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public void Parallel_signatures_second_corrupt_first_valid_second_fails_validation()
    {
        var path = InvalidFixturePath("invalid-parallel-second-signature-corrupt.edoc");
        Assert.True(File.Exists(path), MissingHint);

        using var fs = File.OpenRead(path);
        var report = EdocValidation.OpenAndValidate(fs, SignatureTrustPolicy.CryptographyOnly);
        Assert.Equal(2, report.Signatures.Count);
        Assert.True(report.Signatures[0].Result.Success, report.Signatures[0].Result.Error);
        Assert.False(report.Signatures[1].Result.Success);
        Assert.False(string.IsNullOrEmpty(report.Signatures[1].Result.Error));
        Assert.False(report.AllSignaturesValid);
    }
}
