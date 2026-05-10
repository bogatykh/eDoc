using System.IO;
using eDocLib;
using eDocLib.Asic.Container;
using eDocLib.Configuration;
using Xunit;

namespace eDocLib.Tests;

public class AsicContainerReaderPayloadSpillTests
{
    [Fact]
    public void Large_payload_uses_temp_file_stream_when_threshold_zero()
    {
        var payload = new byte[256];
        Random.Shared.NextBytes(payload);
        using var edoc = Edoc.CreateNew();
        edoc.AddDataFile(new MemoryStream(payload), "big.bin", "application/octet-stream");

        using var zipMs = new MemoryStream();
        edoc.Save(zipMs);
        zipMs.Position = 0;

        using var reader = new AsicContainerReader(zipMs, payloadMemoryThresholdBytes: 0);
        var result = reader.Read();
        var df = Assert.Single(result.DataFiles);
        Assert.IsAssignableFrom<FileStream>(df.Stream);
    }

    [Fact]
    public void Small_payload_stays_in_memory_with_default_threshold()
    {
        var payload = new byte[1024];
        Random.Shared.NextBytes(payload);
        using var edoc = Edoc.CreateNew();
        edoc.AddDataFile(new MemoryStream(payload), "small.bin", "application/octet-stream");

        using var zipMs = new MemoryStream();
        edoc.Save(zipMs);
        zipMs.Position = 0;

        using var reader = new AsicContainerReader(zipMs);
        var result = reader.Read();
        var df = Assert.Single(result.DataFiles);
        Assert.IsAssignableFrom<MemoryStream>(df.Stream);
    }

    [Fact]
    public void Payload_spill_uses_configured_temp_directory()
    {
        var payload = new byte[256];
        Random.Shared.NextBytes(payload);
        using var edoc = Edoc.CreateNew();
        edoc.AddDataFile(new MemoryStream(payload), "blob.bin", "application/octet-stream");

        using var zipMs = new MemoryStream();
        edoc.Save(zipMs);
        zipMs.Position = 0;

        var spillDir = Path.Combine(Path.GetTempPath(), "edoc-spill-test-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(spillDir);
        try
        {
            using var reader = new AsicContainerReader(zipMs, payloadMemoryThresholdBytes: 0, spillDir);
            var result = reader.Read();
            var df = Assert.Single(result.DataFiles);
            Assert.IsAssignableFrom<FileStream>(df.Stream);
            Assert.StartsWith(spillDir, Path.GetFullPath(((FileStream)df.Stream).Name), StringComparison.Ordinal);
        }
        finally
        {
            try
            {
                Directory.Delete(spillDir, recursive: true);
            }
            catch (IOException)
            {
            }
        }
    }

    [Fact]
    public void Edoc_open_honors_payload_spill_temp_directory_via_options()
    {
        var payload = new byte[128];
        Random.Shared.NextBytes(payload);
        using var built = Edoc.CreateNew();
        built.AddDataFile(new MemoryStream(payload), "x.bin", "application/octet-stream");

        using var zipMs = new MemoryStream();
        built.Save(zipMs);
        zipMs.Position = 0;

        var spillDir = Path.Combine(Path.GetTempPath(), "edoc-open-spill-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(spillDir);
        try
        {
            var readCfg = EdocLibConfigBuilder.Create()
                .WithPayloadMemoryThresholdBytes(0)
                .WithPayloadSpillTempDirectory(spillDir)
                .Build();
            using var opened = new Edoc(zipMs, config: readCfg);
            var df = Assert.Single(opened.DataFiles);
            Assert.IsAssignableFrom<FileStream>(df.Stream);
            Assert.StartsWith(spillDir, Path.GetFullPath(((FileStream)df.Stream).Name), StringComparison.Ordinal);
        }
        finally
        {
            try
            {
                Directory.Delete(spillDir, recursive: true);
            }
            catch (IOException)
            {
            }
        }
    }
}
