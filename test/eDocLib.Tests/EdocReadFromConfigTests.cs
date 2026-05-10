using System.IO;
using eDocLib;
using eDocLib.Configuration;
using Xunit;

namespace eDocLib.Tests;

public class EdocReadFromConfigTests
{
    [Fact]
    public void Edoc_Open_uses_config_payload_threshold()
    {
        var payload = new byte[128];
        Random.Shared.NextBytes(payload);
        using var built = Edoc.CreateNew();
        built.AddDataFile(new MemoryStream(payload), "p.bin", "application/octet-stream");
        using var zip = new MemoryStream();
        built.Save(zip);
        zip.Position = 0;

        var cfg = EdocLibConfigBuilder.Create().WithPayloadMemoryThresholdBytes(0).Build();
        var loaded = Edoc.Open(cfg, zip);
        var df = Assert.Single(loaded.DataFiles);
        Assert.IsAssignableFrom<FileStream>(df.Stream);
    }

    [Fact]
    public void Negative_threshold_throws()
    {
        using var zip = new MemoryStream(new byte[] { 0x50, 0x4b });
        var cfg = EdocLibConfigBuilder.Create().WithPayloadMemoryThresholdBytes(-1).Build();
        var ex = Assert.Throws<ArgumentOutOfRangeException>(() => Edoc.Open(cfg, zip));
        Assert.Contains("PayloadMemoryThresholdBytes", ex.Message, StringComparison.OrdinalIgnoreCase);
    }
}
