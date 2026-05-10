using eDocLib;
using Xunit;

namespace eDocLib.Tests;

/// <summary>Lightweight rules for <see cref="DataFile"/> (not ASiC-specific).</summary>
public class DataFileContractTests
{
    [Fact]
    public void MimeType_can_be_replaced_after_construction()
    {
        var ms = new MemoryStream("x"u8.ToArray());
        var df = new DataFile(ms, "a.txt", "text/plain");
        Assert.Equal("text/plain", df.MimeType);

        df.MimeType = "application/octet-stream";
        Assert.Equal("application/octet-stream", df.MimeType);
    }

    [Fact]
    public void Constructor_without_mime_defaults_to_octet_stream()
    {
        var df = new DataFile(new MemoryStream(), "b.bin");
        Assert.Equal(System.Net.Mime.MediaTypeNames.Application.Octet, df.MimeType);
    }
}
