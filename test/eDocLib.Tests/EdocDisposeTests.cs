using System.IO;
using eDocLib;
using eDocLib.Configuration;
using Xunit;

namespace eDocLib.Tests;

public class EdocDisposeTests
{
    [Fact]
    public void Dispose_leaves_caller_supplied_memory_stream_open()
    {
        var payload = new byte[] { 9, 8, 7 };
        using var ms = new MemoryStream(payload);
        var edoc = Edoc.CreateNew();
        edoc.AddDataObject(ms, "x.bin", "application/octet-stream");
        edoc.Dispose();

        ms.Position = 0;
        Assert.Equal(payload.Length, ms.Read(new byte[8], 0, payload.Length));
    }

    [Fact]
    public void Dispose_closes_zip_loaded_spill_payload_stream()
    {
        var payload = new byte[64];
        Random.Shared.NextBytes(payload);
        using var built = Edoc.CreateNew();
        built.AddDataObject(new MemoryStream(payload), "p.bin", "application/octet-stream");

        using var zipMs = new MemoryStream();
        built.Save(zipMs);
        zipMs.Position = 0;

        var spillDir = Path.Combine(Path.GetTempPath(), "edoc-dispose-test-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(spillDir);
        try
        {
            var readCfg = EdocLibConfigBuilder.Create()
                .WithPayloadMemoryThresholdBytes(0)
                .WithPayloadSpillTempDirectory(spillDir)
                .Build();
            var edoc = new Edoc(zipMs, config: readCfg);
            var df = edoc.GetDataObject(0);
            Assert.IsAssignableFrom<FileStream>(df.Stream);
            edoc.Dispose();

            Assert.Throws<ObjectDisposedException>(() => df.Stream.ReadByte());
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
    public void Dispose_then_members_throw_ObjectDisposedException()
    {
        var edoc = Edoc.CreateNew();
        edoc.Dispose();
        Assert.Throws<ObjectDisposedException>(() => { _ = edoc.DataObjectCount; });
        Assert.Throws<ObjectDisposedException>(() =>
        {
            edoc.AddDataObject(new MemoryStream(), "a.txt", "text/plain");
        });
    }

    [Fact]
    public void RemoveDataObjectAt_disposes_container_owned_stream_from_zip()
    {
        var payload = new byte[32];
        Random.Shared.NextBytes(payload);
        using var built = Edoc.CreateNew();
        built.AddDataObject(new MemoryStream(payload), "z.bin", "application/octet-stream");

        using var zipMs = new MemoryStream();
        built.Save(zipMs);
        zipMs.Position = 0;

        var spillDir = Path.Combine(Path.GetTempPath(), "edoc-remove-owned-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(spillDir);
        try
        {
            var readCfg = EdocLibConfigBuilder.Create()
                .WithPayloadMemoryThresholdBytes(0)
                .WithPayloadSpillTempDirectory(spillDir)
                .Build();
            var edoc = new Edoc(zipMs, config: readCfg);
            var df = edoc.GetDataObject(0);
            var fs = Assert.IsAssignableFrom<FileStream>(df.Stream);
            edoc.RemoveDataObjectAt(0);

            Assert.Throws<ObjectDisposedException>(() => fs.ReadByte());
            Assert.Equal(0, edoc.DataObjectCount);
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
