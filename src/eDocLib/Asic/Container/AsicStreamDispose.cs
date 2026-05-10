using System.IO;

namespace eDocLib.Asic.Container;

/// <summary>Best-effort stream disposal — suppresses races where the stream is already disposed or an I/O handle vanished.</summary>
internal static class AsicStreamDispose
{
    /// <summary>Calls <see cref="System.IO.Stream.Dispose()"/> and ignores recoverable disposal races.</summary>
    internal static void TryDispose(Stream stream)
    {
        try
        {
            stream.Dispose();
        }
        catch (ObjectDisposedException)
        {
        }
        catch (IOException)
        {
        }
    }
}
