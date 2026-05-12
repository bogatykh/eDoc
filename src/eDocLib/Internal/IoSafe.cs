using System.IO;

namespace eDocLib.Internal;

/// <summary>Filesystem operations that swallow expected IO failures (cache eviction, temp cleanup).</summary>
internal static class IoSafe
{
    /// <summary>Writes <paramref name="content"/> to <c>*.tmp</c> next to <paramref name="targetPath"/>, then replaces atomically.</summary>
    internal static async Task WriteAllBytesAtomicAsync(
        string targetPath,
        ReadOnlyMemory<byte> content,
        CancellationToken cancellationToken = default)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(targetPath);
        var tmp = targetPath + ".tmp";
        try
        {
            await using (var stream = new FileStream(
                               tmp,
                               FileMode.Create,
                               FileAccess.Write,
                               FileShare.None,
                               bufferSize: 4096,
                               FileOptions.Asynchronous))
            {
                await stream.WriteAsync(content, cancellationToken).ConfigureAwait(false);
            }

            File.Move(tmp, targetPath, overwrite: true);
        }
        catch
        {
            TryDeleteFile(tmp);
            throw;
        }
    }

    /// <summary>Deletes <paramref name="path"/>; returns <c>false</c> on <see cref="IOException"/> or <see cref="UnauthorizedAccessException"/>.</summary>
    internal static bool TryDeleteFile(string path)
    {
        try
        {
            File.Delete(path);
            return true;
        }
        catch (IOException)
        {
            return false;
        }
        catch (UnauthorizedAccessException)
        {
            return false;
        }
    }
}
