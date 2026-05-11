namespace eDocLib;

/// <summary>Filesystem operations that swallow expected IO failures (cache eviction, temp cleanup).</summary>
internal static class IoSafe
{
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
