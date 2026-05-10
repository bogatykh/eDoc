using System.IO;

namespace eDocLib.Asic.Container;

/// <summary>Normalizes optional host directories used when large ZIP payloads spill to disk.</summary>
internal static class PayloadSpillPathNormalize
{
    /// <summary>Returns a rooted full path or <c>null</c> when <paramref name="directory"/> is blank.</summary>
    internal static string? FromOptionalDirectory(string? directory)
    {
        if (string.IsNullOrWhiteSpace(directory))
        {
            return null;
        }

        return Path.GetFullPath(directory.Trim());
    }
}
