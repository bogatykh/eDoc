using System.Collections.Generic;

namespace eDocLib.Validation;

/// <summary>
/// Shared helpers for merging TSL URI strings (service type / status) into case-insensitive sets.
/// </summary>
internal static class TslQualificationUriSets
{
    /// <summary>Adds trimmed non-empty strings from <paramref name="values"/> into <paramref name="target"/>.</summary>
    internal static void AddTrimmedNonEmpty(IEnumerable<string>? values, HashSet<string> target)
    {
        if (values is null)
        {
            return;
        }

        foreach (var s in values)
        {
            if (!string.IsNullOrWhiteSpace(s))
            {
                target.Add(s.Trim());
            }
        }
    }
}
