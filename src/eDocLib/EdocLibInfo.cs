using System.Reflection;

namespace eDocLib;

/// <summary>
/// Build identity of this assembly for logging and support (values reflect MSBuild / CI metadata, not string literals in source).
/// Set version via <c>&lt;Version&gt;</c> or packaging in <c>eDocLib.csproj</c>; optional <c>InformationalVersion</c> from CI.
/// </summary>
public static class EdocLibInfo
{
    private static readonly Assembly LibAssembly = typeof(EdocLibInfo).Assembly;

    /// <summary>
    /// Prefer for diagnostics: NuGet/semver label plus optional prerelease or commit metadata when the build sets
    /// <see cref="AssemblyInformationalVersionAttribute"/> (SDK maps from <c>InformationalVersion</c> or <c>Version</c>).
    /// </summary>
    public static string InformationalVersion =>
        LibAssembly.GetCustomAttribute<AssemblyInformationalVersionAttribute>()?.InformationalVersion
        ?? AssemblyVersion;

    /// <summary><c>Major.Minor.Build.Revision</c> from <see cref="AssemblyName.Version"/>.</summary>
    public static string AssemblyVersion =>
        LibAssembly.GetName().Version?.ToString() ?? "0.0.0.0";

    /// <summary>Short assembly name (typically <c>eDocLib</c>).</summary>
    public static string AssemblyName => LibAssembly.GetName().Name ?? "eDocLib";
}
