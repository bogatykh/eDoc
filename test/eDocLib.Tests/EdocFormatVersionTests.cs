using eDocLib;
using Xunit;

namespace eDocLib.Tests;

/// <summary><see cref="Edoc.FormatVersion"/> assignment rules (setter is <c>internal</c>; tests run in friend assembly).</summary>
public class EdocFormatVersionTests
{
    [Fact]
    public void FormatVersion_empty_string_throws()
    {
        var edoc = Edoc.CreateNew();
        Assert.Throws<ArgumentException>(() => edoc.FormatVersion = "");
        Assert.Throws<ArgumentException>(() => edoc.FormatVersion = "   ");
    }

    [Fact]
    public void FormatVersion_trims_whitespace_when_non_empty()
    {
        var edoc = Edoc.CreateNew();
        edoc.FormatVersion = "  2.1  ";
        Assert.Equal("2.1", edoc.FormatVersion);
    }
}
