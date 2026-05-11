using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using eDocLib;
using eDocLib.Validation;
using eDocLib.Asic.Xades;
using Xunit;

namespace eDocLib.Tests;

/// <summary><see cref="Edoc.Dispose"/> interaction with <see cref="Edoc.Save"/> and <see cref="Edoc.ValidateAsync"/>.</summary>
public class EdocDisposedTests
{
    [Fact]
    public void After_dispose_save_throws_ObjectDisposedException()
    {
        var edoc = Edoc.CreateNew();
        edoc.Dispose();

        Assert.Throws<ObjectDisposedException>(() => edoc.Save(new MemoryStream()));
    }

    [Fact]
    public async Task After_dispose_save_with_preflight_throws_ObjectDisposedException()
    {
        var edoc = Edoc.CreateNew();
        edoc.Dispose();

        await Assert.ThrowsAsync<ObjectDisposedException>(async () =>
                await edoc.SaveAsync(new MemoryStream(), validateSignaturesFirst: true))
            ;
    }

    [Fact]
    public async Task After_dispose_validate_throws_ObjectDisposedException()
    {
        var edoc = Edoc.CreateNew();
        edoc.Dispose();

        await Assert.ThrowsAsync<ObjectDisposedException>(() => edoc.ValidateAsync());
        await Assert.ThrowsAsync<ObjectDisposedException>(() => edoc.ValidateAsync(SignatureTrustPolicy.CryptographyOnly))
            ;
    }

    [Fact]
    public void Dispose_is_idempotent()
    {
        var edoc = Edoc.CreateNew();
        edoc.Dispose();
        edoc.Dispose();
        Assert.Throws<ObjectDisposedException>(() => edoc.Save(new MemoryStream()));
    }
}
