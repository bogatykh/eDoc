using System.Security.Cryptography.X509Certificates;
using eDocLib.Validation;
using Xunit;

namespace eDocLib.Tests;

public class CertificatePathStatusTests
{
    [Fact]
    public void AllElementsNoError_null_or_empty_paths_yields_null()
    {
        Assert.Null(CertificatePathStatus.AllElementsNoError(null));
        Assert.Null(CertificatePathStatus.AllElementsNoError(Array.Empty<CertificateChainDiagnostic>()));
    }

    [Fact]
    public void AllElementsNoError_true_when_only_no_error_flags()
    {
        var path = new[]
        {
            new CertificateChainDiagnostic(
                0,
                "CN=a",
                "CN=a",
                "T0",
                "1",
                DateTimeOffset.UtcNow,
                DateTimeOffset.UtcNow.AddYears(1),
                new[] { new X509ChainStatus { Status = X509ChainStatusFlags.NoError } }),
        };
        Assert.True(CertificatePathStatus.AllElementsNoError(path));
    }
}
