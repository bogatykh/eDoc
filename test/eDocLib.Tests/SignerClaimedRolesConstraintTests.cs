using System;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Threading.Tasks;
using eDocLib.Asic.Xades;
using eDocLib.Validation;
using Xunit;

namespace eDocLib.Tests;

/// <summary>
/// Edge-case coverage for signer-role constraints: <see cref="SignatureTrustPolicy.HasSignerClaimedRoleConstraints"/>
/// boolean logic, allow-list trim / case sensitivity, "empty allow-list" semantics (passes by design), and the
/// indication mapping (constraint failure → Indeterminate, not TotalFailed).
/// </summary>
public class SignerClaimedRolesConstraintTests
{
    [Fact]
    public void HasSignerClaimedRoleConstraints_is_false_for_default_policy()
    {
        Assert.False(new SignatureTrustPolicy().HasSignerClaimedRoleConstraints);
    }

    [Fact]
    public void HasSignerClaimedRoleConstraints_is_true_when_RequireAtLeastOneSignerClaimedRole_set()
    {
        var policy = new SignatureTrustPolicy { RequireAtLeastOneSignerClaimedRole = true };
        Assert.True(policy.HasSignerClaimedRoleConstraints);
    }

    [Fact]
    public void HasSignerClaimedRoleConstraints_is_true_when_allow_list_has_meaningful_entry()
    {
        var policy = new SignatureTrustPolicy
        {
            SignerClaimedRoleAllowList = new[] { "Author" },
        };
        Assert.True(policy.HasSignerClaimedRoleConstraints);
    }

    [Fact]
    public void HasSignerClaimedRoleConstraints_is_false_for_whitespace_only_allow_list()
    {
        // Regression: callers might pass a config-driven array that ended up with whitespace strings.
        // The "constraints" flag must not pretend a constraint exists when there's nothing to enforce —
        // otherwise StampSlice would set SignerClaimedRolesConstraintOk=true with no actual check performed.
        var policy = new SignatureTrustPolicy
        {
            SignerClaimedRoleAllowList = new[] { "   ", "\t", string.Empty },
        };
        Assert.False(policy.HasSignerClaimedRoleConstraints);
    }

    [Fact]
    public void HasSignerClaimedRoleConstraints_is_false_for_empty_allow_list()
    {
        var policy = new SignatureTrustPolicy
        {
            SignerClaimedRoleAllowList = Array.Empty<string>(),
        };
        Assert.False(policy.HasSignerClaimedRoleConstraints);
    }

    [Fact]
    public async Task ValidateAsync_rejects_role_outside_allow_list()
    {
        // Crypto verifies → role check fires after → result is "References valid, Success=false" → Indeterminate.
        var (sig, payload) = await SignBesWithRolesAsync("UnauthorisedRole");
        var policy = new SignatureTrustPolicy
        {
            SignerClaimedRoleAllowList = new[] { "Author", "Reviewer" },
        };

        var result = await SignatureValidator.ValidateAsync(
            sig,
            new System.Collections.Generic.Dictionary<string, byte[]> { ["doc.txt"] = payload },
            policy);

        Assert.False(result.Success);
        Assert.True(result.ReferencesAndSignatureValid);
        Assert.False(result.SignerClaimedRolesConstraintOk);
        Assert.Equal(SignatureValidationIndication.Indeterminate, result.GetIndication());
        Assert.Contains("not allowed", result.Error ?? string.Empty, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public async Task ValidateAsync_accepts_role_in_allow_list_after_trimming_both_sides()
    {
        // Allow list entries get trimmed before comparison; signer roles likewise come through trimmed
        // (XadesSignature.ParseSignerRoles already strips whitespace). Confirms the symmetry.
        var (sig, payload) = await SignBesWithRolesAsync("  Author  ");
        var policy = new SignatureTrustPolicy
        {
            SignerClaimedRoleAllowList = new[] { "  Author  ", "Reviewer" },
        };
        var result = await SignatureValidator.ValidateAsync(
            sig,
            new System.Collections.Generic.Dictionary<string, byte[]> { ["doc.txt"] = payload },
            policy);

        Assert.True(result.Success);
        Assert.True(result.SignerClaimedRolesConstraintOk);
    }

    [Fact]
    public async Task ValidateAsync_treats_role_match_as_case_sensitive_ordinal()
    {
        // Documents the deliberate Ordinal comparison: "author" != "Author". Callers who want case-insensitive
        // matching need to normalize the allow list (or the signer's input) themselves.
        var (sig, payload) = await SignBesWithRolesAsync("author");
        var policy = new SignatureTrustPolicy
        {
            SignerClaimedRoleAllowList = new[] { "Author" },
        };
        var result = await SignatureValidator.ValidateAsync(
            sig,
            new System.Collections.Generic.Dictionary<string, byte[]> { ["doc.txt"] = payload },
            policy);

        Assert.False(result.Success);
        Assert.False(result.SignerClaimedRolesConstraintOk);
    }

    [Fact]
    public async Task ValidateAsync_with_whitespace_only_allow_list_does_not_block_any_role()
    {
        // The role check treats a whitespace-only allow-list as "no constraint" (matches HasSignerClaimedRoleConstraints).
        // Any role passes; this is the documented "empty allow-list = unconstrained" semantics.
        var (sig, payload) = await SignBesWithRolesAsync("Whatever");
        var policy = new SignatureTrustPolicy
        {
            SignerClaimedRoleAllowList = new[] { "   ", "\t" },
        };
        var result = await SignatureValidator.ValidateAsync(
            sig,
            new System.Collections.Generic.Dictionary<string, byte[]> { ["doc.txt"] = payload },
            policy);
        Assert.True(result.Success);
        Assert.Null(result.SignerClaimedRolesConstraintOk); // No constraint → field stays null.
    }

    [Fact]
    public async Task ValidateAsync_RequireAtLeastOneSignerClaimedRole_fails_when_signer_has_no_role()
    {
        var (sig, payload) = await SignBesWithRolesAsync(/* no roles */);
        var policy = new SignatureTrustPolicy { RequireAtLeastOneSignerClaimedRole = true };
        var result = await SignatureValidator.ValidateAsync(
            sig,
            new System.Collections.Generic.Dictionary<string, byte[]> { ["doc.txt"] = payload },
            policy);

        Assert.False(result.Success);
        Assert.False(result.SignerClaimedRolesConstraintOk);
        Assert.Equal(SignatureValidationIndication.Indeterminate, result.GetIndication());
    }

    [Fact]
    public async Task ValidateAsync_RequireAtLeastOneSignerClaimedRole_passes_when_signer_has_any_role()
    {
        var (sig, payload) = await SignBesWithRolesAsync("Author");
        var policy = new SignatureTrustPolicy { RequireAtLeastOneSignerClaimedRole = true };
        var result = await SignatureValidator.ValidateAsync(
            sig,
            new System.Collections.Generic.Dictionary<string, byte[]> { ["doc.txt"] = payload },
            policy);

        Assert.True(result.Success);
        Assert.True(result.SignerClaimedRolesConstraintOk);
    }

    [Fact]
    public async Task ValidateAsync_RequireAtLeastOneSignerClaimedRole_paired_with_allow_list_enforces_both()
    {
        // Combined constraints: signer must have any role AND that role must be in the allow list.
        var (sigBad, payload1) = await SignBesWithRolesAsync(/* no roles */);
        var policy = new SignatureTrustPolicy
        {
            RequireAtLeastOneSignerClaimedRole = true,
            SignerClaimedRoleAllowList = new[] { "Author" },
        };
        var bad = await SignatureValidator.ValidateAsync(
            sigBad,
            new System.Collections.Generic.Dictionary<string, byte[]> { ["doc.txt"] = payload1 },
            policy);
        Assert.False(bad.Success);

        var (sigGood, payload2) = await SignBesWithRolesAsync("Author");
        var good = await SignatureValidator.ValidateAsync(
            sigGood,
            new System.Collections.Generic.Dictionary<string, byte[]> { ["doc.txt"] = payload2 },
            policy);
        Assert.True(good.Success);
    }

    private static async Task<(XadesSignature Signature, byte[] Payload)> SignBesWithRolesAsync(params string[] roles)
    {
        using var rsa = RSA.Create(2048);
        var req = new CertificateRequest("CN=roles-test", rsa, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        using var cert = req.CreateSelfSigned(DateTimeOffset.UtcNow.AddDays(-1), DateTimeOffset.UtcNow.AddYears(1));
        var payload = System.Text.Encoding.UTF8.GetBytes("role-payload");
        var dfs = new[] { new DataFile(new MemoryStream(payload.ToArray()), "doc.txt", "text/plain") };
        var sig = XadesBesSigner.Sign(dfs, cert, DateTimeOffset.UtcNow, signerRoles: roles.Length == 0 ? null : roles);
        await Task.CompletedTask;
        return (sig, payload);
    }
}
