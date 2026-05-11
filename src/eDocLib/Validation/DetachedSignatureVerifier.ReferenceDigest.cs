using System.IO;
using System.Security.Cryptography;
using System.Security.Cryptography.Xml;
using System.Xml;

namespace eDocLib.Validation;

internal static partial class DetachedSignatureVerifier
{
    /// <summary>
    /// Attempts to verify a single <c>ds:Reference</c> against the supplied payload source.
    /// </summary>
    /// <remarks>
    /// Hashes the payload incrementally from the stream when the reference has no XML transform chain;
    /// for references with transforms, buffers the payload (the transform API requires an in-memory representation).
    /// </remarks>
    private static bool TryVerifyReference(
        Reference reference,
        XmlDocument document,
        IValidationPayloadSource payloadSource,
        out string? error)
    {
        error = null;
        var uri = reference.Uri ?? string.Empty;

        using var hashAlg = CreateHashAlgorithm(reference.DigestMethod);
        var expected = GetDigestBytes(reference);

        byte[] actual;
        if (uri.StartsWith("#", StringComparison.Ordinal))
        {
            var id = uri[1..];
            var target = FindElementById(document, id);
            if (target == null)
            {
                error = $"Could not resolve reference URI '{uri}'.";
                return false;
            }

            var bytes = ApplyTransforms(reference, target);
            actual = hashAlg.ComputeHash(bytes);
        }
        else
        {
            if (!payloadSource.TryOpen(uri, out var payloadStream))
            {
                error = $"Missing payload for reference URI '{uri}'.";
                return false;
            }

            if (reference.TransformChain.Count == 0)
            {
                actual = hashAlg.ComputeHash(payloadStream);
            }
            else
            {
                var buffered = ReadAllBytes(payloadStream);
                var transformed = ApplyTransforms(reference, buffered);
                actual = hashAlg.ComputeHash(transformed);
            }
        }

        if (!CryptographicOperations.FixedTimeEquals(actual, expected))
        {
            error = $"Digest mismatch for reference URI '{uri}'.";
            return false;
        }

        return true;
    }

    private static byte[] ReadAllBytes(Stream stream)
    {
        if (stream is MemoryStream ms && ms.TryGetBuffer(out var seg) && seg.Offset == 0 && seg.Count == ms.Length)
        {
            return seg.Array!.Length == seg.Count ? seg.Array! : ms.ToArray();
        }

        using var copy = new MemoryStream();
        stream.CopyTo(copy);
        return copy.ToArray();
    }

    /// <summary>Runs the reference transform chain for an in-document element and returns octets to digest.</summary>
    private static byte[] ApplyTransforms(Reference reference, XmlElement element)
    {
        if (reference.TransformChain.Count == 0)
        {
            return CanonicalizeElementExcC14N(element);
        }

        var current = (object)WrapInOwnDocument(element);
        foreach (Transform transform in reference.TransformChain)
        {
            transform.LoadInput(current);
            current = transform.GetOutput(typeof(Stream)) ?? transform.GetOutput(typeof(XmlDocument))!;
            if (current is Stream s)
            {
                using var ms = new MemoryStream();
                s.CopyTo(ms);
                current = ms.ToArray();
            }
        }

        return current switch
        {
            byte[] b => b,
            XmlDocument d => CanonicalizeElementExcC14N(d.DocumentElement!),
            XmlElement e => CanonicalizeElementExcC14N(e),
            _ => throw new NotSupportedException("Transform output type is not supported."),
        };
    }

    /// <summary>Runs the reference transform chain over a detached binary payload and returns octets to digest.</summary>
    private static byte[] ApplyTransforms(Reference reference, byte[] payload)
    {
        if (reference.TransformChain.Count == 0)
        {
            return payload;
        }

        object current = payload;
        foreach (Transform transform in reference.TransformChain)
        {
            transform.LoadInput(current);
            var output = transform.GetOutput(typeof(Stream));
            if (output is not Stream stream)
            {
                throw new NotSupportedException("Transform chain over binary payload must yield a stream.");
            }

            using var ms = new MemoryStream();
            stream.CopyTo(ms);
            current = ms.ToArray();
        }

        return (byte[])current;
    }
}
