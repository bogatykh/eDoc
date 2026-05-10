using System.Net.Http;

namespace eDocLib.Revocation.Online;

/// <summary>Reads HTTP revocation bodies with a hard byte ceiling to bound memory use.</summary>
internal static class RevocationResponseBodyReader
{
    /// <summary>Copies <paramref name="content"/> into memory when total length ≤ <paramref name="maxBytes"/>.</summary>
    internal static async Task<byte[]> ReadAsByteArrayWithLimitAsync(
        HttpContent content,
        int maxBytes,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(content);
        if (maxBytes <= 0)
        {
            throw new ArgumentOutOfRangeException(nameof(maxBytes));
        }

        if (content.Headers.ContentLength is { } len && len > maxBytes)
        {
            throw new InvalidOperationException(
                $"Revocation HTTP Content-Length ({len}) exceeds the maximum allowed size ({maxBytes} bytes).");
        }

        await using var stream = await content.ReadAsStreamAsync(cancellationToken).ConfigureAwait(false);
        using var ms = new MemoryStream();
        var buffer = new byte[8192];
        var total = 0;
        while (true)
        {
            var read = await stream.ReadAsync(buffer.AsMemory(0, buffer.Length), cancellationToken).ConfigureAwait(false);
            if (read == 0)
            {
                break;
            }

            if (total + read > maxBytes)
            {
                throw new InvalidOperationException(
                    $"Revocation HTTP response exceeds the maximum allowed size ({maxBytes} bytes).");
            }

            await ms.WriteAsync(buffer.AsMemory(0, read), cancellationToken).ConfigureAwait(false);
            total += read;
        }

        return ms.ToArray();
    }
}
