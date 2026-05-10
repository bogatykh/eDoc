using System.Security.Cryptography.X509Certificates;
using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.Asn1.X509.Qualified;
using Org.BouncyCastle.X509;

namespace eDocLib.Validation;

/// <summary>
/// Reads ETSI / PKIX <c>qcStatements</c> (OID 1.3.6.1.5.5.7.1.3) for reporting heuristics when TSL data is absent.
/// Does not replace legal qualification from national trusted lists — combine with TSL-based mapping when available.
/// </summary>
internal static class SignerCertificateQualificationHeuristics
{
    /// <summary>id-pe-qcStatements (RFC 3739).</summary>
    public const string QcStatementsExtensionOid = "1.3.6.1.5.5.7.1.3";

    /// <summary>ETSI id-etsi-qcs-QcCompliance.</summary>
    public const string EtsiQcsQcCompliance = "0.4.0.1862.1.1";

    /// <summary>ETSI id-etsi-qcs-QcSSCD.</summary>
    public const string EtsiQcsQcSscd = "0.4.0.1862.1.4";

    /// <summary>ETSI id-etsi-qct-esign.</summary>
    public const string EtsiQctEsign = "0.4.0.1862.1.6.1";

    /// <summary>ETSI id-etsi-qct-eseal.</summary>
    public const string EtsiQctEseal = "0.4.0.1862.1.6.2";

    /// <summary>Flags derived from recognised statement <c>statementId</c> OIDs inside <c>qcStatements</c>.</summary>
    public readonly record struct EtsiQcStatementFlags(
        bool QcCompliance,
        bool QcSscd,
        bool Esign,
        bool Eseal);

    /// <summary>
    /// Parses the signing certificate for ETSI QC statement IDs we care about.
    /// Returns <c>false</c> when the extension is missing or cannot be parsed.
    /// </summary>
    public static bool TryReadEtsiQcStatements(X509Certificate2 cert, out EtsiQcStatementFlags flags)
    {
        flags = default;
        if (cert is null || cert.RawData.Length == 0)
        {
            return false;
        }

        try
        {
            var bc = new X509CertificateParser().ReadCertificate(cert.RawData);
            var qcOid = new DerObjectIdentifier(QcStatementsExtensionOid);
            var extVal = bc.GetExtensionValue(qcOid);
            if (extVal is null)
            {
                return false;
            }

            var octets = Asn1OctetString.GetInstance(extVal);
            var seq = Asn1Sequence.GetInstance(octets.GetOctets());
            var any = false;
            var compliance = false;
            var sscd = false;
            var esign = false;
            var eseal = false;

            foreach (var el in seq)
            {
                var stmt = QCStatement.GetInstance(el);
                var id = stmt.StatementId?.Id;
                if (string.IsNullOrEmpty(id))
                {
                    continue;
                }

                any = true;
                if (string.Equals(id, EtsiQcsQcCompliance, StringComparison.Ordinal))
                {
                    compliance = true;
                }
                else if (string.Equals(id, EtsiQcsQcSscd, StringComparison.Ordinal))
                {
                    sscd = true;
                }
                else if (string.Equals(id, EtsiQctEsign, StringComparison.Ordinal))
                {
                    esign = true;
                }
                else if (string.Equals(id, EtsiQctEseal, StringComparison.Ordinal))
                {
                    eseal = true;
                }
            }

            if (!any)
            {
                return false;
            }

            flags = new EtsiQcStatementFlags(compliance, sscd, esign, eseal);
            return true;
        }
        catch (InvalidCastException)
        {
            return false;
        }
        catch (ArgumentException)
        {
            return false;
        }
    }
}
