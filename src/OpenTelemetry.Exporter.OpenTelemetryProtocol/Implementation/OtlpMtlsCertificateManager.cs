// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

#if NET

using System.Net.Security;
using System.Security.Cryptography.X509Certificates;

namespace OpenTelemetry.Exporter.OpenTelemetryProtocol.Implementation;

/// <summary>
/// Manages certificate loading, validation, and security checks for mTLS connections.
/// </summary>
/// <remarks>
/// This class is maintained for backward compatibility.
/// New code should use <see cref="OtlpCertificateManager"/> directly.
/// </remarks>
[Obsolete("Use OtlpCertificateManager instead. This class will be removed in a future version.")]
internal static class OtlpMtlsCertificateManager
{
    internal const string CaCertificateType = OtlpCertificateManager.TrustedCertificateType;
    internal const string ClientCertificateType = OtlpCertificateManager.ClientCertificateType;
    internal const string ClientPrivateKeyType = OtlpCertificateManager.ClientPrivateKeyType;

    /// <summary>
    /// Loads a CA certificate from a PEM file.
    /// </summary>
    /// <param name="caCertificatePath">Path to the CA certificate file.</param>
    /// <returns>The loaded CA certificate.</returns>
    public static X509Certificate2 LoadCaCertificate(string caCertificatePath)
    {
        return OtlpCertificateManager.LoadCaCertificate(caCertificatePath);
    }

    /// <summary>
    /// Loads a client certificate from a single file or from separate certificate and key files.
    /// </summary>
    /// <param name="clientCertificatePath">Path to the client certificate file.</param>
    /// <param name="clientKeyPath">Path to the client private key file. Can be null for single-file certificates.</param>
    /// <returns>The loaded client certificate with private key.</returns>
    public static X509Certificate2 LoadClientCertificate(
        string clientCertificatePath,
        string? clientKeyPath)
    {
        return OtlpCertificateManager.LoadClientCertificate(clientCertificatePath, clientKeyPath);
    }

    /// <summary>
    /// Validates the certificate chain for a given certificate.
    /// </summary>
    /// <param name="certificate">The certificate to validate.</param>
    /// <param name="certificateType">Type description for logging.</param>
    /// <returns>True if the certificate chain is valid; otherwise, false.</returns>
    public static bool ValidateCertificateChain(
        X509Certificate2 certificate,
        string certificateType)
    {
        return OtlpCertificateManager.ValidateCertificateChain(certificate, certificateType);
    }

    /// <summary>
    /// Validates a server certificate against the provided CA certificate.
    /// </summary>
    /// <param name="serverCert">The server certificate to validate.</param>
    /// <param name="chain">The certificate chain.</param>
    /// <param name="sslPolicyErrors">The SSL policy errors.</param>
    /// <param name="caCertificate">The CA certificate to validate against.</param>
    /// <returns>True if the certificate is valid; otherwise, false.</returns>
    internal static bool ValidateServerCertificate(
        X509Certificate2 serverCert,
        X509Chain chain,
        SslPolicyErrors sslPolicyErrors,
        X509Certificate2 caCertificate)
    {
        return OtlpCertificateManager.ValidateServerCertificate(serverCert, chain, sslPolicyErrors, caCertificate);
    }
}

#endif
