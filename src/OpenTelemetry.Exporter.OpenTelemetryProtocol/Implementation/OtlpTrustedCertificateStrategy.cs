// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

#if NET

using System.Security.Cryptography.X509Certificates;

namespace OpenTelemetry.Exporter.OpenTelemetryProtocol.Implementation;

/// <summary>
/// Strategy for configuring server certificate trust without client authentication.
/// </summary>
/// <remarks>
/// This strategy is used when only OTEL_EXPORTER_OTLP_CERTIFICATE is set.
/// Common use case: connecting to a server with a self-signed certificate.
/// This is NOT mTLS - it only establishes trust for the server's certificate.
/// </remarks>
internal sealed class OtlpTrustedCertificateStrategy : IOtlpTlsHandlerStrategy, IDisposable
{
    private readonly X509Certificate2 trustedCertificate;
    private bool disposed;

    /// <summary>
    /// Initializes a new instance of the <see cref="OtlpTrustedCertificateStrategy"/> class.
    /// </summary>
    /// <param name="trustedCertificate">The trusted CA certificate.</param>
    public OtlpTrustedCertificateStrategy(X509Certificate2 trustedCertificate)
    {
        this.trustedCertificate = trustedCertificate ?? throw new ArgumentNullException(nameof(trustedCertificate));
    }

    /// <inheritdoc/>
    public void Configure(HttpClientHandler handler)
    {
        ArgumentNullException.ThrowIfNull(handler);

        handler.CheckCertificateRevocationList = true;

        // Configure server certificate validation using trusted CA
        handler.ServerCertificateCustomValidationCallback = (
            httpRequestMessage,
            cert,
            chain,
            sslPolicyErrors) =>
        {
            if (cert == null || chain == null)
            {
                return false;
            }

            return OtlpCertificateManager.ValidateServerCertificate(
                cert,
                chain,
                sslPolicyErrors,
                this.trustedCertificate);
        };
    }

    /// <inheritdoc/>
    public void Dispose()
    {
        if (!this.disposed)
        {
            this.trustedCertificate.Dispose();
            this.disposed = true;
        }
    }
}

#endif
