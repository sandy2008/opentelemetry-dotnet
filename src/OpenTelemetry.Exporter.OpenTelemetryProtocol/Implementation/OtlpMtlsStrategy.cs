// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

#if NET

using System.Security.Cryptography.X509Certificates;

namespace OpenTelemetry.Exporter.OpenTelemetryProtocol.Implementation;

/// <summary>
/// Strategy for configuring mutual TLS (mTLS) with client certificate authentication.
/// </summary>
/// <remarks>
/// This strategy is used when OTEL_EXPORTER_OTLP_CLIENT_CERTIFICATE is set.
/// mTLS is an authentication system in which both the client and server authenticate each other.
/// This may optionally include a trusted CA certificate for server validation.
/// </remarks>
internal sealed class OtlpMtlsStrategy : IOtlpTlsHandlerStrategy, IDisposable
{
    private readonly X509Certificate2 clientCertificate;
    private readonly X509Certificate2? trustedCertificate;
    private bool disposed;

    /// <summary>
    /// Initializes a new instance of the <see cref="OtlpMtlsStrategy"/> class.
    /// </summary>
    /// <param name="clientCertificate">The client certificate for authentication.</param>
    /// <param name="trustedCertificate">Optional trusted CA certificate for server validation.</param>
    public OtlpMtlsStrategy(
        X509Certificate2 clientCertificate,
        X509Certificate2? trustedCertificate = null)
    {
        this.clientCertificate = clientCertificate ?? throw new ArgumentNullException(nameof(clientCertificate));
        this.trustedCertificate = trustedCertificate;
    }

    /// <inheritdoc/>
    public void Configure(HttpClientHandler handler)
    {
        ArgumentNullException.ThrowIfNull(handler);

        handler.CheckCertificateRevocationList = true;

        // Configure client certificate for mutual authentication
        handler.ClientCertificates.Add(this.clientCertificate);
        handler.ClientCertificateOptions = ClientCertificateOption.Manual;

        // Optionally configure server certificate validation if trusted CA is provided
        if (this.trustedCertificate != null)
        {
            var caCert = this.trustedCertificate;
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
                    caCert);
            };
        }
    }

    /// <inheritdoc/>
    public void Dispose()
    {
        if (!this.disposed)
        {
            this.clientCertificate.Dispose();
            this.trustedCertificate?.Dispose();
            this.disposed = true;
        }
    }
}

#endif
