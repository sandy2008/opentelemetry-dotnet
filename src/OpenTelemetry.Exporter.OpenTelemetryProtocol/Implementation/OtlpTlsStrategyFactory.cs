// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

#if NET

using System.Security.Cryptography.X509Certificates;

namespace OpenTelemetry.Exporter.OpenTelemetryProtocol.Implementation;

/// <summary>
/// Factory for creating appropriate TLS handler strategies based on configuration.
/// </summary>
/// <remarks>
/// This factory implements the Factory pattern to create the appropriate
/// <see cref="IOtlpTlsHandlerStrategy"/> based on the provided configuration:
/// - <see cref="OtlpTrustedCertificateStrategy"/>: When only trusted certificate is configured (self-signed cert trust).
/// - <see cref="OtlpMtlsStrategy"/>: When client certificate is configured (mutual TLS authentication).
/// </remarks>
internal static class OtlpTlsStrategyFactory
{
    /// <summary>
    /// Creates an appropriate TLS handler strategy based on the provided options.
    /// </summary>
    /// <param name="tlsOptions">The TLS configuration options.</param>
    /// <returns>An appropriate <see cref="IOtlpTlsHandlerStrategy"/> for the configuration.</returns>
    /// <exception cref="ArgumentNullException">Thrown when <paramref name="tlsOptions"/> is null.</exception>
    /// <exception cref="InvalidOperationException">Thrown when TLS is not enabled.</exception>
    public static IOtlpTlsHandlerStrategy CreateStrategy(OtlpTlsOptions tlsOptions)
    {
        ArgumentNullException.ThrowIfNull(tlsOptions);

        if (!tlsOptions.IsTlsEnabled && !tlsOptions.IsMtlsEnabled)
        {
            throw new InvalidOperationException(
                "TLS options must include at least a trusted certificate path or client certificate path.");
        }

        X509Certificate2? trustedCertificate = null;
        X509Certificate2? clientCertificate = null;

        try
        {
            // Load trusted CA certificate if configured
            if (!string.IsNullOrEmpty(tlsOptions.TrustedCertificatePath))
            {
                trustedCertificate = OtlpCertificateManager.LoadCaCertificate(
                    tlsOptions.TrustedCertificatePath);

                if (tlsOptions.EnableCertificateChainValidation)
                {
                    OtlpCertificateManager.ValidateCertificateChain(
                        trustedCertificate,
                        OtlpCertificateManager.TrustedCertificateType);
                }
            }

            // Check if this is mTLS (has client certificate)
            if (tlsOptions is OtlpMtlsOptions mtlsOptions && mtlsOptions.IsMtlsEnabled)
            {
                // Load client certificate
                if (string.IsNullOrEmpty(mtlsOptions.ClientKeyPath))
                {
                    clientCertificate = OtlpCertificateManager.LoadClientCertificate(
                        mtlsOptions.ClientCertificatePath!,
                        null);
                }
                else
                {
                    clientCertificate = OtlpCertificateManager.LoadClientCertificate(
                        mtlsOptions.ClientCertificatePath!,
                        mtlsOptions.ClientKeyPath);
                }

                if (tlsOptions.EnableCertificateChainValidation)
                {
                    OtlpCertificateManager.ValidateCertificateChain(
                        clientCertificate,
                        OtlpCertificateManager.ClientCertificateType);
                }

                OpenTelemetryProtocolExporterEventSource.Log.MtlsConfigurationEnabled(
                    clientCertificate.Subject);

                // Create mTLS strategy (takes ownership of certificates)
                var mtlsStrategy = new OtlpMtlsStrategy(clientCertificate, trustedCertificate);

                // Null out references since strategy now owns them
                clientCertificate = null;
                trustedCertificate = null;

                return mtlsStrategy;
            }

            // Trusted certificate only - not mTLS, just server certificate trust
            if (trustedCertificate != null)
            {
                OpenTelemetryProtocolExporterEventSource.Log.TrustedCertificateConfigured(
                    trustedCertificate.Subject);

                var strategy = new OtlpTrustedCertificateStrategy(trustedCertificate);

                // Null out reference since strategy now owns it
                trustedCertificate = null;

                return strategy;
            }

            throw new InvalidOperationException(
                "Unable to create TLS strategy: no valid certificate configuration found.");
        }
        catch
        {
            // Clean up certificates on failure - these may be null if already transferred to a strategy
#pragma warning disable CA1508 // Avoid dead conditional code - certificates may be null if already transferred
            trustedCertificate?.Dispose();
            clientCertificate?.Dispose();
#pragma warning restore CA1508
            throw;
        }
    }

    /// <summary>
    /// Creates an appropriate TLS handler strategy from OtlpMtlsOptions.
    /// </summary>
    /// <param name="mtlsOptions">The mTLS configuration options.</param>
    /// <returns>An appropriate <see cref="IOtlpTlsHandlerStrategy"/> for the configuration.</returns>
    /// <remarks>
    /// This overload exists for backward compatibility with code using <see cref="OtlpMtlsOptions"/>.
    /// </remarks>
    public static IOtlpTlsHandlerStrategy CreateStrategy(OtlpMtlsOptions mtlsOptions)
    {
        return CreateStrategy((OtlpTlsOptions)mtlsOptions);
    }
}

#endif
