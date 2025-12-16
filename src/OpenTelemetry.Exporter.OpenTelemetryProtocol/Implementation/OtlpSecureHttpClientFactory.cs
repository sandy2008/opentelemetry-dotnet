// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

#if NET

namespace OpenTelemetry.Exporter.OpenTelemetryProtocol.Implementation;

/// <summary>
/// Factory for creating HttpClient instances configured with TLS settings.
/// </summary>
/// <remarks>
/// This factory uses the Strategy pattern to apply appropriate TLS configuration:
/// - Server certificate trust for self-signed certificates (non-mTLS scenario)
/// - Mutual TLS (mTLS) for client authentication.
/// </remarks>
internal static class OtlpSecureHttpClientFactory
{
    /// <summary>
    /// Creates an HttpClient configured with TLS settings based on the provided options.
    /// </summary>
    /// <param name="tlsOptions">The TLS configuration options.</param>
    /// <param name="configureClient">Optional action to configure the client.</param>
    /// <returns>An HttpClient configured for secure communication.</returns>
    /// <exception cref="ArgumentNullException">Thrown when <paramref name="tlsOptions"/> is null.</exception>
    /// <exception cref="InvalidOperationException">Thrown when TLS is not enabled.</exception>
    public static HttpClient CreateSecureHttpClient(
        OtlpTlsOptions tlsOptions,
        Action<HttpClient>? configureClient = null)
    {
        ArgumentNullException.ThrowIfNull(tlsOptions);

        IOtlpTlsHandlerStrategy? strategy = null;
        StrategyHttpClientHandler? handler = null;

        try
        {
            // Create the appropriate strategy based on configuration
            strategy = OtlpTlsStrategyFactory.CreateStrategy(tlsOptions);

            // Create HttpClientHandler and apply strategy
#pragma warning disable CA2000 // Dispose objects before losing scope - HttpClientHandler is disposed by HttpClient
            handler = new StrategyHttpClientHandler(strategy);
#pragma warning restore CA2000

            // Strategy now owned by handler
            strategy = null;

#pragma warning disable CA5399 // CheckCertificateRevocationList is set in the strategy's Configure method
            var client = new HttpClient(handler, disposeHandler: true);
#pragma warning restore CA5399

            configureClient?.Invoke(client);

            return client;
        }
        catch (Exception ex)
        {
            // Clean up on failure
            handler?.Dispose();
            strategy?.Dispose();

            OpenTelemetryProtocolExporterEventSource.Log.SecureHttpClientCreationFailed(ex);
            throw;
        }
    }

    /// <summary>
    /// Creates an HttpClient configured with mTLS settings.
    /// </summary>
    /// <param name="mtlsOptions">The mTLS configuration options.</param>
    /// <param name="configureClient">Optional action to configure the client.</param>
    /// <returns>An HttpClient configured for mTLS.</returns>
    /// <remarks>
    /// This method exists for backward compatibility. New code should use
    /// <see cref="CreateSecureHttpClient(OtlpTlsOptions, Action{HttpClient}?)"/>.
    /// </remarks>
    public static HttpClient CreateMtlsHttpClient(
        OtlpMtlsOptions mtlsOptions,
        Action<HttpClient>? configureClient = null)
    {
        return CreateSecureHttpClient(mtlsOptions, configureClient);
    }

    /// <summary>
    /// HttpClientHandler that uses a TLS strategy for configuration.
    /// </summary>
    private sealed class StrategyHttpClientHandler : HttpClientHandler
    {
        private readonly IOtlpTlsHandlerStrategy strategy;

        internal StrategyHttpClientHandler(IOtlpTlsHandlerStrategy strategy)
        {
            this.strategy = strategy ?? throw new ArgumentNullException(nameof(strategy));

            // Apply the strategy configuration
            strategy.Configure(this);
        }

        protected override void Dispose(bool disposing)
        {
            if (disposing)
            {
                this.strategy.Dispose();
            }

            base.Dispose(disposing);
        }
    }
}

#endif
