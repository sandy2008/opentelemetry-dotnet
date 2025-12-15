// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

#if NET

using System.Security.Cryptography.X509Certificates;

namespace OpenTelemetry.Exporter.OpenTelemetryProtocol.Implementation;

/// <summary>
/// Factory for creating HttpClient instances configured with TLS and optional mTLS settings.
/// </summary>
internal static class OtlpTlsHttpClientFactory
{
    /// <summary>
    /// Creates an HttpClient configured with TLS and optional mTLS settings.
    /// </summary>
    /// <param name="tlsOptions">The TLS configuration options.</param>
    /// <param name="mtlsOptions">The mTLS client certificate configuration options.</param>
    /// <param name="configureClient">Optional action to configure the client.</param>
    /// <returns>An HttpClient configured for TLS/mTLS.</returns>
    /// <exception cref="InvalidOperationException">Thrown when neither TLS nor mTLS is enabled.</exception>
    public static HttpClient CreateHttpClient(
        OtlpTlsOptions? tlsOptions,
        OtlpMtlsOptions? mtlsOptions,
        Action<HttpClient>? configureClient = null)
    {
        if (tlsOptions?.IsEnabled != true && mtlsOptions?.IsEnabled != true)
        {
            throw new InvalidOperationException(
                "TLS options must include a trusted CA certificate path or a client certificate path.");
        }

        HttpClientHandler? handler = null;
        IHttpClientSecurityConfigurer? configurer = null;

        try
        {
            configurer = OtlpHttpClientSecurityConfigurerFactory.Create(tlsOptions, mtlsOptions);
            if (configurer == null)
            {
                throw new InvalidOperationException(
                    "TLS options must include a trusted CA certificate path or a client certificate path.");
            }

            // Create HttpClientHandler with TLS/mTLS configuration
#pragma warning disable CA2000 // Dispose objects before losing scope - HttpClientHandler is disposed by HttpClient
#pragma warning disable CA5399 // CheckCertificateRevocationList is enabled in TlsHttpClientHandler constructor
            handler = new TlsHttpClientHandler();
#pragma warning restore CA5399
#pragma warning restore CA2000
            configurer.Apply(handler);

            var client = new HttpClient(handler, disposeHandler: true);

            configureClient?.Invoke(client);

            return client;
        }
        catch (Exception ex)
        {
            // Dispose handler if something went wrong
            handler?.Dispose();

            OpenTelemetryProtocolExporterEventSource.Log.MtlsHttpClientCreationFailed(ex);
            throw;
        }
    }

    internal sealed class TlsHttpClientHandler : HttpClientHandler
    {
        private X509Certificate2? caCertificate;
        private X509Certificate2? clientCertificate;

        internal TlsHttpClientHandler()
        {
            this.CheckCertificateRevocationList = true;
        }

        internal void ConfigureClientCertificate(X509Certificate2 clientCertificate)
        {
            ArgumentNullException.ThrowIfNull(clientCertificate);

            this.clientCertificate = clientCertificate;

            this.ClientCertificates.Add(clientCertificate);
            this.ClientCertificateOptions = ClientCertificateOption.Manual;
        }

        internal void ConfigureTrustedCaCertificate(X509Certificate2 caCertificate)
        {
            ArgumentNullException.ThrowIfNull(caCertificate);

            this.caCertificate = caCertificate;

            this.ServerCertificateCustomValidationCallback = (
                httpRequestMessage,
                cert,
                chain,
                sslPolicyErrors) =>
            {
                if (cert == null || chain == null || this.caCertificate == null)
                {
                    return false;
                }

                return OtlpCertificateManager.ValidateServerCertificate(
                    cert,
                    chain,
                    sslPolicyErrors,
                    this.caCertificate);
            };
        }

        protected override void Dispose(bool disposing)
        {
            if (disposing)
            {
                this.caCertificate?.Dispose();
                this.clientCertificate?.Dispose();
            }

            base.Dispose(disposing);
        }
    }
}

#endif
