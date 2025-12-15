// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

#if NET
using System.Security.Cryptography.X509Certificates;

namespace OpenTelemetry.Exporter.OpenTelemetryProtocol.Implementation;

internal static class OtlpHttpClientSecurityConfigurerFactory
{
    public static IHttpClientSecurityConfigurer? Create(
        OtlpTlsOptions? tlsOptions,
        OtlpMtlsOptions? mtlsOptions)
    {
        IHttpClientSecurityConfigurer? trustedCertConfigurer =
            tlsOptions?.IsEnabled == true
                ? new TrustedCertConfigurer(tlsOptions)
                : null;

        IHttpClientSecurityConfigurer? clientCertConfigurer =
            mtlsOptions?.IsEnabled == true
                ? new ClientCertConfigurer(mtlsOptions)
                : null;

        if (trustedCertConfigurer == null)
        {
            return clientCertConfigurer;
        }

        if (clientCertConfigurer == null)
        {
            return trustedCertConfigurer;
        }

        return new CompositeConfigurer(trustedCertConfigurer, clientCertConfigurer);
    }

    private sealed class CompositeConfigurer : IHttpClientSecurityConfigurer
    {
        private readonly IHttpClientSecurityConfigurer first;
        private readonly IHttpClientSecurityConfigurer second;

        internal CompositeConfigurer(IHttpClientSecurityConfigurer first, IHttpClientSecurityConfigurer second)
        {
            this.first = first;
            this.second = second;
        }

        public void Apply(HttpClientHandler handler)
        {
            this.first.Apply(handler);
            this.second.Apply(handler);
        }
    }

    private sealed class TrustedCertConfigurer : IHttpClientSecurityConfigurer
    {
        private readonly OtlpTlsOptions tlsOptions;

        internal TrustedCertConfigurer(OtlpTlsOptions tlsOptions)
        {
            this.tlsOptions = tlsOptions;
        }

        public void Apply(HttpClientHandler handler)
        {
            ArgumentNullException.ThrowIfNull(handler);

            if (handler is not OtlpTlsHttpClientFactory.TlsHttpClientHandler tlsHandler)
            {
                throw new ArgumentException(
                    $"Expected handler type '{typeof(OtlpTlsHttpClientFactory.TlsHttpClientHandler)}'.",
                    nameof(handler));
            }

            X509Certificate2? caCertificate = null;
            try
            {
                caCertificate = OtlpCertificateManager.LoadCaCertificate(this.tlsOptions.CertificatePath!);

                if (this.tlsOptions.EnableCertificateChainValidation)
                {
                    OtlpCertificateManager.ValidateCertificateChain(
                        caCertificate,
                        OtlpCertificateManager.CaCertificateType);
                }

                tlsHandler.ConfigureTrustedCaCertificate(caCertificate);

                // Handler now owns the certificate and will dispose it when disposed.
                caCertificate = null;
            }
            finally
            {
                caCertificate?.Dispose();
            }
        }
    }

    private sealed class ClientCertConfigurer : IHttpClientSecurityConfigurer
    {
        private readonly OtlpMtlsOptions mtlsOptions;

        internal ClientCertConfigurer(OtlpMtlsOptions mtlsOptions)
        {
            this.mtlsOptions = mtlsOptions;
        }

        public void Apply(HttpClientHandler handler)
        {
            ArgumentNullException.ThrowIfNull(handler);

            if (handler is not OtlpTlsHttpClientFactory.TlsHttpClientHandler tlsHandler)
            {
                throw new ArgumentException(
                    $"Expected handler type '{typeof(OtlpTlsHttpClientFactory.TlsHttpClientHandler)}'.",
                    nameof(handler));
            }

            X509Certificate2? clientCertificate = null;
            try
            {
                clientCertificate = string.IsNullOrEmpty(this.mtlsOptions.ClientKeyPath)
                    ? OtlpCertificateManager.LoadClientCertificate(
                        this.mtlsOptions.ClientCertificatePath!,
                        null)
                    : OtlpCertificateManager.LoadClientCertificate(
                        this.mtlsOptions.ClientCertificatePath!,
                        this.mtlsOptions.ClientKeyPath);

                if (this.mtlsOptions.EnableCertificateChainValidation)
                {
                    OtlpCertificateManager.ValidateCertificateChain(
                        clientCertificate,
                        OtlpCertificateManager.ClientCertificateType);
                }

                OpenTelemetryProtocolExporterEventSource.Log.MtlsConfigurationEnabled(
                    clientCertificate.Subject);

                tlsHandler.ConfigureClientCertificate(clientCertificate);

                // Handler now owns the certificate and will dispose it when disposed.
                clientCertificate = null;
            }
            finally
            {
                clientCertificate?.Dispose();
            }
        }
    }
}

#endif
