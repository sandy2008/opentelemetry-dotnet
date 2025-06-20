// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

#if NET8_0_OR_GREATER

using System.Net.Security;
using System.Security.Cryptography.X509Certificates;

namespace OpenTelemetry.Exporter;

/// <summary>
/// Configuration options for mTLS (mutual TLS) authentication in OTLP exporters.
/// </summary>
/// <remarks>
/// This class is only available on .NET 8.0 and later versions.
/// </remarks>
internal class OtlpMtlsOptions
{
    /// <summary>
    /// Gets or sets the path to the CA certificate file in PEM format.
    /// </summary>
    public string? CaCertificatePath { get; set; }

    /// <summary>
    /// Gets or sets the path to the client certificate file in PEM format.
    /// </summary>
    public string? ClientCertificatePath { get; set; }

    /// <summary>
    /// Gets or sets the path to the client private key file in PEM format.
    /// </summary>
    public string? ClientKeyPath { get; set; }

    /// <summary>
    /// Gets or sets a value indicating whether to enable file permission checks.
    /// When enabled, the exporter will verify that certificate files have appropriate permissions.
    /// </summary>
    public bool EnableFilePermissionChecks { get; set; } = true;

    /// <summary>
    /// Gets or sets a value indicating whether to enable certificate chain validation.
    /// When enabled, the exporter will validate the certificate chain and reject invalid certificates.
    /// </summary>
    public bool EnableCertificateChainValidation { get; set; } = true;

    /// <summary>
    /// Gets or sets the server certificate validation callback.
    /// This callback is used to validate the server certificate during TLS handshake.
    /// If not set, the default certificate validation logic will be used.
    /// </summary>
    public Func<
        X509Certificate2,
        X509Chain,
        SslPolicyErrors,
        bool
    >? ServerCertificateValidationCallback
    { get; set; }

    /// <summary>
    /// Gets a value indicating whether mTLS is enabled.
    /// mTLS is considered enabled if at least the client certificate path is provided.
    /// </summary>
    public bool IsEnabled => !string.IsNullOrWhiteSpace(this.ClientCertificatePath);
}

#endif
