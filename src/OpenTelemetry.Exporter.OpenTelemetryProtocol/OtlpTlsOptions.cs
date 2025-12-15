// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

#if NET

namespace OpenTelemetry.Exporter;

internal sealed class OtlpTlsOptions
{
    /// <summary>
    /// Gets or sets the path to the CA certificate file in PEM format.
    /// </summary>
    public string? CertificatePath { get; set; }

    /// <summary>
    /// Gets or sets a value indicating whether to enable certificate chain validation.
    /// When enabled, the exporter will validate the certificate chain and reject invalid certificates.
    /// </summary>
    public bool EnableCertificateChainValidation { get; set; } = true;

    public bool IsEnabled => !string.IsNullOrWhiteSpace(this.CertificatePath);
}

#endif

