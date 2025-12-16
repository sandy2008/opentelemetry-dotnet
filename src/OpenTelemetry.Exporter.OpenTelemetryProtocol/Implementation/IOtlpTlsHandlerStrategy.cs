// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

#if NET

namespace OpenTelemetry.Exporter.OpenTelemetryProtocol.Implementation;

/// <summary>
/// Strategy interface for configuring TLS settings on HttpClientHandler.
/// </summary>
/// <remarks>
/// Implementations of this interface apply different TLS configurations:
/// - Server certificate trust (for self-signed certificates).
/// - Mutual TLS (client authentication).
/// </remarks>
internal interface IOtlpTlsHandlerStrategy : IDisposable
{
    /// <summary>
    /// Configures the HttpClientHandler with appropriate TLS settings.
    /// </summary>
    /// <param name="handler">The handler to configure.</param>
    void Configure(HttpClientHandler handler);
}

#endif
