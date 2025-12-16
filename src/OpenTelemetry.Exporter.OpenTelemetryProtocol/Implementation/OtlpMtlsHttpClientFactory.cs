// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

#if NET

namespace OpenTelemetry.Exporter.OpenTelemetryProtocol.Implementation;

/// <summary>
/// Factory for creating HttpClient instances configured with mTLS settings.
/// </summary>
/// <remarks>
/// This class is maintained for backward compatibility.
/// New code should use <see cref="OtlpSecureHttpClientFactory"/> directly.
/// </remarks>
[Obsolete("Use OtlpSecureHttpClientFactory.CreateSecureHttpClient instead. This class will be removed in a future version.")]
internal static class OtlpMtlsHttpClientFactory
{
    /// <summary>
    /// Creates an HttpClient configured with mTLS settings.
    /// </summary>
    /// <param name="mtlsOptions">The mTLS configuration options.</param>
    /// <param name="configureClient">Optional action to configure the client.</param>
    /// <returns>An HttpClient configured for mTLS.</returns>
    /// <exception cref="ArgumentNullException">Thrown when <paramref name="mtlsOptions"/> is null.</exception>
    /// <exception cref="InvalidOperationException">Thrown when mTLS is not enabled.</exception>
    public static HttpClient CreateMtlsHttpClient(
        OtlpMtlsOptions mtlsOptions,
        Action<HttpClient>? configureClient = null)
    {
        ArgumentNullException.ThrowIfNull(mtlsOptions);

        if (!mtlsOptions.IsEnabled)
        {
            throw new InvalidOperationException("mTLS options must include a client or CA certificate path.");
        }

        // Delegate to the new secure factory
        return OtlpSecureHttpClientFactory.CreateSecureHttpClient(mtlsOptions, configureClient);
    }
}

#endif
