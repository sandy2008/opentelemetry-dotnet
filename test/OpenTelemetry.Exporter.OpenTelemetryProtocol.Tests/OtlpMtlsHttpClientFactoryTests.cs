// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

#if NET

using Xunit;

namespace OpenTelemetry.Exporter.OpenTelemetryProtocol.Tests;

public class OtlpMtlsHttpClientFactoryTests
{
    [Fact]
    public void CreateHttpClient_ReturnsHttpClient_WhenMtlsIsDisabled()
    {
        var options = new OtlpMtlsOptions(); // Disabled by default

        using var httpClient = OpenTelemetryProtocol.Implementation.OtlpMtlsHttpClientFactory.CreateMtlsHttpClient(options);

        Assert.NotNull(httpClient);
        Assert.IsType<HttpClient>(httpClient);
    }

    [Fact]
    public void CreateHttpClient_ThrowsFileNotFoundException_WhenCertificateFileDoesNotExist()
    {
        var options = new OtlpMtlsOptions { ClientCertificatePath = "/nonexistent/client.crt" };

        var exception = Assert.Throws<FileNotFoundException>(() =>
            OpenTelemetryProtocol.Implementation.OtlpMtlsHttpClientFactory.CreateMtlsHttpClient(options));

        Assert.Contains("Certificate file not found", exception.Message, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public void CreateHttpClient_ConfiguresClientCertificate_WhenValidCertificateProvided()
    {
        var tempCertFile = Path.GetTempFileName();
        try
        {
            // Create a self-signed certificate for testing
            using var cert = CreateSelfSignedCertificate();
            var certBytes = cert.Export(System.Security.Cryptography.X509Certificates.X509ContentType.Pfx);
            File.WriteAllBytes(tempCertFile, certBytes);

            var options = new OtlpMtlsOptions
            {
                ClientCertificatePath = tempCertFile,
                EnableCertificateChainValidation = false, // Ignore validation for test cert
            };

            using var httpClient = OpenTelemetryProtocol.Implementation.OtlpMtlsHttpClientFactory.CreateMtlsHttpClient(options);

            Assert.NotNull(httpClient);

            // Verify the HttpClientHandler has client certificates configured
            var handlerField = typeof(HttpClient).GetField(
                "_handler",
                System.Reflection.BindingFlags.NonPublic | System.Reflection.BindingFlags.Instance);
            if (handlerField?.GetValue(httpClient) is HttpClientHandler handler)
            {
                Assert.NotEmpty(handler.ClientCertificates);
            }
        }
        finally
        {
            if (File.Exists(tempCertFile))
            {
                File.Delete(tempCertFile);
            }
        }
    }

    [Fact]
    public void CreateHttpClient_ConfiguresServerCertificateValidation_WhenTrustedRootCertificatesProvided()
    {
        var tempTrustStoreFile = Path.GetTempFileName();
        try
        {
            // Create a self-signed certificate for testing as trusted root
            using var trustedCert = CreateSelfSignedCertificate();
            var trustedCertPem = Convert.ToBase64String(trustedCert.Export(System.Security.Cryptography.X509Certificates.X509ContentType.Cert));
            var pemContent =
                $"-----BEGIN CERTIFICATE-----\n{trustedCertPem}\n-----END CERTIFICATE-----";
            File.WriteAllText(tempTrustStoreFile, pemContent);

            var options = new OtlpMtlsOptions
            {
                CaCertificatePath = tempTrustStoreFile,
            };

            using var httpClient = OpenTelemetryProtocol.Implementation.OtlpMtlsHttpClientFactory.CreateMtlsHttpClient(options);

            Assert.NotNull(httpClient);

            // Verify the HttpClientHandler has server certificate validation configured
            var handlerField = typeof(HttpClient).GetField(
                "_handler",
                System.Reflection.BindingFlags.NonPublic | System.Reflection.BindingFlags.Instance);
            if (handlerField?.GetValue(httpClient) is HttpClientHandler handler)
            {
                Assert.NotNull(handler.ServerCertificateCustomValidationCallback);
            }
        }
        finally
        {
            if (File.Exists(tempTrustStoreFile))
            {
                File.Delete(tempTrustStoreFile);
            }
        }
    }

    [Fact]
    public void CreateMtlsHttpClient_ThrowsArgumentNullException_WhenOptionsIsNull()
    {
        var exception = Assert.Throws<ArgumentNullException>(() =>
            OpenTelemetryProtocol.Implementation.OtlpMtlsHttpClientFactory.CreateMtlsHttpClient(null!));

        Assert.Equal("mtlsOptions", exception.ParamName);
    }

    private static System.Security.Cryptography.X509Certificates.X509Certificate2 CreateSelfSignedCertificate()
    {
        using var rsa = System.Security.Cryptography.RSA.Create(2048);
        var req = new System.Security.Cryptography.X509Certificates.CertificateRequest(
            "CN=Test Certificate",
            rsa,
            System.Security.Cryptography.HashAlgorithmName.SHA256,
            System.Security.Cryptography.RSASignaturePadding.Pkcs1);

        var cert = req.CreateSelfSigned(
            DateTimeOffset.UtcNow.AddDays(-1),
            DateTimeOffset.UtcNow.AddDays(30));
        return cert;
    }
}

#endif
