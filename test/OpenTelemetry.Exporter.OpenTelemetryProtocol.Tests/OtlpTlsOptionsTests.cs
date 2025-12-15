// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

#if NET

namespace OpenTelemetry.Exporter.OpenTelemetryProtocol.Tests;

public class OtlpTlsOptionsTests
{
    [Fact]
    public void DefaultValues_AreValid()
    {
        var options = new OtlpTlsOptions();

        Assert.Null(options.CertificatePath);
        Assert.True(options.EnableCertificateChainValidation);
        Assert.False(options.IsEnabled);
    }

    [Fact]
    public void Properties_CanBeSet()
    {
        var options = new OtlpTlsOptions
        {
            CertificatePath = "/path/to/ca.crt",
            EnableCertificateChainValidation = false,
        };

        Assert.Equal("/path/to/ca.crt", options.CertificatePath);
        Assert.False(options.EnableCertificateChainValidation);
        Assert.True(options.IsEnabled);
    }

    [Theory]
    [InlineData("")]
    [InlineData("   ")]
    public void IsEnabled_ReturnsFalse_WhenCertificatePathIsEmpty(string filePath)
    {
        var options = new OtlpTlsOptions { CertificatePath = filePath };
        Assert.False(options.IsEnabled);
    }
}

#endif

