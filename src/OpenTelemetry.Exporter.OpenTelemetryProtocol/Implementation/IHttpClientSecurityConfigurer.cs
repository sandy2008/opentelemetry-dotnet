// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

#if NET

namespace OpenTelemetry.Exporter.OpenTelemetryProtocol.Implementation;

internal interface IHttpClientSecurityConfigurer
{
    void Apply(HttpClientHandler handler);
}

#endif
