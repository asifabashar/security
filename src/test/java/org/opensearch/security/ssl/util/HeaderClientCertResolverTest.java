/*
 * SPDX-License-Identifier: Apache-2.0
 *
 * The OpenSearch Contributors require contributions made to
 * this file be licensed under the Apache-2.0 license or a
 * compatible open source license.
 */

package org.opensearch.security.ssl.util;

import java.io.FileInputStream;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.Collections;
import java.util.List;
import java.util.Map;

import org.junit.Test;

import org.opensearch.common.settings.Settings;
import org.opensearch.security.filter.SecurityRequest;
import org.opensearch.security.ssl.transport.DefaultPrincipalExtractor;
import org.opensearch.security.ssl.transport.PrincipalExtractor;
import org.opensearch.security.test.helper.file.FileHelper;
import org.opensearch.security.util.FakeRestRequest;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.is;
import static org.hamcrest.Matchers.nullValue;

public class HeaderClientCertResolverTest {

    private static final String PROXY_PRINCIPAL = "CN=spock,OU=client,O=client,L=Test,C=DE";
    private static final String KIRK_PRINCIPAL = "CN=kirk,OU=client,O=client,L=Test,C=DE";
    private static final PrincipalExtractor EXTRACTOR = new DefaultPrincipalExtractor();

    private static X509Certificate[] loadCert(String classpathResource) throws Exception {
        try (FileInputStream fis = new FileInputStream(FileHelper.getAbsoluteFilePathFromClassPath(classpathResource).toFile())) {
            return new X509Certificate[] { (X509Certificate) CertificateFactory.getInstance("X.509").generateCertificate(fis) };
        }
    }

    private static String encodedPem(String classpathResource) throws Exception {
        String pem = Files.readString(FileHelper.getAbsoluteFilePathFromClassPath(classpathResource), StandardCharsets.UTF_8);
        return URLEncoder.encode(pem, StandardCharsets.UTF_8);
    }

    private static SecurityRequest requestWithHeader(String name, String value) {
        return new FakeRestRequest(Map.of(name, value), Collections.emptyMap()).asSecurityRequest();
    }

    private static Settings enabledSettings() {
        return Settings.builder()
            .put(SSLConfigConstants.SECURITY_SSL_HTTP_USE_HEADER_CERT, true)
            .putList(SSLConfigConstants.SECURITY_SSL_HTTP_HEADER_CERT_ALLOWED_PROXY_PRINCIPLE, List.of(PROXY_PRINCIPAL))
            .build();
    }

    private static SSLRequestHelper.SSLInfo resolve(
        Settings settings,
        SecurityRequest request,
        X509Certificate[] certs,
        PrincipalExtractor extractor
    ) {
        return HeaderClientCertResolver.maybeOverride(settings, request, certs, PROXY_PRINCIPAL, extractor, "TLSv1.3", "cipher", null);
    }

    @Test
    public void headerCertReplacesHandshakeCertForAllowedProxy() throws Exception {
        X509Certificate[] proxyCerts = loadCert("ssl/spock.crt.pem");
        SecurityRequest request = requestWithHeader("x-client-cert", encodedPem("ssl/kirk.crt.pem"));

        SSLRequestHelper.SSLInfo info = resolve(enabledSettings(), request, proxyCerts, EXTRACTOR);

        assertThat(info.getPrincipal(), is(KIRK_PRINCIPAL));
        assertThat(info.getX509Certs().length, is(1));
        assertThat(info.getX509Certs()[0].getSubjectX500Principal().getName(), is(KIRK_PRINCIPAL));
    }

    @Test
    public void customHeaderNameIsHonored() throws Exception {
        X509Certificate[] proxyCerts = loadCert("ssl/spock.crt.pem");
        Settings settings = Settings.builder()
            .put(enabledSettings())
            .put(SSLConfigConstants.SECURITY_SSL_HTTP_HEADER_CERT_NAME, "x-forwarded-client-cert")
            .build();
        SecurityRequest request = requestWithHeader("x-forwarded-client-cert", encodedPem("ssl/kirk.crt.pem"));

        SSLRequestHelper.SSLInfo info = resolve(settings, request, proxyCerts, EXTRACTOR);

        assertThat(info.getPrincipal(), is(KIRK_PRINCIPAL));
    }

    @Test
    public void nullPrincipalExtractorYieldsNullPrincipal() throws Exception {
        X509Certificate[] proxyCerts = loadCert("ssl/spock.crt.pem");
        SecurityRequest request = requestWithHeader("x-client-cert", encodedPem("ssl/kirk.crt.pem"));

        SSLRequestHelper.SSLInfo info = resolve(enabledSettings(), request, proxyCerts, null);

        assertThat(info.getPrincipal(), nullValue());
        assertThat(info.getX509Certs()[0].getSubjectX500Principal().getName(), is(KIRK_PRINCIPAL));
    }

    @Test
    public void invalidHeaderCertKeepsHandshakeCert() throws Exception {
        X509Certificate[] proxyCerts = loadCert("ssl/spock.crt.pem");
        SecurityRequest request = requestWithHeader("x-client-cert", "not-a-certificate");

        SSLRequestHelper.SSLInfo info = resolve(enabledSettings(), request, proxyCerts, EXTRACTOR);

        assertThat(info.getPrincipal(), is(PROXY_PRINCIPAL));
        assertThat(info.getX509Certs(), is(proxyCerts));
    }

    @Test
    public void principalNotAllowedKeepsHandshakeCert() throws Exception {
        X509Certificate[] proxyCerts = loadCert("ssl/spock.crt.pem");
        Settings settings = Settings.builder()
            .put(SSLConfigConstants.SECURITY_SSL_HTTP_USE_HEADER_CERT, true)
            .putList(SSLConfigConstants.SECURITY_SSL_HTTP_HEADER_CERT_ALLOWED_PROXY_PRINCIPLE, List.of("CN=someone-else"))
            .build();
        SecurityRequest request = requestWithHeader("x-client-cert", encodedPem("ssl/kirk.crt.pem"));

        SSLRequestHelper.SSLInfo info = resolve(settings, request, proxyCerts, EXTRACTOR);

        assertThat(info.getPrincipal(), is(PROXY_PRINCIPAL));
        assertThat(info.getX509Certs(), is(proxyCerts));
    }

    @Test
    public void featureDisabledKeepsHandshakeCert() throws Exception {
        X509Certificate[] proxyCerts = loadCert("ssl/spock.crt.pem");
        Settings settings = Settings.builder()
            .putList(SSLConfigConstants.SECURITY_SSL_HTTP_HEADER_CERT_ALLOWED_PROXY_PRINCIPLE, List.of(PROXY_PRINCIPAL))
            .build();
        SecurityRequest request = requestWithHeader("x-client-cert", encodedPem("ssl/kirk.crt.pem"));

        SSLRequestHelper.SSLInfo info = resolve(settings, request, proxyCerts, EXTRACTOR);

        assertThat(info.getPrincipal(), is(PROXY_PRINCIPAL));
        assertThat(info.getX509Certs(), is(proxyCerts));
    }

    @Test
    public void missingHeaderKeepsHandshakeCert() throws Exception {
        X509Certificate[] proxyCerts = loadCert("ssl/spock.crt.pem");
        SecurityRequest request = new FakeRestRequest(Collections.emptyMap(), Collections.emptyMap()).asSecurityRequest();

        SSLRequestHelper.SSLInfo info = resolve(enabledSettings(), request, proxyCerts, EXTRACTOR);

        assertThat(info.getPrincipal(), is(PROXY_PRINCIPAL));
        assertThat(info.getX509Certs(), is(proxyCerts));
    }

    @Test
    public void noHandshakeCertIgnoresHeader() throws Exception {
        SecurityRequest request = requestWithHeader("x-client-cert", encodedPem("ssl/kirk.crt.pem"));

        SSLRequestHelper.SSLInfo info = resolve(enabledSettings(), request, null, EXTRACTOR);

        assertThat(info.getPrincipal(), is(PROXY_PRINCIPAL));
        assertThat(info.getX509Certs(), nullValue());
    }
}
