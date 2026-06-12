/*
 * Copyright 2015-2017 floragunn GmbH
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *
 */

package org.opensearch.security.ssl.util;

import java.io.ByteArrayInputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.net.URLDecoder;
import java.nio.charset.StandardCharsets;
import java.nio.file.Path;
import java.security.KeyStore;
import java.security.cert.CRL;
import java.security.cert.Certificate;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.Arrays;
import java.util.Base64;
import java.util.Collection;
import java.util.Date;
import java.util.Map.Entry;
import javax.net.ssl.SSLEngine;
import javax.net.ssl.SSLPeerUnverifiedException;
import javax.net.ssl.SSLSession;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import org.opensearch.OpenSearchException;
import org.opensearch.common.settings.Settings;
import org.opensearch.common.util.concurrent.ThreadContext;
import org.opensearch.env.Environment;
import org.opensearch.secure_sm.AccessController;
import org.opensearch.security.filter.SecurityRequest;
import org.opensearch.security.ssl.transport.PrincipalExtractor;
import org.opensearch.security.ssl.transport.PrincipalExtractor.Type;

import static org.opensearch.security.ssl.SecureSSLSettings.SSLSetting.SECURITY_SSL_HTTP_TRUSTSTORE_PASSWORD;

public class SSLRequestHelper {

    private static final Logger log = LogManager.getLogger(SSLRequestHelper.class);

    public static class SSLInfo {
        private final X509Certificate[] x509Certs;
        private final X509Certificate[] localCertificates;
        private final String principal;
        private final String protocol;
        private final String cipher;
        private final X509Certificate[] headerCerts;
        private final String headerPrincipal;

        public SSLInfo(
            final X509Certificate[] x509Certs,
            final String principal,
            final String protocol,
            final String cipher,
            X509Certificate[] localCertificates,
            final X509Certificate[] headerCerts,
            final String headerPrincipal
        ) {
            super();
            this.x509Certs = x509Certs;
            this.principal = principal;
            this.protocol = protocol;
            this.cipher = cipher;
            this.localCertificates = localCertificates;
            this.headerCerts = headerCerts;
            this.headerPrincipal = headerPrincipal;
        }

        public X509Certificate[] getX509Certs() {
            return x509Certs == null ? null : x509Certs.clone();
        }

        public X509Certificate[] getLocalCertificates() {
            return localCertificates == null ? null : localCertificates.clone();
        }

        public String getPrincipal() {
            return principal;
        }

        public String getProtocol() {
            return protocol;
        }

        public String getCipher() {
            return cipher;
        }

        @Override
        public String toString() {
            return "SSLInfo [x509Certs="
                + Arrays.toString(x509Certs)
                + ", principal="
                + principal
                + ", protocol="
                + protocol
                + ", cipher="
                + cipher
                + "]";
        }

    }

    public static SSLInfo getSSLInfo(
        final Settings settings,
        final Path configPath,
        final SecurityRequest request,
        PrincipalExtractor principalExtractor
    ) throws SSLPeerUnverifiedException {
        final SSLEngine engine = request.getSSLEngine();
        if (engine == null) {
            return null;
        }

        final SSLSession session = engine.getSession();

        X509Certificate[] x509Certs = null;
        X509Certificate[] x509HeaderCerts = null;
        final String protocol = session.getProtocol();
        final String cipher = session.getCipherSuite();
        String principal = null;
        String headerCertPrincipal = null;
        final String clientCertHeaderName = settings.get("clientCertHeaderName", "ClientCert");
        final boolean isURLEncoded = Boolean.parseBoolean(settings.get("isURLEncoded", "true"));

        String clientCertEncoded = request.header(clientCertHeaderName);
        log.trace("Client Cert Encoded : {} ", clientCertEncoded);
        if (isURLEncoded) {
            String clientCertFromHeader = URLDecoder.decode(clientCertEncoded, StandardCharsets.UTF_8);
            byte[] decodedClientCert = Base64.getDecoder().decode(clientCertFromHeader);

            CertificateFactory factory = null;
            try {
                factory = CertificateFactory.getInstance("X.509");
                x509HeaderCerts = new X509Certificate[1];
                x509HeaderCerts[0] = (X509Certificate) factory.generateCertificate(new ByteArrayInputStream(decodedClientCert));
                headerCertPrincipal = principalExtractor == null
                    ? null
                    : principalExtractor.extractPrincipal(x509HeaderCerts[0], Type.HTTP);
            } catch (CertificateException e) {

            }

        }

        if (engine.getNeedClientAuth() || engine.getWantClientAuth()) {
            Certificate[] certs = null;
            try {
                certs = session.getPeerCertificates();
            } catch (SSLPeerUnverifiedException e) {
                // deal with 'null' certs down below
            }

            if (certs != null && certs.length > 0 && certs[0] instanceof X509Certificate) {
                x509Certs = Arrays.copyOf(certs, certs.length, X509Certificate[].class);
                validatePeerCerts(x509Certs, settings, configPath);
                principal = principalExtractor == null ? null : principalExtractor.extractPrincipal(x509Certs[0], Type.HTTP);
            } else if (engine.getNeedClientAuth()) {
                throw new OpenSearchException("No client certificates found but such are needed (SG 9).");
            }
        }

        X509Certificate[] localCerts = null;
        if (session.getLocalCertificates() != null) {
            localCerts = Arrays.stream(session.getLocalCertificates()).map(X509Certificate.class::cast).toArray(X509Certificate[]::new);
        }

        return new SSLInfo(x509Certs, principal, protocol, cipher, localCerts, x509HeaderCerts, headerCertPrincipal);
    }

    }

    public static boolean containsBadHeader(final ThreadContext context, String prefix) {
        if (context != null) {
            for (final Entry<String, String> header : context.getHeaders().entrySet()) {
                if (header != null && header.getKey() != null && header.getKey().trim().toLowerCase().startsWith(prefix)) {
                    return true;
                }
            }
        }

        return false;
    }

    private static boolean validate(X509Certificate[] x509Certs, final Settings settings, final Path configPath) {

        final boolean validateCrl = settings.getAsBoolean(SSLConfigConstants.SECURITY_SSL_HTTP_CRL_VALIDATE, false);

        final boolean isTraceEnabled = log.isTraceEnabled();
        if (isTraceEnabled) {
            log.trace("validateCrl: {}", validateCrl);
        }

        if (!validateCrl) {
            return true;
        }

        final Environment env = new Environment(settings, configPath);

        try {

            Collection<? extends CRL> crls = null;
            final String crlFile = settings.get(SSLConfigConstants.SECURITY_SSL_HTTP_CRL_FILE);

            if (crlFile != null) {
                final File crl = env.configDir().resolve(crlFile).toAbsolutePath().toFile();
                try (FileInputStream crlin = new FileInputStream(crl)) {
                    crls = CertificateFactory.getInstance("X.509").generateCRLs(crlin);
                }

                if (isTraceEnabled) {
                    log.trace("crls from file: {}", crls.size());
                }
            } else {
                if (isTraceEnabled) {
                    log.trace("no crl file configured");
                }
            }

            final String truststore = settings.get(SSLConfigConstants.SECURITY_SSL_HTTP_TRUSTSTORE_FILEPATH);
            CertificateValidator validator = null;

            if (truststore != null) {
                final String truststoreType = settings.get(SSLConfigConstants.SECURITY_SSL_HTTP_TRUSTSTORE_TYPE, "JKS");
                final String truststorePassword = SECURITY_SSL_HTTP_TRUSTSTORE_PASSWORD.getSetting(settings);
                // final String truststoreAlias = settings.get(SSLConfigConstants.SECURITY_SSL_HTTP_TRUSTSTORE_ALIAS, null);

                final KeyStore ts = KeyStore.getInstance(truststoreType);
                try (FileInputStream fin = new FileInputStream(new File(env.configDir().resolve(truststore).toAbsolutePath().toString()))) {
                    ts.load(
                        fin,
                        (truststorePassword == null || truststorePassword.length() == 0) ? null : truststorePassword.toCharArray()
                    );
                }
                validator = new CertificateValidator(ts, crls);
            } else {
                final File trustedCas = env.configDir()
                    .resolve(settings.get(SSLConfigConstants.SECURITY_SSL_HTTP_PEMTRUSTEDCAS_FILEPATH, ""))
                    .toAbsolutePath()
                    .toFile();
                try (FileInputStream trin = new FileInputStream(trustedCas)) {
                    Collection<? extends Certificate> cert = (Collection<? extends Certificate>) CertificateFactory.getInstance("X.509")
                        .generateCertificates(trin);
                    validator = new CertificateValidator(cert.toArray(new X509Certificate[0]), crls);
                }
            }

            validator.setEnableCRLDP(!settings.getAsBoolean(SSLConfigConstants.SECURITY_SSL_HTTP_CRL_DISABLE_CRLDP, false));
            validator.setEnableOCSP(!settings.getAsBoolean(SSLConfigConstants.SECURITY_SSL_HTTP_CRL_DISABLE_OCSP, false));
            validator.setCheckOnlyEndEntities(
                settings.getAsBoolean(SSLConfigConstants.SECURITY_SSL_HTTP_CRL_CHECK_ONLY_END_ENTITIES, true)
            );
            validator.setPreferCrl(settings.getAsBoolean(SSLConfigConstants.SECURITY_SSL_HTTP_CRL_PREFER_CRLFILE_OVER_OCSP, false));
            Long dateTimestamp = settings.getAsLong(SSLConfigConstants.SECURITY_SSL_HTTP_CRL_VALIDATION_DATE, null);
            if (dateTimestamp != null && dateTimestamp.longValue() < 0) {
                dateTimestamp = null;
            }
            validator.setDate(dateTimestamp == null ? null : new Date(dateTimestamp.longValue()));
            validator.validate(x509Certs);

            return true;

        } catch (Exception e) {
            log.warn("Unable to validate CRL: ", ExceptionUtils.getRootCause(e));
        }

        return false;
    }
}
