/*
 * SPDX-License-Identifier: Apache-2.0
 *
 * The OpenSearch Contributors require contributions made to
 * this file be licensed under the Apache-2.0 license or a
 * compatible open source license.
 */
package org.opensearch.security.bwc;

import java.io.IOException;
import java.net.URI;
import java.net.URISyntaxException;
import java.nio.file.Path;
import java.util.HashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;
import java.util.Set;
import java.util.stream.Collectors;
import javax.net.ssl.SSLContext;

import com.fasterxml.jackson.databind.ObjectMapper;
import org.apache.hc.client5.http.auth.AuthScope;
import org.apache.hc.client5.http.auth.UsernamePasswordCredentials;
import org.apache.hc.client5.http.impl.auth.BasicCredentialsProvider;
import org.apache.hc.client5.http.impl.nio.PoolingAsyncClientConnectionManagerBuilder;
import org.apache.hc.client5.http.nio.AsyncClientConnectionManager;
import org.apache.hc.client5.http.ssl.ClientTlsStrategyBuilder;
import org.apache.hc.client5.http.ssl.NoopHostnameVerifier;
import org.apache.hc.core5.http.Header;
import org.apache.hc.core5.http.HttpHost;
import org.apache.hc.core5.http.io.entity.StringEntity;
import org.apache.hc.core5.http.message.BasicHeader;
import org.apache.hc.core5.http.nio.ssl.TlsStrategy;
import org.apache.hc.core5.reactor.ssl.TlsDetails;
import org.apache.hc.core5.ssl.SSLContextBuilder;
import org.junit.AfterClass;
import org.junit.Assume;
import org.junit.Before;

import org.opensearch.Version;
import org.opensearch.client.Response;
import org.opensearch.client.ResponseException;
import org.opensearch.client.RestClient;
import org.opensearch.client.RestClientBuilder;
import org.opensearch.common.Randomness;
import org.opensearch.common.io.PathUtils;
import org.opensearch.common.settings.Settings;
import org.opensearch.common.util.concurrent.ThreadContext;
import org.opensearch.common.util.io.IOUtils;
import org.opensearch.common.xcontent.support.XContentMapValues;
import org.opensearch.commons.rest.SecureRestClientBuilder;
import org.opensearch.security.bwc.helper.RestHelper;
import org.opensearch.test.rest.OpenSearchRestTestCase;

import static org.apache.hc.core5.http.ContentType.APPLICATION_NDJSON;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.anyOf;
import static org.hamcrest.Matchers.equalTo;
import static org.hamcrest.Matchers.hasItem;
import static org.hamcrest.Matchers.hasKey;
import static org.hamcrest.Matchers.is;

public class SecurityBackwardsCompatibilityIT extends OpenSearchRestTestCase {

    private ClusterType CLUSTER_TYPE;
    private String CLUSTER_NAME;

    private final String TEST_USER = "user";
    private final String TEST_PASSWORD = "290735c0-355d-4aaf-9b42-1aaa1f2a3cee";
    private final String TEST_ROLE = "test-dls-fls-role";
    private static RestClient testUserRestClient = null;

    @Before
    public void testSetup() {
        final String bwcsuiteString = System.getProperty("tests.rest.bwcsuite");
        Assume.assumeTrue("Test cannot be run outside the BWC gradle task 'bwcTestSuite' or its dependent tasks", bwcsuiteString != null);
        CLUSTER_TYPE = ClusterType.parse(bwcsuiteString);
        CLUSTER_NAME = System.getProperty("tests.clustername");
        if (testUserRestClient == null) {
            testUserRestClient = buildClient(
                super.restClientSettings(),
                super.getClusterHosts().toArray(new HttpHost[0]),
                TEST_USER,
                TEST_PASSWORD
            );
        }
    }

    @Override
    protected final boolean preserveClusterUponCompletion() {
        return true;
    }

    @Override
    protected final boolean preserveIndicesUponCompletion() {
        return true;
    }

    @Override
    protected final boolean preserveReposUponCompletion() {
        return true;
    }

    @Override
    protected boolean preserveTemplatesUponCompletion() {
        return true;
    }

    @Override
    protected String getProtocol() {
        return "https";
    }

    @Override
    protected final Settings restClientSettings() {
        return Settings.builder()
            .put(super.restClientSettings())
            // increase the timeout here to 90 seconds to handle long waits for a green
            // cluster health. the waits for green need to be longer than a minute to
            // account for delayed shards
            .put(OpenSearchRestTestCase.CLIENT_SOCKET_TIMEOUT, "90s")
            .build();
    }

    @Override
    protected Settings restAdminSettings() {
        return Settings.builder()
            .put("http.port", 9200)
            .put("plugins.security.ssl.http.enabled", true)
            // this is incorrect on common-utils side. It should be using `pemtrustedcas_filepath`
            .put("plugins.security.ssl.http.pemcert_filepath", "sample.pem")
            .put("plugins.security.ssl.http.keystore_filepath", "test-kirk.jks")
            .put("plugins.security.ssl.http.keystore_password", "changeit")
            .put("plugins.security.ssl.http.keystore_keypassword", "changeit")
            .build();
    }

    protected RestClient buildClient(Settings settings, HttpHost[] hosts, String username, String password) {
        RestClientBuilder builder = RestClient.builder(hosts);
        configureHttpsClient(builder, settings, username, password);
        boolean strictDeprecationMode = settings.getAsBoolean("strictDeprecationMode", true);
        builder.setStrictDeprecationMode(strictDeprecationMode);
        return builder.build();
    }

    @Override
    protected RestClient buildClient(Settings settings, HttpHost[] hosts) throws IOException {
        String keystore = settings.get("plugins.security.ssl.http.keystore_filepath");
        if (Objects.nonNull(keystore)) {
            URI uri = null;
            try {
                uri = this.getClass().getClassLoader().getResource("security/test-kirk.jks").toURI();
            } catch (URISyntaxException e) {
                throw new RuntimeException(e);
            }
            Path configPath = PathUtils.get(uri).getParent().toAbsolutePath();
            return new SecureRestClientBuilder(settings, configPath, hosts).build();
        }
        String username = Optional.ofNullable(System.getProperty("tests.opensearch.username"))
            .orElseThrow(() -> new RuntimeException("user name is missing"));
        String password = Optional.ofNullable(System.getProperty("tests.opensearch.password"))
            .orElseThrow(() -> new RuntimeException("password is missing"));
        return buildClient(super.restClientSettings(), super.getClusterHosts().toArray(new HttpHost[0]), username, password);
    }

    private static void configureHttpsClient(RestClientBuilder builder, Settings settings, String userName, String password) {
        Map<String, String> headers = ThreadContext.buildDefaultHeaders(settings);
        Header[] defaultHeaders = new Header[headers.size()];
        int i = 0;
        for (Map.Entry<String, String> entry : headers.entrySet()) {
            defaultHeaders[i++] = new BasicHeader(entry.getKey(), entry.getValue());
        }
        builder.setDefaultHeaders(defaultHeaders);
        builder.setHttpClientConfigCallback(httpClientBuilder -> {
            BasicCredentialsProvider credentialsProvider = new BasicCredentialsProvider();
            credentialsProvider.setCredentials(new AuthScope(null, -1), new UsernamePasswordCredentials(userName, password.toCharArray()));
            try {
                SSLContext sslContext = SSLContextBuilder.create().loadTrustMaterial(null, (chains, authType) -> true).build();

                TlsStrategy tlsStrategy = ClientTlsStrategyBuilder.create()
                    .setSslContext(sslContext)
                    .setTlsVersions(new String[] { "TLSv1", "TLSv1.1", "TLSv1.2", "SSLv3" })
                    .setHostnameVerifier(NoopHostnameVerifier.INSTANCE)
                    // See please https://issues.apache.org/jira/browse/HTTPCLIENT-2219
                    .setTlsDetailsFactory(sslEngine -> new TlsDetails(sslEngine.getSession(), sslEngine.getApplicationProtocol()))
                    .build();

                final AsyncClientConnectionManager cm = PoolingAsyncClientConnectionManagerBuilder.create()
                    .setTlsStrategy(tlsStrategy)
                    .build();
                return httpClientBuilder.setDefaultCredentialsProvider(credentialsProvider).setConnectionManager(cm);
            } catch (Exception e) {
                throw new RuntimeException(e);
            }
        });
    }

    /**
     * Test /certificates endpoint.
     * Validate certificate info for correctness and check for errors.
     */
    public void testSslCertsInfoEndpoint() throws IOException {
        List<String> expectCertificates = List.of("http", "transport", "transport_client");
        List<Response> resp = RestHelper.requestAgainstAllNodes(adminClient(), "GET", "_plugins/_security/api/certificates", null);
        resp.forEach(response -> {
            assertEquals("SSL certs info endpoint should return 200", 200, response.getStatusLine().getStatusCode());
            Map<String, Object> responseMap;
            try {
                responseMap = responseAsMap(response);
            } catch (IOException e) {
                throw new RuntimeException("Failed to parse certs info response", e);
            }
            @SuppressWarnings("unchecked")
            Map<String, Object> nodeFailureMap = (Map<String, Object>) responseMap.get("_nodes");
            assertEquals(3, nodeFailureMap.get("total"));
            assertEquals(3, nodeFailureMap.get("successful"));
            assertEquals(0, nodeFailureMap.get("failed"));
            @SuppressWarnings("unchecked")
            Map<String, Object> nodesMap = (Map<String, Object>) responseMap.get("nodes");
            for (String nodeKey : nodesMap.keySet()) {
                @SuppressWarnings("unchecked")
                Map<String, Object> nodeInfo = (Map<String, Object>) nodesMap.get(nodeKey);
                @SuppressWarnings("unchecked")
                Map<String, Object> nodeCerts = (Map<String, Object>) nodeInfo.get("certificates");
                for (String expectCertKey : expectCertificates) {
                    assertTrue(nodeCerts.containsKey(expectCertKey));
                    @SuppressWarnings("unchecked")
                    List<Map<String, Object>> certList = (List<Map<String, Object>>) nodeCerts.get(expectCertKey);
                    for (Map<String, Object> singleCert : certList) {
                        verifyCertificateInfo(singleCert);
                    }
                }
            }
        });
    }

    /**
     * Validate the structure of certificates info response items.
     */
    private void verifyCertificateInfo(Map<String, Object> certInfo) {
        assertThat("Certificate should have subject_dn", certInfo, hasKey("subject_dn"));
        assertThat("Certificate should have issuer_dn", certInfo, hasKey("issuer_dn"));
        assertThat("Certificate should have not_before", certInfo, hasKey("not_before"));
        assertThat("Certificate should have not_after", certInfo, hasKey("not_after"));
        Object subjectDn = certInfo.get("subject_dn");
        if (subjectDn != null) {
            assertTrue("subject_dn should be a string", subjectDn instanceof String);
            assertFalse("subject_dn should not be empty", ((String) subjectDn).isEmpty());
        }
        Object issuerDn = certInfo.get("issuer_dn");
        if (issuerDn != null) {
            assertTrue("issuer_dn should be a string", issuerDn instanceof String);
            assertFalse("issuer_dn should not be empty", ((String) issuerDn).isEmpty());
        }
    }

    public void testWhoAmI() throws Exception {
        Map<String, Object> responseMap = getAsMap("_plugins/_security/whoami");
        assertThat(responseMap, hasKey("dn"));
    }

    public void testBasicBackwardsCompatibility() throws Exception {
        String round = System.getProperty("tests.rest.bwcsuite_round");

        if (round.equals("first") || round.equals("old")) {
            assertPluginUpgrade("_nodes/" + CLUSTER_NAME + "-0/plugins");
        } else if (round.equals("second")) {
            assertPluginUpgrade("_nodes/" + CLUSTER_NAME + "-1/plugins");
        } else if (round.equals("third")) {
            assertPluginUpgrade("_nodes/" + CLUSTER_NAME + "-2/plugins");
        }
    }

    /**
     * Tests backward compatibility by created a test user and role with DLS, FLS and masked field settings. Ingests
     * data into a test index and runs a matchAll query against the same.
     */
    public void testDataIngestionAndSearchBackwardsCompatibility() throws Exception {
        String round = System.getProperty("tests.rest.bwcsuite_round");
        String index = "test_index";
        if (round.equals("old")) {
            createTestRoleIfNotExists(TEST_ROLE);
            createUserIfNotExists(TEST_USER, TEST_PASSWORD, TEST_ROLE);
            createIndexIfNotExists(index);
        }
        ingestData(index);
        searchMatchAll(index);
    }

    public void testNodeStats() throws IOException {
        List<Response> responses = RestHelper.requestAgainstAllNodes(client(), "GET", "_nodes/stats", null);
        responses.forEach(r -> assertThat(r.getStatusLine().getStatusCode(), is(200)));
    }

    @SuppressWarnings("unchecked")
    private void assertPluginUpgrade(String uri) throws Exception {
        Map<String, Map<String, Object>> responseMap = (Map<String, Map<String, Object>>) getAsMap(uri).get("nodes");
        for (Map<String, Object> response : responseMap.values()) {
            List<Map<String, Object>> plugins = (List<Map<String, Object>>) response.get("plugins");
            Set<String> pluginNames = plugins.stream().map(map -> (String) map.get("name")).collect(Collectors.toSet());

            final Version minNodeVersion = minimumNodeVersion();

            if (minNodeVersion.major <= 1) {
                assertThat(pluginNames, hasItem("opensearch_security")); // With underscore seperator
            } else {
                assertThat(pluginNames, hasItem("opensearch-security")); // With dash seperator
            }
        }
    }

    /**
     * Ingests data into the test index
     * @param index index to ingest data into
     */

    private void ingestData(String index) throws IOException {
        StringBuilder bulkRequestBody = new StringBuilder();
        ObjectMapper objectMapper = new ObjectMapper();
        int numberOfRequests = Randomness.get().nextInt(10);
        while (numberOfRequests-- > 0) {
            int numberOfDocuments = Randomness.get().nextInt(100) + 1;
            for (int i = 0; i < numberOfDocuments; i++) {
                Map<String, Map<String, String>> indexRequest = new HashMap<>();
                indexRequest.put("index", new HashMap<>() {
                    {
                        put("_index", index);
                    }
                });
                bulkRequestBody.append(objectMapper.writeValueAsString(indexRequest) + "\n");
                bulkRequestBody.append(Song.randomSong().asJson() + "\n");
            }
            List<Response> responses = RestHelper.requestAgainstAllNodes(
                testUserRestClient,
                "POST",
                "_bulk?refresh=wait_for",
                new StringEntity(bulkRequestBody.toString(), APPLICATION_NDJSON)
            );
            responses.forEach(r -> assertThat(r.getStatusLine().getStatusCode(), is(200)));
            for (Response response : responses) {
                Map<String, Object> responseMap = responseAsMap(response);
                List<?> itemResults = (List<?>) XContentMapValues.extractValue(responseMap, "items", "index", "result");
                assertTrue("More than 0 response items", itemResults.size() > 0);
                assertTrue("All results are 'created': " + itemResults, itemResults.stream().allMatch(i -> i.equals("created")));
            }
        }
    }

    /**
     * Runs a matchAll query against the test index
     * @param index index to search
     */
    private void searchMatchAll(String index) throws IOException {
        String matchAllQuery = "{\n" + "    \"query\": {\n" + "        \"match_all\": {}\n" + "    }\n" + "}";
        int numberOfRequests = Randomness.get().nextInt(10);
        while (numberOfRequests-- > 0) {
            List<Response> responses = RestHelper.requestAgainstAllNodes(
                testUserRestClient,
                "POST",
                index + "/_search",
                RestHelper.toHttpEntity(matchAllQuery)
            );
            responses.forEach(r -> assertThat(r.getStatusLine().getStatusCode(), is(200)));

            for (Response response : responses) {
                Map<String, Object> responseMap = responseAsMap(response);
                @SuppressWarnings("unchecked")
                List<Map<?, ?>> sourceDocs = (List<Map<?, ?>>) XContentMapValues.extractValue(responseMap, "hits", "hits", "_source");

                for (Map<?, ?> sourceDoc : sourceDocs) {
                    assertNull("response doc should not contain field forbidden by FLS: " + responseMap, sourceDoc.get(Song.FIELD_LYRICS));
                    assertNotNull(
                        "response doc should contain field not forbidden by FLS: " + responseMap,
                        sourceDoc.get(Song.FIELD_ARTIST)
                    );
                    assertEquals(
                        "response doc should always have genre rock: " + responseMap,
                        Song.GENRE_ROCK,
                        sourceDoc.get(Song.FIELD_GENRE)
                    );
                }
            }
        }
    }

    /**
     * Checks if a resource at the specified URL exists
     * @param url of the resource to be checked for existence
     * @return true if the resource exists, false otherwise
     */

    private boolean resourceExists(String url) throws IOException {
        try {
            RestHelper.get(adminClient(), url);
            return true;
        } catch (ResponseException e) {
            if (e.getResponse().getStatusLine().getStatusCode() == 404) {
                return false;
            } else {
                throw e;
            }
        }
    }

    /**
     * Creates a test role with DLS, FLS and masked field settings on the test index.
     */
    private void createTestRoleIfNotExists(String role) throws IOException {
        String url = "_plugins/_security/api/roles/" + role;
        String roleSettings = "{\n"
            + "  \"cluster_permissions\": [\n"
            + "    \"unlimited\"\n"
            + "  ],\n"
            + "  \"index_permissions\": [\n"
            + "    {\n"
            + "      \"index_patterns\": [\n"
            + "        \"test_index*\"\n"
            + "      ],\n"
            + "      \"dls\": \"{ \\\"bool\\\": { \\\"must\\\": { \\\"match\\\": { \\\"genre\\\": \\\"rock\\\" } } } }\",\n"
            + "      \"fls\": [\n"
            + "        \"~lyrics\"\n"
            + "      ],\n"
            + "      \"masked_fields\": [\n"
            + "        \"artist\"\n"
            + "      ],\n"
            + "      \"allowed_actions\": [\n"
            + "        \"read\",\n"
            + "        \"write\"\n"
            + "      ]\n"
            + "    }\n"
            + "  ],\n"
            + "  \"tenant_permissions\": []\n"
            + "}\n";
        Response response = RestHelper.makeRequest(adminClient(), "PUT", url, RestHelper.toHttpEntity(roleSettings));

        assertThat(response.getStatusLine().getStatusCode(), anyOf(equalTo(200), equalTo(201)));
    }

    /**
     * Creates a test index if it does not exist already
     * @param index index to create
     */

    private void createIndexIfNotExists(String index) throws IOException {
        String settings = "{\n"
            + "  \"settings\": {\n"
            + "    \"index\": {\n"
            + "      \"number_of_shards\": 3,\n"
            + "      \"number_of_replicas\": 1\n"
            + "    }\n"
            + "  }\n"
            + "}";
        if (!resourceExists(index)) {
            Response response = RestHelper.makeRequest(client(), "PUT", index, RestHelper.toHttpEntity(settings));
            assertThat(response.getStatusLine().getStatusCode(), equalTo(200));
        }
    }

    /**
     * Creates the test user if it does not exist already and maps it to the test role with DLS/FLS settings.
     * @param  user user to be created
     * @param  password password for the new user
     * @param  role roles that the user has to be mapped to
     */
    private void createUserIfNotExists(String user, String password, String role) throws IOException {
        String url = "_plugins/_security/api/internalusers/" + user;
        if (!resourceExists(url)) {
            String userSettings = String.format(
                Locale.ENGLISH,
                "{\n" + "  \"password\": \"%s\",\n" + "  \"opendistro_security_roles\": [\"%s\"],\n" + "  \"backend_roles\": []\n" + "}",
                password,
                role
            );
            Response response = RestHelper.makeRequest(adminClient(), "PUT", url, RestHelper.toHttpEntity(userSettings));
            assertThat(response.getStatusLine().getStatusCode(), equalTo(201));
        }
    }

    @AfterClass
    public static void cleanUp() throws IOException {
        OpenSearchRestTestCase.closeClients();
        IOUtils.close(testUserRestClient);
    }
}
