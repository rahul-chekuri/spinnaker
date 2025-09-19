/*
 * Copyright 2025 OpsMx, Inc.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package com.netflix.spinnaker.gate.security.oauth;

import static com.github.tomakehurst.wiremock.client.WireMock.urlPathEqualTo;

import com.github.tomakehurst.wiremock.WireMockServer;
import com.github.tomakehurst.wiremock.client.WireMock;
import com.github.tomakehurst.wiremock.core.WireMockConfiguration;
import com.netflix.spinnaker.gate.security.oauth.config.OAuth2TestConfiguration;
import org.assertj.core.api.Assertions;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.web.server.LocalServerPort;
import org.springframework.context.annotation.Import;
import org.springframework.http.HttpEntity;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpMethod;
import org.springframework.http.ResponseEntity;
import org.springframework.test.context.TestPropertySource;
import org.springframework.web.client.RestTemplate;

/**
 * Integration test that verifies the end-to-end OAuth2 login flow.
 *
 * <p>WireMock simulates the OAuth2 provider endpoints:
 *
 * <ul>
 *   <li>/login/oauth/authorize → redirects to the app with code and state
 *   <li>/login/oauth/user → returns user info JSON
 * </ul>
 *
 * The application runs on a random port, and RestTemplate is configured to follow redirects. This
 * test also verifies handling of null user ID without causing NPE.
 */
@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT)
@TestPropertySource(properties = {"spring.config.location=classpath:gate-test.yml"})
@Import(OAuth2TestConfiguration.class)
public class OAuth2IntegrationWithWireMockTest {

  @Autowired
  private RestTemplate
      restTemplate; // using restTemplate as it follows redirects which is required while testing
  // the OAuth flows

  @LocalServerPort private int port;

  private WireMockServer wireMockServer;

  @BeforeEach
  void setupWireMock() {
    wireMockServer =
        new WireMockServer(
            WireMockConfiguration.options()
                .port(9000)
                .extensions(new RedirectWithStateTransformer(port)));
    wireMockServer.start();

    // Stub authorize endpoint → redirect to the app’s real port
    wireMockServer.stubFor(
        WireMock.get(urlPathEqualTo("/login/oauth/authorize"))
            .willReturn(WireMock.aResponse().withTransformers("redirect-with-state")));

    // Stub user endpoint
    wireMockServer.stubFor(
        WireMock.get(urlPathEqualTo("/login/oauth/user"))
            .willReturn(
                WireMock.aResponse()
                    .withHeader("Content-Type", "application/json")
                    .withBody(
                        """
                {
                  "email": "rahul.c@opsmx.io",
                  "login": "rahul-chekuri",
                  "name": "Rahul Chekuri",
                  "type": "User",
                  "id": null
                }
                """)));
  }

  @AfterEach
  void tearDownWireMock() {
    if (wireMockServer != null) {
      wireMockServer.stop();
    }
  }

  @Test
  void whenOAuth2UserInfoHasNullsThenAuthenticationSucceeds() {
    HttpHeaders headers = new HttpHeaders();
    headers.set(
        HttpHeaders.ACCEPT,
        "text/html"); // pretend it’s a browser otherwise request won't be saved to replay after
    // authentication

    HttpEntity<Void> request = new HttpEntity<>(headers);

    ResponseEntity<String> response =
        restTemplate.exchange(
            "http://localhost:" + port + "/testOAuth2Api", HttpMethod.GET, request, String.class);

    Assertions.assertThat(response.getBody()).isEqualTo("authenticated");
  }
}
