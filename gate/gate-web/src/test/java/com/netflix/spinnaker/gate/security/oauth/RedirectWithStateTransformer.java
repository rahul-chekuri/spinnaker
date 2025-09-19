package com.netflix.spinnaker.gate.security.oauth;

import com.github.tomakehurst.wiremock.client.ResponseDefinitionBuilder;
import com.github.tomakehurst.wiremock.common.FileSource;
import com.github.tomakehurst.wiremock.extension.Parameters;
import com.github.tomakehurst.wiremock.extension.ResponseDefinitionTransformer;
import com.github.tomakehurst.wiremock.http.Request;
import com.github.tomakehurst.wiremock.http.ResponseDefinition;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;

/**
 * WireMock {@link com.github.tomakehurst.wiremock.extension.ResponseTransformer} that dynamically
 * injects the OAuth2 "state" query parameter from the incoming request into the redirect URL.
 *
 * <p>This is useful for simulating an OAuth2 authorization server during testing, where the
 * authorization endpoint must redirect to a callback URL with the original "state" preserved.
 *
 * <p><b>Note on URL encoding:</b> The "state" parameter may contain characters that need URL
 * encoding (such as '=' or '+'). This transformer ensures that the state value from the incoming
 * request is properly encoded in the redirect URL, preventing issues where Spring Security or the
 * client might decode it incorrectly.
 *
 * <p>Example usage:
 *
 * <pre>
 *   WireMock.stubFor(WireMock.get("/login/oauth/authorize")
 *       .willReturn(WireMock.aResponse()
 *           .withStatus(302)
 *           .withHeader("Location", "/login/oauth2/code/github?code=fake-code&state={{request.query.state}}")
 *           .withTransformers("redirect-with-state")));
 * </pre>
 *
 * <p>This transformer ensures that the "state" parameter in the redirect matches the one sent by
 * the client, which is necessary for proper request caching and CSRF protection in Spring Security
 * OAuth2 login flows.
 */
public class RedirectWithStateTransformer extends ResponseDefinitionTransformer {

  private final int appPort;

  public RedirectWithStateTransformer(int appPort) {
    this.appPort = appPort;
  }

  @Override
  public ResponseDefinition transform(
      Request request,
      ResponseDefinition responseDefinition,
      FileSource files,
      Parameters parameters) {
    String state = request.queryParameter("state").firstValue();
    if (state == null) {
      state = "";
    }
    String encoded = URLEncoder.encode(state, StandardCharsets.UTF_8);
    String location =
        "http://localhost:" + appPort + "/login/oauth2/code/github?code=vcbcncnm&state=" + encoded;
    return ResponseDefinitionBuilder.responseDefinition()
        .withStatus(302)
        .withHeader("Location", location)
        .build();
  }

  @Override
  public String getName() {
    return "redirect-with-state";
  }

  // don't apply globally unless you want every response transformed
  @Override
  public boolean applyGlobally() {
    return false;
  }
}
