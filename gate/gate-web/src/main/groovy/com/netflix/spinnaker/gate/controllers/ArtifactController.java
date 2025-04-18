/*
 * Copyright 2017 Google, Inc.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *    http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package com.netflix.spinnaker.gate.controllers;

import com.netflix.spinnaker.gate.services.ArtifactService;
import com.netflix.spinnaker.kork.artifacts.model.Artifact;
import io.swagger.v3.oas.annotations.Operation;
import java.io.InputStream;
import java.util.List;
import java.util.Map;
import org.apache.commons.io.IOUtils;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestHeader;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.servlet.mvc.method.annotation.StreamingResponseBody;

@RestController
@RequestMapping("/artifacts")
public class ArtifactController {

  @Autowired private ArtifactService artifactService;

  @Operation(summary = "Retrieve the list of artifact accounts configured in Clouddriver.")
  @RequestMapping(method = RequestMethod.GET, value = "/credentials")
  List<Map> all(@RequestHeader(value = "X-RateLimit-App", required = false) String sourceApp) {
    return artifactService.getArtifactCredentials(sourceApp);
  }

  @Operation(summary = "Fetch the contents of an artifact")
  @RequestMapping(method = RequestMethod.PUT, value = "/fetch")
  StreamingResponseBody fetch(
      @RequestBody Map<String, String> artifact,
      @RequestHeader(value = "X-RateLimit-App", required = false) String sourceApp) {
    return outputStream -> {
      try (InputStream inputStream = artifactService.getArtifactContents(sourceApp, artifact)) {
        IOUtils.copy(inputStream, outputStream);
      }
    };
  }

  @Operation(summary = "Retrieve the list of artifact names that belong to chosen account")
  @RequestMapping(value = "/account/{accountName}/names", method = RequestMethod.GET)
  List<String> artifactNames(
      @PathVariable String accountName,
      @RequestParam String type,
      @RequestHeader(value = "X-RateLimit-App", required = false) String sourceApp) {
    return artifactService.getArtifactNames(sourceApp, accountName, type);
  }

  @Operation(summary = "Retrieve the list of artifact versions by account and artifact names")
  @RequestMapping(value = "/account/{accountName}/versions", method = RequestMethod.GET)
  List<String> artifactVersions(
      @PathVariable String accountName,
      @RequestParam String type,
      @RequestParam String artifactName,
      @RequestHeader(value = "X-RateLimit-App", required = false) String sourceApp) {
    return artifactService.getArtifactVersions(sourceApp, accountName, type, artifactName);
  }

  @Operation(
      summary =
          "Retrieve the available artifact versions for an artifact provider and package name",
      description = "releaseStatus is an optional comma separated list of statuses to filter on.")
  @RequestMapping(value = "/{provider}/{packageName}", method = RequestMethod.GET)
  List<String> getVersionsOfArtifactForProvider(
      @PathVariable String provider,
      @PathVariable String packageName,
      @RequestParam(required = false) String releaseStatus) {
    return artifactService.getVersionsOfArtifactForProvider(provider, packageName, releaseStatus);
  }

  @Operation(
      summary = "Retrieve the specified artifact version for an artifact provider and package name")
  @RequestMapping(value = "/{provider}/{packageName}/{version:.+}", method = RequestMethod.GET)
  Map<String, Object> getArtifact(
      @PathVariable String provider,
      @PathVariable String packageName,
      @PathVariable String version) {
    return artifactService.getArtifactByVersion(provider, packageName, version);
  }

  @Operation(summary = "Retrieve artifact by content hash")
  @RequestMapping(value = "/content-address/{application}/{hash}", method = RequestMethod.GET)
  Artifact.StoredView getStoredArtifact(
      @PathVariable(value = "application") String application,
      @PathVariable(value = "hash") String hash) {
    return artifactService.getStoredArtifact(application, hash);
  }
}
