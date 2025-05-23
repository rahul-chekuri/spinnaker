/*
 * Copyright 2019 Netflix, Inc.
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

package com.netflix.spinnaker.gate.controllers;

import com.netflix.spinnaker.gate.services.internal.EchoService;
import com.netflix.spinnaker.gate.services.internal.OrcaServiceSelector;
import com.netflix.spinnaker.kork.retrofit.Retrofit2SyncCall;
import io.swagger.v3.oas.annotations.Operation;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/capabilities")
public class CapabilitiesController {
  private final OrcaServiceSelector orcaService;
  private final Optional<EchoService> echoService;

  @Autowired
  CapabilitiesController(OrcaServiceSelector orcaService, Optional<EchoService> echoService) {
    this.orcaService = orcaService;
    this.echoService = echoService;
  }

  @Operation(summary = "Retrieve the list configured deployment monitors")
  @GetMapping(value = "/deploymentMonitors")
  List<Object> getDeploymentMonitors() {
    return Retrofit2SyncCall.execute(orcaService.select().getDeploymentMonitors());
  }

  @Operation(summary = "Retrieve the SpEL expression capabilities (e.g. registered functions, etc)")
  @GetMapping(value = "/expressions")
  Map getExpressionCapabilities() {
    return Retrofit2SyncCall.execute(orcaService.select().getExpressionCapabilities());
  }

  @Operation(summary = "Retrieve the current state of the quiet period")
  @GetMapping(value = "/quietPeriod")
  Map getQuietPeriodState() {
    return echoService
        .map(echo -> Retrofit2SyncCall.execute(echo.getQuietPeriodState()))
        .orElse(null);
  }
}
