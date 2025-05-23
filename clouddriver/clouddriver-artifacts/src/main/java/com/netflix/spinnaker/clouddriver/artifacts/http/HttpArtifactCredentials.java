/*
 * Copyright 2018 Joel Wilsson
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
 *
 */

package com.netflix.spinnaker.clouddriver.artifacts.http;

import com.google.common.collect.ImmutableList;
import com.netflix.spinnaker.clouddriver.artifacts.config.ArtifactCredentials;
import com.netflix.spinnaker.clouddriver.artifacts.config.SimpleHttpArtifactCredentials;
import com.netflix.spinnaker.kork.annotations.NonnullByDefault;
import lombok.Getter;
import lombok.extern.slf4j.Slf4j;
import okhttp3.OkHttpClient;

@NonnullByDefault
@Slf4j
public class HttpArtifactCredentials extends SimpleHttpArtifactCredentials<HttpArtifactAccount>
    implements ArtifactCredentials {
  public static final String CREDENTIALS_TYPE = "artifacts-http";
  @Getter private final String name;
  @Getter private final ImmutableList<String> types = ImmutableList.of("http/file");

  HttpArtifactCredentials(HttpArtifactAccount account, OkHttpClient okHttpClient) {
    super(okHttpClient, account);
    this.name = account.getName();
  }

  @Override
  public String getType() {
    return CREDENTIALS_TYPE;
  }
}
