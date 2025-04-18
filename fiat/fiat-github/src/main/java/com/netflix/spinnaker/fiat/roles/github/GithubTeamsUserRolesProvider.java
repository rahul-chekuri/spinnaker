/*
 * Copyright 2016 Google, Inc.
 *
 * Licensed under the Apache License, Version 2.0 (the "License")
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

package com.netflix.spinnaker.fiat.roles.github;

import com.google.common.cache.CacheBuilder;
import com.google.common.cache.CacheLoader;
import com.google.common.cache.LoadingCache;
import com.google.common.util.concurrent.ListenableFuture;
import com.google.common.util.concurrent.ListenableFutureTask;
import com.netflix.spinnaker.fiat.model.resources.Role;
import com.netflix.spinnaker.fiat.permissions.ExternalUser;
import com.netflix.spinnaker.fiat.roles.UserRolesProvider;
import com.netflix.spinnaker.fiat.roles.github.client.GitHubClient;
import com.netflix.spinnaker.fiat.roles.github.model.Member;
import com.netflix.spinnaker.fiat.roles.github.model.Team;
import com.netflix.spinnaker.kork.retrofit.Retrofit2SyncCall;
import com.netflix.spinnaker.kork.retrofit.exceptions.SpinnakerHttpException;
import com.netflix.spinnaker.kork.retrofit.exceptions.SpinnakerNetworkException;
import java.util.*;
import java.util.concurrent.*;
import java.util.stream.Collectors;
import lombok.Data;
import lombok.Setter;
import lombok.extern.slf4j.Slf4j;
import lombok.val;
import org.apache.commons.lang3.StringUtils;
import org.springframework.beans.factory.InitializingBean;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.stereotype.Component;
import org.springframework.util.Assert;

@Slf4j
@Component
@ConditionalOnProperty(value = "auth.group-membership.service", havingValue = "github")
public class GithubTeamsUserRolesProvider implements UserRolesProvider, InitializingBean {

  private static List<String> RATE_LIMITING_HEADERS =
      Arrays.asList("X-RateLimit-Limit", "X-RateLimit-Remaining", "X-RateLimit-Reset");

  @Autowired @Setter private GitHubClient gitHubClient;

  @Autowired @Setter private GitHubProperties gitHubProperties;

  private ExecutorService executor = Executors.newSingleThreadExecutor();

  private LoadingCache<String, Set<String>> membersCache;

  private LoadingCache<String, List<Team>> teamsCache;

  private LoadingCache<String, Set<String>> teamMembershipCache;

  private static final String ACTIVE = "active";

  @Override
  public void afterPropertiesSet() throws Exception {
    Assert.state(gitHubProperties.getOrganization() != null, "Supply an organization");
    Assert.state(gitHubProperties.getBaseUrl() != null, "Supply a base url");

    this.initializeMembersCache();
    this.initializeTeamsCache();
    this.initializeTeamMembershipCache();
  }

  private void initializeMembersCache() {
    // Note if multiple github orgs is ever supported the maximumSize will need to change
    this.membersCache =
        CacheBuilder.newBuilder()
            .maximumSize(1) // This will only be a cache of one entry keyed by org name.
            .refreshAfterWrite(
                this.gitHubProperties.getMembershipCacheTTLSeconds(), TimeUnit.SECONDS)
            .build(
                new CacheLoader<String, Set<String>>() {
                  public Set<String> load(String key) {
                    Set<String> members = new HashSet<>();
                    int page = 1;
                    boolean hasMorePages = true;

                    do {
                      List<Member> membersPage = getMembersInOrgPaginated(key, page++);
                      membersPage.forEach(m -> members.add(m.getLogin().toLowerCase()));
                      if (membersPage.size() != gitHubProperties.paginationValue) {
                        hasMorePages = false;
                      }
                      log.debug(
                          "Got "
                              + membersPage.size()
                              + " members back. hasMorePages: "
                              + hasMorePages);
                    } while (hasMorePages);

                    return members;
                  }

                  public ListenableFuture<Set<String>> reload(
                      final String key, final Set<String> prev) {
                    ListenableFutureTask<Set<String>> task =
                        ListenableFutureTask.create(
                            new Callable<Set<String>>() {
                              public Set<String> call() {
                                return load(key);
                              }
                            });
                    executor.execute(task);
                    return task;
                  }
                });
  }

  private void initializeTeamsCache() {
    // Note if multiple github orgs is ever supported the maximumSize will need to change
    this.teamsCache =
        CacheBuilder.newBuilder()
            .maximumSize(1) // This will only be a cache of one entry keyed by org name.
            .refreshAfterWrite(
                this.gitHubProperties.getMembershipCacheTTLSeconds(), TimeUnit.SECONDS)
            .build(
                new CacheLoader<String, List<Team>>() {
                  public List<Team> load(String key) {
                    List<Team> teams = new ArrayList<>();
                    int page = 1;
                    boolean hasMorePages = true;

                    do {
                      List<Team> teamsPage = getTeamsInOrgPaginated(key, page++);
                      teams.addAll(teamsPage);
                      if (teamsPage.size() != gitHubProperties.paginationValue) {
                        hasMorePages = false;
                      }
                      log.debug(
                          "Got " + teamsPage.size() + " teams back. hasMorePages: " + hasMorePages);
                    } while (hasMorePages);

                    return teams;
                  }

                  public ListenableFuture<List<Team>> reload(
                      final String key, final List<Team> prev) {
                    ListenableFutureTask<List<Team>> task =
                        ListenableFutureTask.create(
                            new Callable<List<Team>>() {
                              public List<Team> call() {
                                return load(key);
                              }
                            });
                    executor.execute(task);
                    return task;
                  }
                });
  }

  private void initializeTeamMembershipCache() {
    this.teamMembershipCache =
        CacheBuilder.newBuilder()
            .maximumSize(this.gitHubProperties.getMembershipCacheTeamsSize())
            .refreshAfterWrite(
                this.gitHubProperties.getMembershipCacheTTLSeconds(), TimeUnit.SECONDS)
            .build(
                new CacheLoader<String, Set<String>>() {
                  public Set<String> load(String key) {
                    Set<String> memberships = new HashSet<>();
                    int page = 1;
                    boolean hasMorePages = true;
                    do {
                      List<Member> members =
                          getMembersInTeamPaginated(
                              gitHubProperties.getOrganization(), key, page++);
                      members.forEach(m -> memberships.add(m.getLogin().toLowerCase()));
                      if (members.size() != gitHubProperties.paginationValue) {
                        hasMorePages = false;
                      }
                      log.debug(
                          "Got " + members.size() + " teams back. hasMorePages: " + hasMorePages);
                    } while (hasMorePages);

                    return memberships;
                  }

                  public ListenableFuture<Set<String>> reload(
                      final String key, final Set<String> prev) {
                    ListenableFutureTask<Set<String>> task =
                        ListenableFutureTask.create(
                            new Callable<Set<String>>() {
                              public Set<String> call() {
                                return load(key);
                              }
                            });
                    executor.execute(task);
                    return task;
                  }
                });
  }

  @Override
  public List<Role> loadRoles(ExternalUser user) {
    String username = user.getId();

    log.debug("loadRoles for user " + username);
    if (StringUtils.isEmpty(username) || StringUtils.isEmpty(gitHubProperties.getOrganization())) {
      return new ArrayList<>();
    }

    if (!isMemberOfOrg(username)) {
      log.debug(username + "is not a member of organization " + gitHubProperties.getOrganization());
      return new ArrayList<>();
    }
    log.debug(username + "is a member of organization " + gitHubProperties.getOrganization());

    List<Role> result = new ArrayList<>();
    result.add(toRole(gitHubProperties.getOrganization()));

    // Get teams of the org
    List<Team> teams = getTeams();
    log.debug("Found " + teams.size() + " teams in org.");

    teams.forEach(
        t -> {
          String debugMsg = username + " is a member of team " + t.getName();
          if (isMemberOfTeam(t, username)) {
            result.add(toRole(t.getSlug()));
            debugMsg += ": true";
          } else {
            debugMsg += ": false";
          }
          log.debug(debugMsg);
        });

    return result;
  }

  private boolean isMemberOfOrg(String username) {
    boolean isMemberOfOrg = false;
    try {
      isMemberOfOrg =
          this.membersCache
              .get(gitHubProperties.getOrganization())
              .contains(username.toLowerCase());
    } catch (ExecutionException e) {
      log.error("Failed to read from cache when getting org membership", e);
    }
    return isMemberOfOrg;
  }

  private List<Team> getTeams() {
    try {
      return this.teamsCache.get(gitHubProperties.getOrganization());
    } catch (ExecutionException e) {
      log.error("Failed to read from cache when getting teams", e);
    }
    return Collections.emptyList();
  }

  private List<Team> getTeamsInOrgPaginated(String organization, int page) {
    List<Team> teams = new ArrayList<>();
    try {
      log.debug("Requesting page " + page + " of teams.");
      teams =
          Retrofit2SyncCall.execute(
              gitHubClient.getOrgTeams(organization, page, gitHubProperties.paginationValue));
    } catch (SpinnakerNetworkException e) {
      log.error(String.format("Could not find the server %s", gitHubProperties.getBaseUrl()), e);
    } catch (SpinnakerHttpException e) {
      if (e.getResponseCode() != HttpStatus.NOT_FOUND.value()) {
        handleNon404s(e);
        throw e;
      } else {
        log.error("404 when getting teams", e);
      }
    }

    return teams;
  }

  private List<Member> getMembersInOrgPaginated(String organization, int page) {
    List<Member> members = new ArrayList<>();
    try {
      log.debug("Requesting page " + page + " of members.");
      members =
          Retrofit2SyncCall.execute(
              gitHubClient.getOrgMembers(organization, page, gitHubProperties.paginationValue));
    } catch (SpinnakerNetworkException e) {
      log.error(String.format("Could not find the server %s", gitHubProperties.getBaseUrl()), e);
    } catch (SpinnakerHttpException e) {
      if (e.getResponseCode() != HttpStatus.NOT_FOUND.value()) {
        handleNon404s(e);
        throw e;
      } else {
        log.error("404 when getting members", e);
      }
    }

    return members;
  }

  private List<Member> getMembersInTeamPaginated(String organization, String teamSlug, int page) {
    List<Member> members = new ArrayList<>();
    try {
      log.debug("Requesting page " + page + " of members team " + teamSlug + ".");
      members =
          Retrofit2SyncCall.execute(
              gitHubClient.getMembersOfTeam(
                  organization, teamSlug, page, gitHubProperties.paginationValue));
    } catch (SpinnakerNetworkException e) {
      log.error(String.format("Could not find the server %s", gitHubProperties.getBaseUrl()), e);
    } catch (SpinnakerHttpException e) {
      if (e.getResponseCode() != HttpStatus.NOT_FOUND.value()) {
        handleNon404s(e);
        throw e;
      } else {
        log.error("404 when getting members of team", e);
      }
    }

    return members;
  }

  private boolean isMemberOfTeam(Team t, String username) {
    try {
      return this.teamMembershipCache.get(t.getSlug()).contains(username.toLowerCase());
    } catch (ExecutionException e) {
      log.error("Failed to read from cache when getting team membership", e);
    }
    return false;
  }

  private void handleNon404s(SpinnakerHttpException e) {
    String msg = "";
    if (e.getResponseCode() == HttpStatus.UNAUTHORIZED.value()) {
      msg = "HTTP 401 Unauthorized.";
    } else if (e.getResponseCode() == HttpStatus.FORBIDDEN.value()) {
      HttpHeaders headers = e.getHeaders();
      val rateHeaders =
          RATE_LIMITING_HEADERS.stream()
              .filter(headers::containsKey)
              .map(headers::getFirst)
              .collect(Collectors.toList());

      msg = "HTTP 403 Forbidden. Rate limit info: " + StringUtils.join(rateHeaders, ", ");
    }
    log.error(msg, e);
  }

  private static Role toRole(String name) {
    return new Role().setName(name.toLowerCase()).setSource(Role.Source.GITHUB_TEAMS);
  }

  @Override
  public Map<String, Collection<Role>> multiLoadRoles(Collection<ExternalUser> users) {
    if (users == null || users.isEmpty()) {
      return new HashMap<>();
    }

    val emailGroupsMap = new HashMap<String, Collection<Role>>();
    users.forEach(u -> emailGroupsMap.put(u.getId(), loadRoles(u)));

    return emailGroupsMap;
  }

  @Data
  private class OrgMembershipKey {
    private final String organization;
    private final String username;
  }

  @Data
  private class TeamMembershipKey {
    private final Long teamId;
    private final String username;
  }
}
