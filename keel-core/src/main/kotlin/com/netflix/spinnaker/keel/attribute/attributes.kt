/*
 * Copyright 2017 Netflix, Inc.
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
package com.netflix.spinnaker.keel.attribute

import com.fasterxml.jackson.annotation.JsonCreator
import com.fasterxml.jackson.annotation.JsonTypeInfo
import com.fasterxml.jackson.annotation.JsonTypeName
import com.netflix.spinnaker.keel.AssetPriority

/**
 * An Attribute is a strictly typed key/value pair. They're attached as a collection of metadata on Assets and used
 * by Filters, Policies and event handlers for performing direct or indirect actions on Assets.
 */
@JsonTypeInfo(use = JsonTypeInfo.Id.NAME, include = JsonTypeInfo.As.PROPERTY, property = "kind")
abstract class Attribute<out T>
@JsonCreator constructor(
  val kind: String,
  val value: T
)

/**
 * Defines the namespace-specific priority of an asset.
 */
@JsonTypeName("Priority")
class PriorityAttribute(value: AssetPriority) : Attribute<AssetPriority>("Priority", value)

/**
 * Defines whether or not an Asset's desired state should be getting actively converged. Release valve.
 */
@JsonTypeName("Enabled")
class EnabledAttribute(value: Boolean) : Attribute<Boolean>("Enabled", value)

/**
 * Defines at what times during the time of day & weekly schedule an Asset should be a candidate for being converged.
 */
@JsonTypeName("ExecutionWindow")
class ExecutionWindowAttribute(value: ExecutionWindow) : Attribute<ExecutionWindow>("ExecutionWindow", value) {
  override fun toString(): String {
    return "ExecutionWindowAttribute(days=${value.days}, timeWindows=${value.timeWindows})"
  }
}

data class ExecutionWindow(
  val days: List<Int>,
  val timeWindows: List<TimeWindow>
)

data class TimeWindow(
  val startHour: Int,
  val startMin: Int,
  val endHour: Int,
  val endMin: Int
)

/**
 * Defines the origin of an Asset. When defined, Spinnaker is capable of exposing richer back-linking to where an
 * Asset is defined.
 */
@JsonTypeName("Origin")
class OriginAttribute(value: String) : Attribute<String>("Origin", value)
