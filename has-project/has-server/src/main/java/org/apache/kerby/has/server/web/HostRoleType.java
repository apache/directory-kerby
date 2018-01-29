/**
 * Licensed to the Apache Software Foundation (ASF) under one
 * or more contributor license agreements.  See the NOTICE file
 * distributed with this work for additional information
 * regarding copyright ownership.  The ASF licenses this file
 * to you under the Apache License, Version 2.0 (the
 * "License"); you may not use this file except in compliance
 * with the License.  You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package org.apache.kerby.has.server.web;

import org.apache.hadoop.classification.InterfaceAudience;
import org.apache.hadoop.classification.InterfaceStability;

@InterfaceAudience.Public
@InterfaceStability.Stable
public enum HostRoleType {
    HDFS("HDFS", new String[]{"HTTP", "hdfs"}),
    YARN("YARN", new String[]{"yarn"}),
    MAPRED("MAPRED", new String[]{"mapred"}),
    HBASE("HBASE", new String[]{"hbase"}),
    ZOOKEEPER("ZOOKEEPER", new String[]{"zookeeper"}),
    SPARK("SPARK", new String[]{"spark"}),
    HIVE("HIVE", new String[]{"hive"}),
    OOZIE("OOZIE", new String[]{"oozie"}),
    HUE("HUE", new String[]{"hue"});

    private String name;
    private String[] princs;

    HostRoleType(String name, String[] princs) {
        this.name = name;
        this.princs = princs;
    }

    public String[] getPrincs() {
        return princs;
    }

    public String getName() {
        return name;
    }

    public void setName(String name) {
        this.name = name;
    }
}
