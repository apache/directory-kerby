/**
 *  Licensed to the Apache Software Foundation (ASF) under one
 *  or more contributor license agreements.  See the NOTICE file
 *  distributed with this work for additional information
 *  regarding copyright ownership.  The ASF licenses this file
 *  to you under the Apache License, Version 2.0 (the
 *  "License"); you may not use this file except in compliance
 *  with the License.  You may obtain a copy of the License at
 *  
 *    http://www.apache.org/licenses/LICENSE-2.0
 *  
 *  Unless required by applicable law or agreed to in writing,
 *  software distributed under the License is distributed on an
 *  "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 *  KIND, either express or implied.  See the License for the
 *  specific language governing permissions and limitations
 *  under the License. 
 *  
 */
package org.apache.kerby.kerberos.kdc.identitybackend;

import org.apache.kerby.config.Config;
import org.apache.kerby.kerberos.kerb.identity.KrbIdentity;
import org.apache.kerby.kerberos.kerb.identity.backend.AbstractIdentityBackend;
import org.apache.zookeeper.WatchedEvent;
import org.apache.zookeeper.Watcher;
import org.apache.zookeeper.ZooKeeper;
import org.apache.zookeeper.server.ServerConfig;
import org.apache.zookeeper.server.ZooKeeperServerMain;
import org.apache.zookeeper.server.quorum.QuorumPeerConfig;

import java.io.IOException;
import java.util.List;
import java.util.Properties;

/**
 * A Zookeeper based backend implementation. Currently it uses an embedded
 * Zookeeper. In follow up it will be enhanced to support standalone Zookeeper
 * cluster for replication and reliability.
 *
 */
public class ZookeeperIdentityBackend extends AbstractIdentityBackend
        implements Watcher {
    private Config config;
    private String zkHost;
    private int zkPort;

    /**
     * Constructing an instance using specified config that contains anything
     * to be used to init the Zookeeper backend.
     * @param config
     */
    public ZookeeperIdentityBackend(Config config) {
        this.config = config;
        init();
    }

    private void init() {
        zkHost = config.getString(ZKConfKey.ZK_HOST);
        zkPort = config.getInt(ZKConfKey.ZK_PORT);
        startEmbeddedZookeeper();
        connectZK();
    }

    /**
     * Prepare connection to Zookeeper server.
     */
    private void connectZK() {
        try {
            ZooKeeper zooKeeper = new ZooKeeper(zkHost, zkPort, null);
        } catch (IOException e) {
            throw new RuntimeException("Failed to prepare Zookeeper connection");
        }
    }

    /**
     * Load identities from file
     */
    public void load() throws IOException {
        // TODO: prepare zookeeper connection to the server.
        ZooKeeper zooKeeper = null;

        // TODO: load the kdb file from zookeeper
    }

    private void startEmbeddedZookeeper() {
        Properties startupProperties = new Properties();

        QuorumPeerConfig quorumConfiguration = new QuorumPeerConfig();
        try {
            quorumConfiguration.parseProperties(startupProperties);
        } catch(Exception e) {
            throw new RuntimeException(e);
        }

        final ZooKeeperServerMain zooKeeperServer = new ZooKeeperServerMain();
        final ServerConfig configuration = new ServerConfig();
        configuration.readFrom(quorumConfiguration);

        new Thread() {
            public void run() {
                try {
                    zooKeeperServer.runFromConfig(configuration);
                } catch (IOException e) {
                    //log.error("ZooKeeper Failed", e);
                }
            }
        }.start();

    }

    /**
     * This will watch all the kdb update event so that it's timely synced.
     * @param event
     */
    @Override
    public void process(WatchedEvent event) {
        System.out.print("I got an event: " + event);
    }

    @Override
    protected KrbIdentity doGetIdentity(String principalName) {
        return null;
    }

    @Override
    protected KrbIdentity doAddIdentity(KrbIdentity identity) {
        return null;
    }

    @Override
    protected KrbIdentity doUpdateIdentity(KrbIdentity identity) {
        return null;
    }

    @Override
    protected void doDeleteIdentity(String principalName) {

    }

    @Override
    public List<String> getIdentities(int start, int limit) {
        return null;
    }
}
