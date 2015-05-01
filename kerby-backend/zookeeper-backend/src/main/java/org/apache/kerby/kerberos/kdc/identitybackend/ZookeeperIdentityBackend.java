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
import org.apache.zookeeper.KeeperException;
import org.apache.zookeeper.WatchedEvent;
import org.apache.zookeeper.Watcher;
import org.apache.zookeeper.ZooKeeper;
import org.apache.zookeeper.server.ServerConfig;
import org.apache.zookeeper.server.ZooKeeperServerMain;
import org.apache.zookeeper.server.quorum.QuorumPeerConfig;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.File;
import java.io.IOException;
import java.util.ArrayList;
import java.util.Collections;
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
    private static final Logger LOG = LoggerFactory.getLogger(ZookeeperIdentityBackend.class);
    private Config config;      //NOPMD
    private String zkHost;
    private int zkPort;
    private File dataDir;
    private File dataLogDir;
    private ZooKeeper zooKeeper;

    public ZookeeperIdentityBackend() {

    }

    /**
     * Constructing an instance using specified config that contains anything
     * to be used to init the Zookeeper backend.
     * @param config
     */
    public ZookeeperIdentityBackend(Config config) {
         setConfig(config);
    }

    @Override
    public void initialize() {
        super.initialize();
        init();
    }

    private void init() {
        zkHost = getConfig().getString(ZKConfKey.ZK_HOST);
        zkPort = getConfig().getInt(ZKConfKey.ZK_PORT);
        dataDir = new File(getConfig().getString(ZKConfKey.DATA_DIR));
        dataLogDir = new File(getConfig().getString(ZKConfKey.DATA_LOG_DIR));

        startEmbeddedZookeeper();
        connectZK();
    }

    /**
     * Prepare connection to Zookeeper server.
     */
    private void connectZK() {
        try {
            zooKeeper = new ZooKeeper(zkHost, zkPort, null);
        } catch (IOException e) {
            throw new RuntimeException("Failed to prepare Zookeeper connection");
        }
    }

    /**
     * Load identities from file
     */
    public void load() throws IOException {
        // TODO: prepare zookeeper connection to the server.
        // ZooKeeper zooKeeper = null;

        // TODO: load the kdb file from zookeeper
    }

    private void startEmbeddedZookeeper() {

        Properties startupProperties = new Properties();
        startupProperties.put("dataDir", dataDir.getAbsolutePath());
        startupProperties.put("dataLogDir", dataLogDir.getAbsolutePath());
        startupProperties.put("clientPort", zkPort);

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
                    e.printStackTrace();
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
        principalName = replaceSlash(principalName);
        IdentityZNode identityZNode = new IdentityZNode(zooKeeper, principalName);
        KrbIdentity krb = new KrbIdentity(principalName);
        try {
            if (!identityZNode.exist()) {
                return null;
            }
            krb.setPrincipal(identityZNode.getPrincipalName());
            krb.setCreatedTime(identityZNode.getCreatedTime());
            krb.setDisabled(identityZNode.getDisabled());
            krb.setExpireTime(identityZNode.getExpireTime());
            krb.setKdcFlags(identityZNode.getKdcFlags());
            krb.addKeys(identityZNode.getKeys());
            krb.setKeyVersion(identityZNode.getKeyVersion());
            krb.setLocked(identityZNode.getLocked());
        } catch (KeeperException e) {
            LOG.error("Fail to get identity from zookeeper", e);
        }
        return krb;
    }

    @Override
    protected KrbIdentity doAddIdentity(KrbIdentity identity) {
        try {
            setIdentity(identity);
        } catch (KeeperException e) {
            LOG.error("Fail to add identity to zookeeper", e);
        }
        return identity;
    }

    @Override
    protected KrbIdentity doUpdateIdentity(KrbIdentity identity) {
        try {
            setIdentity(identity);
        } catch (KeeperException e) {
            LOG.error("Fail to update identity in zookeeper", e);
        }
        return identity;
    }

    @Override
    protected void doDeleteIdentity(String principalName) {
        principalName = replaceSlash(principalName);
        IdentityZNode identityZNode = new IdentityZNode(zooKeeper, principalName);
        try {
            identityZNode.deleteIdentity();
        } catch (KeeperException e) {
            LOG.error("Fail to delete identity in zookeeper", e);
        }
    }

    @Override
    public List<String> getIdentities(int start, int limit) {
        List<String> identityNames = null;
        try {
            // The identities getting from zookeeper is unordered
            identityNames = IdentityZNodeHelper.getIdentityNames(zooKeeper);
        } catch (KeeperException e) {
            LOG.error("Fail to get identities from zookeeper", e);
        }
        List<String> newIdentities = new ArrayList<>(identityNames.size());
        for(String name : identityNames) {
            if(name.contains("\\")) {
                name = name.replace("\\", "/");
            }
            newIdentities.add(name);
        }
        Collections.sort(newIdentities);
        return newIdentities.subList(start, limit);
    }

    private void setIdentity(KrbIdentity identity) throws KeeperException {
        String principalName = identity.getPrincipalName();
        principalName = replaceSlash(principalName);
        IdentityZNode identityZNode = new IdentityZNode(zooKeeper, principalName);
        identityZNode.setPrincipalName(identity.getPrincipalName());
        identityZNode.setCreatedTime(identity.getCreatedTime());
        identityZNode.setDisabled(identity.isDisabled());
        identityZNode.setExpireTime(identity.getExpireTime());
        identityZNode.setKdcFlags(identity.getKdcFlags());
        identityZNode.setKeys(identity.getKeys());
        identityZNode.setKeyVersion(identity.getKeyVersion());
        identityZNode.setLocked(identity.isLocked());
    }

    private String replaceSlash(String name) {
        if(name.contains("/")) {
            name = name.replace("/", "\\");
        }
        return name;
    }
}
