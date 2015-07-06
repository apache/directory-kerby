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
    private String zkHost;
    private int zkPort;
    private File dataFile;
    private File dataLogFile;
    private ZooKeeper zooKeeper;
    private final ZooKeeperServerMain zooKeeperServer = new ZooKeeperServerMain();
    private static Thread zookeeperThread;

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

    /**
     * {@inheritDoc}
     */
    @Override
    public void initialize() {
        super.initialize();
        init();
    }

    /**
     * Init Zookeeper Server and connection service, used to initialize the backend.
     */
    private void init() {
        zkHost = getConfig().getString(ZKConfKey.ZK_HOST);
        zkPort = getConfig().getInt(ZKConfKey.ZK_PORT);

        String dataDir = getConfig().getString(ZKConfKey.DATA_DIR);
        if (dataDir == null || dataDir.isEmpty()) {
            throw new RuntimeException("No data dir is found");
        }

        dataFile = new File(dataDir);
        if (! dataFile.exists()) {
            dataFile.mkdirs();
        }

        String dataLogDir = getConfig().getString(ZKConfKey.DATA_LOG_DIR);
        if (dataLogDir == null || dataLogDir.isEmpty()) {
            throw new RuntimeException("No data log dir is found");
        }

        dataLogFile = new File(dataLogDir);
        if (! dataLogFile.exists()) {
            dataLogFile.mkdirs();
        }

        startEmbeddedZookeeper();
        connectZK();
    }

    /**
     * Prepare connection to Zookeeper server.
     */
    private void connectZK() {
        try {
            zooKeeper = new ZooKeeper(zkHost, 10000, null);
            while (true) {
                if (!zooKeeper.getState().isConnected()) {
                    try {
                        Thread.sleep(100);
                    } catch (InterruptedException e) {
                        e.printStackTrace();
                    }
                } else {
                    break;
                }
            }

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

    /**
     * Start the Zookeeper server
     */
    private void startEmbeddedZookeeper() {

        Properties startupProperties = new Properties();
        startupProperties.put("dataDir", dataFile.getAbsolutePath());
        startupProperties.put("dataLogDir", dataLogFile.getAbsolutePath());
        startupProperties.put("clientPort", zkPort);

        QuorumPeerConfig quorumConfiguration = new QuorumPeerConfig();
        try {
            quorumConfiguration.parseProperties(startupProperties);
        } catch(Exception e) {
            throw new RuntimeException(e);
        }

        final ServerConfig configuration = new ServerConfig();
        configuration.readFrom(quorumConfiguration);

        if (zookeeperThread == null) {
            zookeeperThread = new Thread() {
                public void run() {
                    try {
                        zooKeeperServer.runFromConfig(configuration);
                    } catch (IOException e) {
                        LOG.error("ZooKeeper Failed", e);
                    }
                }
            };
            zookeeperThread.start();
        }
    }

    /**
     * This will watch all the kdb update event so that it's timely synced.
     * @param event The kdb update event ot watch.
     */
    @Override
    public void process(WatchedEvent event) {
        System.out.print("I got an event: " + event);
    }

    /**
     * {@inheritDoc}
     */
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
            return null;
        }
        return krb;
    }

    /**
     * {@inheritDoc}
     */
    @Override
    protected KrbIdentity doAddIdentity(KrbIdentity identity) {
        if (doGetIdentity(identity.getPrincipalName()) != null) {
            throw new RuntimeException("Principal already exists.");
        }
        try {
            setIdentity(identity);
        } catch (KeeperException e) {
            LOG.error("Fail to add identity to zookeeper", e);
            return null;
        }
        return identity;
    }

    /**
     * {@inheritDoc}
     */
    @Override
    protected KrbIdentity doUpdateIdentity(KrbIdentity identity) {
        if (doGetIdentity(identity.getPrincipalName()) == null) {
            throw new RuntimeException("Principal does not exist.");
        }
        try {
            setIdentity(identity);
        } catch (KeeperException e) {
            LOG.error("Fail to update identity in zookeeper", e);
            return null;
        }
        return identity;
    }

    /**
     * {@inheritDoc}
     */
    @Override
    protected void doDeleteIdentity(String principalName) {
        principalName = replaceSlash(principalName);
        if (doGetIdentity(principalName) == null) {
            throw new RuntimeException("Principal does not exist.");
        }
        IdentityZNode identityZNode = new IdentityZNode(zooKeeper, principalName);
        try {
            identityZNode.deleteIdentity();
        } catch (KeeperException e) {
            LOG.error("Fail to delete identity in zookeeper", e);
        }
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public List<String> getIdentities(int start, int limit) {
        if (limit == -1) {
            return getIdentities();
        }

        return getIdentities().subList(start, start + limit);
    }

    /**
     * Get all of the identity names
     * @return
     */
    public List<String> getIdentities() {

        List<String> identityNames = null;
        try {
            // The identities getting from zookeeper is unordered
            identityNames = IdentityZNodeHelper.getIdentityNames(zooKeeper);
        } catch (KeeperException e) {
            LOG.error("Fail to get identities from zookeeper", e);
        }
        if(identityNames == null || identityNames.isEmpty()) {
            return null;
        }
        List<String> newIdentities = new ArrayList<>(identityNames.size());
        for(String name : identityNames) {
            if(name.contains("\\")) {
                name = name.replace("\\", "/");
            }
            newIdentities.add(name);
        }
        Collections.sort(newIdentities);
        return newIdentities;
    }

    /**
     * Set the identity to add or update an indentity in the backend.
     * @param identity . The identity to update
     * @throws KeeperException
     */
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

    /**
     * Use "\\" to replace "/" in  a String object.
     * @param name . The the name string to convert
     * @return
     */
    private String replaceSlash(String name) {
        if(name.contains("/")) {
            name = name.replace("/", "\\");
        }
        return name;
    }
}
