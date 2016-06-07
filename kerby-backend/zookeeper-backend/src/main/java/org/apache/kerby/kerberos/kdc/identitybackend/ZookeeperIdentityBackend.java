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
import org.apache.kerby.kerberos.kerb.KrbException;
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
 */
public class ZookeeperIdentityBackend extends AbstractIdentityBackend {
    private static Thread zookeeperThread;
    private final ZooKeeperServerMain zooKeeperServer = new ZooKeeperServerMain();
    private String zkHost;
    private int zkPort;
    private File dataDir;
    private ZooKeeper zooKeeper;
    private static final Logger LOG = LoggerFactory.getLogger(ZookeeperIdentityBackend.class);

    public ZookeeperIdentityBackend() {

    }

    /**
     * Constructing an instance using specified config that contains anything
     * to be used to init the Zookeeper backend.
     * @param config The configuration for zookeeper identity backend.
     */
    public ZookeeperIdentityBackend(Config config) {
         setConfig(config);
    }

    /**
     * {@inheritDoc}
     */
    @Override
    protected void doInitialize() throws KrbException {
        LOG.info("Initializing the Zookeeper identity backend.");
        init();
    }

    /**
     * {@inheritDoc}
     */
    @Override
    protected void doStop() throws KrbException {
        try {
            zooKeeper.close();
        } catch (InterruptedException e) {
            e.printStackTrace();
        }
        LOG.info("Zookeeper session closed.");
    }

    /**
     * Init Zookeeper Server and connection service, used to initialize the backend.
     */
    private void init() throws KrbException {
        zkHost = getConfig().getString(ZKConfKey.ZK_HOST, true);
        zkPort = getConfig().getInt(ZKConfKey.ZK_PORT, true);

        String dataDirString = getConfig().getString(ZKConfKey.DATA_DIR, true);
        if (dataDirString == null || dataDirString.isEmpty()) {
            File zooKeeperDir = new File(getBackendConfig().getConfDir(), "zookeeper");
            dataDir = new File(zooKeeperDir, "data");
        } else {
            dataDir = new File(dataDirString);
        }

        if (!dataDir.exists() && !dataDir.mkdirs()) {
            throw new KrbException("could not create data file dir " + dataDir);
        }

        LOG.info("Data dir: " + dataDir);

        if (getConfig().getBoolean(ZKConfKey.EMBEDDED_ZK, true)) {
            startEmbeddedZookeeper();
        }
        connectZK();
    }

    /**
     * Prepare connection to Zookeeper server.
     */
    private void connectZK() throws KrbException {
        try {
            String serverStr = zkHost + ":" + zkPort;
            zooKeeper = new ZooKeeper(serverStr, 10000, new MyWatcher());
            while (true) {
                if (!zooKeeper.getState().isConnected()) {
                    try {
                        Thread.sleep(100);
                    } catch (InterruptedException e) {
                        e.printStackTrace();
                    }
                } else {
                    LOG.info("Success connect to zookeeper server.");
                    break;
                }
            }

        } catch (IOException e) {
            LOG.error("Error occurred while connecting to zookeeper.");
            throw new KrbException("Failed to prepare Zookeeper connection");
        }
    }

    /**
     * Start the Zookeeper server
     */
    private void startEmbeddedZookeeper() throws KrbException {
        Properties startupProperties = new Properties();
        startupProperties.put("dataDir", dataDir.getAbsolutePath());
        startupProperties.put("clientPort", zkPort);

        QuorumPeerConfig quorumConfiguration = new QuorumPeerConfig();
        try {
            quorumConfiguration.parseProperties(startupProperties);
        } catch (Exception e) {
            throw new KrbException("Loading quorum configuraiton failed", e);
        }

        final ServerConfig configuration = new ServerConfig();
        configuration.readFrom(quorumConfiguration);

        if (zookeeperThread == null) {
            zookeeperThread = new Thread() {
                public void run() {
                    try {
                        zooKeeperServer.runFromConfig(configuration);
                    } catch (IOException e) {
                        LOG.warn(e.getMessage());
                    }
                }
            };
            zookeeperThread.setDaemon(true);
            zookeeperThread.start();
        }
        LOG.info("Embedded Zookeeper started.");
    }

    /**
     * {@inheritDoc}
     */
    @Override
    protected KrbIdentity doGetIdentity(String principalName) throws KrbException {
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
            throw new KrbException("Fail to get identity from zookeeper", e);
        }

        return krb;
    }

    /**
     * {@inheritDoc}
     */
    @Override
    protected KrbIdentity doAddIdentity(KrbIdentity identity) throws KrbException {
        try {
            setIdentity(identity);
        } catch (Exception e) {
            throw new KrbException("Fail to add identity to zookeeper", e);
        }
        return doGetIdentity(identity.getPrincipalName());
    }

    /**
     * {@inheritDoc}
     */
    @Override
    protected KrbIdentity doUpdateIdentity(KrbIdentity identity) throws KrbException {
        try {
            setIdentity(identity);
        } catch (Exception e) {
            throw new KrbException("Fail to update identity in zookeeper", e);
        }
        return doGetIdentity(identity.getPrincipalName());
    }

    /**
     * {@inheritDoc}
     */
    @Override
    protected void doDeleteIdentity(String principalName) throws KrbException {
        principalName = replaceSlash(principalName);
        IdentityZNode identityZNode = new IdentityZNode(zooKeeper, principalName);
        try {
            identityZNode.deleteIdentity();
        } catch (KeeperException e) {
            throw new KrbException("Fail to delete identity in zookeeper", e);
        }
    }

    /**
     * {@inheritDoc}
     */
    @Override
    protected Iterable<String> doGetIdentities() throws KrbException {
        List<String> identityNames;

        try {
            // The identities getting from zookeeper is unordered
            identityNames = IdentityZNodeHelper.getIdentityNames(zooKeeper);
        } catch (KeeperException e) {
            throw new KrbException("Fail to get identities from zookeeper", e);
        }

        if (identityNames == null || identityNames.isEmpty()) {
            return null;
        }

        List<String> newIdentities = new ArrayList<>(identityNames.size());
        for (String name : identityNames) {
            if (name.contains("\\")) {
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
     * @throws org.apache.zookeeper.KeeperException
     */
    private void setIdentity(KrbIdentity identity) throws KeeperException, IOException {
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
        if (name.contains("/")) {
            name = name.replace("/", "\\");
        }
        return name;
    }

    class MyWatcher implements Watcher {

        /**
         * This will watch all the kdb update event so that it's timely synced.
         * @param event The kdb update event ot watch.
         */
        public void process(WatchedEvent event) {
//            System.out.println("I got an event: " + event.getPath());
        }

    }
}
