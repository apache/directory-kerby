package org.haox.kerb.server;

import org.haox.event.EventHub;
import org.haox.kerb.server.identity.IdentityService;
import org.haox.kerb.server.identity.SimpleIdentityBackend;
import org.haox.kerb.server.replay.ReplayCheckService;
import org.haox.kerb.server.replay.ReplayCheckServiceImpl;
import org.haox.transport.Acceptor;
import org.haox.transport.tcp.TcpAcceptor;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.File;

public abstract class AbstractKdcServer
{
    private static final Logger logger = LoggerFactory.getLogger(AbstractKdcServer.class);

    private String kdcHost;
    private short kdcPort;

    private boolean started;
    private String serviceName = "HaoxKdc";

    private EventHub eventHub;

    protected KdcConfig kdcConfig;
    protected IdentityService identityService;
    private ReplayCheckService replayCheckService;
    protected File workDir;

    public AbstractKdcServer() {

    }

    public String getKdcRealm() {
        return kdcConfig.getKdcRealm();
    }

    private String getKdcHost() {
        if (kdcHost != null) {
            return kdcHost;
        }
        return kdcConfig.getKdcHost();
    }

    private short getKdcPort() {
        if (kdcPort > 0) {
            return kdcPort;
        }
        return kdcConfig.getKdcPort();
    }

    public void setKdcHost(String kdcHost) {
        this.kdcHost = kdcHost;
    }

    public void setKdcPort(short kdcPort) {
        this.kdcPort = kdcPort;
    }

    public boolean enableDebug() {
        return kdcConfig.enableDebug();
    }

    public void init() {
        initConfig();

        this.workDir = getWorkDir();

        initIdentityService();
        initReplayCheckService();
    }

    protected File getWorkDir() {
        String path = kdcConfig.getWorkDir();
        File file = new File(path);
        file.mkdirs();
        return file;
    }

    protected abstract void initConfig();

    public void start() {
        logger.info("Starting " + getServiceName());
        try {
            doStart();
        } catch (Exception e) {
            throw new RuntimeException("Failed to start " + getServiceName(), e);
        }

        started = true;

        logger.info("Started " + serviceName);
    }

    protected void doStart() throws Exception {
        this.eventHub = new EventHub();
        eventHub.register(new KdcHandler());

        Acceptor acceptor = new TcpAcceptor(new KrbStreamingDecoder());
        eventHub.register(acceptor);

        eventHub.start();
        acceptor.listen(getKdcHost(), getKdcPort());
    }

    public void stop() {
        logger.info("Stopping " + serviceName);
        try {
            doStop();
        } catch (Exception e) {
            throw new RuntimeException("Failed to stop " + getServiceName());
        }
        logger.info("Stopped " + serviceName);
    }

    protected void doStop() throws Exception {
        eventHub.stop();
    }

    public KdcConfig getConfig() {
        return kdcConfig;
    }

    public boolean isStarted() {
        return started;
    }

    protected void setStarted( boolean started ) {
        this.started = started;
    }

    protected void setServiceName( String name ) {
        this.serviceName = name;
    }

    protected String getServiceName() {
        if (serviceName != null) {
            return serviceName;
        }
        return kdcConfig.getKdcServiceName();
    }

    public IdentityService getIdentityService() {
        return identityService;
    }

    protected void initIdentityService() {
        File identityFile = new File(workDir, "simplekdb.dat");
        this.identityService = new SimpleIdentityBackend(identityFile);
    }

    public ReplayCheckService getReplayCheckService() {
        return replayCheckService;
    }

    protected void initReplayCheckService() {
        this.replayCheckService = new ReplayCheckServiceImpl();
    }
}
