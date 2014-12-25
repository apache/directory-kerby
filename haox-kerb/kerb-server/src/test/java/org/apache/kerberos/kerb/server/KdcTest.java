package org.apache.kerberos.kerb.server;

import org.junit.After;
import org.junit.Before;
import org.junit.Test;

import java.io.IOException;
import java.net.InetSocketAddress;
import java.net.SocketAddress;
import java.nio.ByteBuffer;
import java.nio.channels.SocketChannel;

public class KdcTest {

    private String serverHost = "localhost";
    private short serverPort = 8089;

    private SimpleKdcServer kdcServer;

    @Before
    public void setUp() throws Exception {
        kdcServer = new SimpleKdcServer();
        kdcServer.setKdcHost(serverHost);
        kdcServer.setKdcPort(serverPort);
        kdcServer.init();
        kdcServer.start();
    }

    @Test
    public void testKdc() throws IOException, InterruptedException {
        Thread.sleep(15);

        SocketChannel socketChannel = SocketChannel.open();
        socketChannel.configureBlocking(true);
        SocketAddress sa = new InetSocketAddress(serverHost, serverPort);
        socketChannel.connect(sa);

        String BAD_KRB_MESSAGE = "Hello World!";
        ByteBuffer writeBuffer = ByteBuffer.allocate(4 + BAD_KRB_MESSAGE.getBytes().length);
        writeBuffer.putInt(BAD_KRB_MESSAGE.getBytes().length);
        writeBuffer.put(BAD_KRB_MESSAGE.getBytes());
        writeBuffer.flip();

        socketChannel.write(writeBuffer);
    }

    @After
    public void tearDown() throws Exception {
        kdcServer.stop();
    }
}