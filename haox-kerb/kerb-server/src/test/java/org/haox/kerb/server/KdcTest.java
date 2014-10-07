package org.haox.kerb.server;

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
    private short serverPort = 8088;

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
        Thread.sleep(10);

        SocketChannel socketChannel = SocketChannel.open();
        socketChannel.configureBlocking(true);
        SocketAddress sa = new InetSocketAddress(serverHost, serverPort);
        socketChannel.connect(sa);
        String TEST_MESSAGE = "Hello World!";
        ByteBuffer writeBuffer = ByteBuffer.allocate(4 + TEST_MESSAGE.getBytes().length);
        writeBuffer.putInt(TEST_MESSAGE.getBytes().length);
        writeBuffer.put(TEST_MESSAGE.getBytes());
        writeBuffer.flip();
        socketChannel.write(writeBuffer);
        ByteBuffer byteBuffer = ByteBuffer.allocate(65536);
        socketChannel.read(byteBuffer);
        byteBuffer.flip();
        //clientRecvedMessage = recvBuffer2String(byteBuffer);

        //Assert.assertEquals(TEST_MESSAGE, clientRecvedMessage);
    }

    @After
    public void tearDown() throws Exception {
        kdcServer.stop();
    }
}