package org.haox.kerb;

import java.io.IOException;
import java.net.DatagramSocket;
import java.net.InetSocketAddress;
import java.nio.ByteBuffer;
import java.nio.channels.DatagramChannel;

public class TestTransportServer {
    private String serverHost = "127.0.0.1";
    private short serverPort = 8181;
    private DatagramChannel serverSocketChannel;

    public void setUp() throws IOException {
        setUpServerSide();
    }

    private void setUpServerSide() throws IOException {
        serverSocketChannel = DatagramChannel.open();
        serverSocketChannel.configureBlocking(true);
        DatagramSocket serverSocket = serverSocketChannel.socket();
        serverSocket.bind(new InetSocketAddress(serverPort));
    }

    public void testUdpTransport() throws IOException {
        setUp();

        while (true) {
            ByteBuffer recvBuffer = ByteBuffer.allocate(65536); // to optimize
            InetSocketAddress fromAddress = (InetSocketAddress) serverSocketChannel.receive(recvBuffer);
            if (fromAddress != null) {
                recvBuffer.flip();
                serverSocketChannel.send(recvBuffer, fromAddress);
            }

            try {
                Thread.sleep(1000);
            } catch (InterruptedException e) {
                e.printStackTrace();
            }
        }
    }

    public static void main(String[] args) throws IOException {
        TestTransportServer server = new TestTransportServer();
        server.testUdpTransport();
    }

}
