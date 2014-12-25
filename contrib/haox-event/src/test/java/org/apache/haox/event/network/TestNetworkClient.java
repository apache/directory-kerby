package org.apache.haox.event.network;

import junit.framework.Assert;
import org.apache.haox.event.Event;
import org.apache.haox.event.EventHandler;
import org.apache.haox.event.EventHub;
import org.apache.haox.event.EventWaiter;
import org.apache.haox.transport.MessageHandler;
import org.apache.haox.transport.Network;
import org.apache.haox.transport.Transport;
import org.apache.haox.transport.event.MessageEvent;
import org.apache.haox.transport.event.TransportEvent;
import org.apache.haox.transport.event.TransportEventType;
import org.junit.After;
import org.junit.Before;
import org.junit.Test;

import java.io.IOException;
import java.net.DatagramSocket;
import java.net.InetSocketAddress;
import java.net.ServerSocket;
import java.nio.ByteBuffer;
import java.nio.channels.*;
import java.util.Iterator;
import java.util.Set;

public class TestNetworkClient extends TestNetworkBase {

    private EventHub eventHub;
    private EventWaiter eventWaiter;

    @Before
    public void setUp() throws IOException {
        setUpServer();
        setUpClient();
    }

    private void setUpServer() {
        new Thread(new Runnable() {
            @Override
            public void run() {
                try {
                    doRunTcpServer();
                } catch (IOException e) {
                    e.printStackTrace();
                }
            }
        }).start();

        new Thread(new Runnable() {
            @Override
            public void run() {
                try {
                    doRunUdpServer();
                } catch (IOException e) {
                    e.printStackTrace();
                }
            }
        }).start();
    }

    private void doRunTcpServer() throws IOException {
        ServerSocketChannel serverSocketChannel;
        Selector selector = Selector.open();
        serverSocketChannel = ServerSocketChannel .open();
        serverSocketChannel.configureBlocking(false);
        ServerSocket serverSocket = serverSocketChannel.socket();
        serverSocket.bind(new InetSocketAddress(tcpPort));
        serverSocketChannel.register(selector, SelectionKey.OP_ACCEPT);

        SocketChannel socketChannel;
        while (true) {
            if (selector.selectNow() > 0) {
                Set<SelectionKey> selectionKeys = selector.selectedKeys();
                Iterator<SelectionKey> iterator = selectionKeys.iterator();
                while (iterator.hasNext()) {
                    SelectionKey selectionKey = iterator.next();
                    iterator.remove();

                    if (selectionKey.isAcceptable()) {
                        while ((socketChannel = serverSocketChannel.accept()) != null) {
                            socketChannel.configureBlocking(false);
                            socketChannel.socket().setTcpNoDelay(true);
                            socketChannel.socket().setKeepAlive(true);
                            socketChannel.register(selector, SelectionKey.OP_READ | SelectionKey.OP_WRITE, socketChannel);
                            //selectionKey.attach(socketChannel);
                        }
                    } else if (selectionKey.isReadable()) {
                        ByteBuffer recvBuffer = ByteBuffer.allocate(65536);
                        socketChannel = (SocketChannel) selectionKey.attachment();
                        if (socketChannel.read(recvBuffer) > 0) {
                            recvBuffer.flip();
                            socketChannel.write(recvBuffer);
                        }
                    }
                }

                try {
                    Thread.sleep(1000);
                } catch (InterruptedException e) {
                    e.printStackTrace();
                }
            }
        }
    }

    private void doRunUdpServer() throws IOException {
        DatagramChannel serverSocketChannel;
        Selector selector = Selector.open();
        serverSocketChannel = DatagramChannel.open();
        serverSocketChannel.configureBlocking(false);
        DatagramSocket serverSocket = serverSocketChannel.socket();
        serverSocket.bind(new InetSocketAddress(udpPort));
        serverSocketChannel.register(selector, SelectionKey.OP_READ);

        while (true) {
            if (selector.selectNow() > 0) {
                Set<SelectionKey> selectionKeys = selector.selectedKeys();
                Iterator<SelectionKey> iterator = selectionKeys.iterator();
                while (iterator.hasNext()) {
                    SelectionKey selectionKey = iterator.next();
                    iterator.remove();
                    if (selectionKey.isReadable()) {
                        ByteBuffer recvBuffer = ByteBuffer.allocate(65536);
                        InetSocketAddress fromAddress = (InetSocketAddress) serverSocketChannel.receive(recvBuffer);
                        if (fromAddress != null) {
                            recvBuffer.flip();
                            serverSocketChannel.send(recvBuffer, fromAddress);
                        }
                    }
                }

                try {
                    Thread.sleep(1000);
                } catch (InterruptedException e) {
                    e.printStackTrace();
                }
            }
        }
    }

    private void setUpClient() throws IOException {
        eventHub = new EventHub();

        EventHandler messageHandler = new MessageHandler() {
            @Override
            protected void handleMessage(MessageEvent event) {
                if (event.getEventType() == TransportEventType.INBOUND_MESSAGE) {
                    ByteBuffer buffer = event.getMessage();
                    if (buffer != null) {
                        clientRecvedMessage = recvBuffer2String(buffer);
                        System.out.println("Recved clientRecvedMessage: " + clientRecvedMessage);
                        Boolean result = TEST_MESSAGE.equals(clientRecvedMessage);
                        dispatch(new Event(TestEventType.FINISHED, result));
                    }
                }
            }
        };
        eventHub.register(messageHandler);

        Network network = new Network();
        network.setStreamingDecoder(createStreamingDecoder());
        eventHub.register(network);

        eventWaiter = eventHub.waitEvent(
                TestEventType.FINISHED,
                TransportEventType.NEW_TRANSPORT);

        eventHub.start();
        network.tcpConnect(serverHost, tcpPort);
        network.udpConnect(serverHost, udpPort);
    }

    @Test
    public void testNetworkClient() {
        Event event = eventWaiter.waitEvent(TransportEventType.NEW_TRANSPORT);
        Transport transport = ((TransportEvent) event).getTransport();
        transport.sendMessage(ByteBuffer.wrap(TEST_MESSAGE.getBytes()));
        event = eventWaiter.waitEvent(TestEventType.FINISHED);
        Assert.assertTrue((Boolean) event.getEventData());

        event = eventWaiter.waitEvent(TransportEventType.NEW_TRANSPORT);
        transport = ((TransportEvent) event).getTransport();
        transport.sendMessage(ByteBuffer.wrap(TEST_MESSAGE.getBytes()));
        event = eventWaiter.waitEvent(TestEventType.FINISHED);
        Assert.assertTrue((Boolean) event.getEventData());
    }

    @After
    public void cleanup() {
        eventHub.stop();
    }
}
