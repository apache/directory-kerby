package org.haox.transport;

import org.haox.transport.tcp.StreamingDecoder;
import org.haox.transport.tcp.TcpConnector;
import org.haox.transport.tcp.TcpTransportHandler;
import org.haox.transport.udp.UdpConnector;
import org.haox.transport.udp.UdpTransportHandler;

public class Connector {

    private UdpTransportHandler udpTransportHandler;
    private TcpTransportHandler tcpTransportHandler;

    /**
     * TCP transport only, for decoding tcp streaming into messages
     * @param streamingDecoder
     */
    public void setStreamingDecoder(StreamingDecoder streamingDecoder) {
        tcpTransportHandler = new TcpTransportHandler(streamingDecoder);
    }

    /**
     * Connect on the given server address. Can be called multiple times
     * for multiple servers
     * @param serverAddress
     * @param serverPort
     * @param isTCP
     */
    public void connect(String serverAddress, short serverPort, boolean isTCP) {
        TransportConnector tc = null;
        if (isTCP) {
            if (tcpTransportHandler == null) {
                throw new IllegalArgumentException("No streaming decoder set yet");
            }
            tc = new TcpConnector(tcpTransportHandler);
        } else {
            if (udpTransportHandler == null) {
                udpTransportHandler = new UdpTransportHandler();
            }
            tc = new UdpConnector(udpTransportHandler);
        }
        tc.connect(serverAddress, serverPort);
    }

}
