package org.haox.transport;

import org.haox.transport.tcp.StreamingDecoder;
import org.haox.transport.tcp.TcpAcceptor;
import org.haox.transport.tcp.TcpTransportHandler;
import org.haox.transport.udp.UdpAcceptor;
import org.haox.transport.udp.UdpTransportHandler;

public class Acceptor {

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
     * Listen and accept connections on the address. Can be called multiple
     * times for multiple server addresses.
     * @param address
     * @param listenPort
     * @param isTCP
     */
    public void listen(String address, short listenPort, boolean isTCP) {
        TransportAcceptor ta = null;
        if (isTCP) {
            if (tcpTransportHandler == null) {
                throw new IllegalArgumentException("No streaming decoder set yet");
            }
            ta = new TcpAcceptor(tcpTransportHandler);
        } else {
            if (udpTransportHandler == null) {
                udpTransportHandler = new UdpTransportHandler();
            }
            ta = new UdpAcceptor(udpTransportHandler);
        }
        ta.listen(address, listenPort);
    }

}
