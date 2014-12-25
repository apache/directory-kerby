package org.apache.kerberos.kerb.common;

import org.apache.kerberos.kerb.codec.KrbCodec;
import org.apache.kerberos.kerb.spec.common.KrbMessage;
import org.apache.haox.transport.Transport;

import java.io.IOException;
import java.nio.ByteBuffer;

public class KrbUtil {

    public static void sendMessage(KrbMessage message, Transport transport) {
        int bodyLen = message.encodingLength();
        ByteBuffer buffer = ByteBuffer.allocate(bodyLen + 4);
        buffer.putInt(bodyLen);
        message.encode(buffer);
        buffer.flip();
        transport.sendMessage(buffer);
    }

    public static KrbMessage decodeMessage(ByteBuffer message) throws IOException {
        int bodyLen = message.getInt();
        assert (message.remaining() >= bodyLen);

        KrbMessage krbMessage = KrbCodec.decodeMessage(message);

        return krbMessage;
    }

}
