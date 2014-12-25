package org.haox.kerb.common;

import org.haox.kerb.codec.KrbCodec;
import org.haox.kerb.spec.common.KrbMessage;
import org.haox.transport.Transport;

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
