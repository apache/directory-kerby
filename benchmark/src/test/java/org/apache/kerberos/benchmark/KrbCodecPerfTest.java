package org.apache.kerberos.benchmark;

import org.apache.directory.api.asn1.DecoderException;
import org.apache.directory.api.asn1.EncoderException;
import org.apache.directory.api.asn1.ber.Asn1Decoder;
import org.apache.directory.shared.kerberos.codec.apReq.ApReqContainer;
import org.apache.kerberos.kerb.KrbException;
import org.apache.kerberos.kerb.spec.ap.ApReq;

import java.io.IOException;
import java.io.InputStream;
import java.nio.ByteBuffer;

public class KrbCodecPerfTest {

    public static void main(String[] args) throws KrbException, IOException, DecoderException, EncoderException {
        InputStream is = KrbCodecPerfTest.class.getResourceAsStream("/apreq.token");
        byte[] bytes = new byte[is.available()];
        is.read(bytes);

        int times = 1000000;
        perfApacheDS(ByteBuffer.wrap(bytes), times);
        perfHaox(ByteBuffer.wrap(bytes), times);
    }

    private static void perfHaox(ByteBuffer apreqToken, int times) throws KrbException, IOException {
        long start = System.currentTimeMillis();

        for (int i = 0; i < times; ++i) {
            //ApReq apReq = KrbCodec.decode(apreqToken, ApReq.class);
            ApReq apReq = new ApReq(); apReq.decode(apreqToken);
            if (apReq == null) {
                throw new RuntimeException("Decoding failed");
            }
            String serverName = apReq.getTicket().getSname().toString();

            apreqToken.rewind();
        }

        long end = System.currentTimeMillis();
        System.out.println("HaoxCodec takes:" + (end - start));
    }

    private static void perfApacheDS(ByteBuffer apreqToken, int times) throws EncoderException, DecoderException {
        long start = System.currentTimeMillis();

        for (int i = 0; i < times; ++i) {
            Asn1Decoder krbDecoder = new Asn1Decoder();
            ApReqContainer apreqContainer = new ApReqContainer(apreqToken);
            krbDecoder.decode(apreqToken, apreqContainer);
            String serverName = apreqContainer.getApReq().getTicket().getSName().toString();

            apreqToken.rewind();
        }

        long end = System.currentTimeMillis();
        System.out.println("ApacheDS takes:" + (end - start));
    }

}
