package org.apache.commons.ssl;

import static org.junit.Assert.assertTrue;
import org.junit.Test;

import java.io.ByteArrayInputStream;
import java.util.Arrays;
import java.util.Random;


public class TestBase64 {

    @Test
    public void testOrigBase64() throws Exception {
        Random random = new Random();
        for (int i = 0; i < 4567; i++) {
            byte[] buf = new byte[i];
            random.nextBytes(buf);
            byte[] enc = Base64.encodeBase64(buf);
            ByteArrayInputStream in = new ByteArrayInputStream(enc);
            enc = Util.streamToBytes(in);
            byte[] dec = Base64.decodeBase64(enc);
            boolean result = Arrays.equals(buf, dec);
            if (!result) {
                System.out.println();
                System.out.println("testOrigBase64 Failed on : " + i);
            }
            assertTrue(result);
        }
        for (int i = 5; i < 50; i++) {
            int testSize = (i * 1000) + 123;
            byte[] buf = new byte[testSize];
            random.nextBytes(buf);
            byte[] enc = Base64.encodeBase64(buf);
            ByteArrayInputStream in = new ByteArrayInputStream(enc);
            enc = Util.streamToBytes(in);            
            byte[] dec = Base64.decodeBase64(enc);
            boolean result = Arrays.equals(buf, dec);
            if (!result) {
                System.out.println();
                System.out.println("testOrigBase64 Failed on : " + testSize);
            }
            assertTrue(result);
        }
    }

    @Test
    public void testBase64() throws Exception {
        Random random = new Random();
        for (int i = 0; i < 4567; i++) {
            byte[] buf = new byte[i];
            random.nextBytes(buf);

            ByteArrayInputStream in = new ByteArrayInputStream( buf );
            Base64InputStream base64 = new Base64InputStream(in,true);
            byte[] enc = Util.streamToBytes(base64);
            in = new ByteArrayInputStream( enc );
            base64 = new Base64InputStream(in);
            byte[] dec = Util.streamToBytes(base64);

            boolean result = Arrays.equals(buf, dec);
            if (!result) {
                System.out.println();
                System.out.println("testBase64 Failed on : " + i);                                
            }
            assertTrue(result);
        }
        for (int i = 5; i < 50; i++) {
            int testSize = (i * 1000) + 123;
            byte[] buf = new byte[testSize];
            random.nextBytes(buf);

            ByteArrayInputStream in = new ByteArrayInputStream( buf );
            Base64InputStream base64 = new Base64InputStream(in,true);
            byte[] enc = Util.streamToBytes(base64);
            in = new ByteArrayInputStream( enc );
            base64 = new Base64InputStream(in);
            byte[] dec = Util.streamToBytes(base64);

            boolean result = Arrays.equals(buf, dec);
            if (!result) {
                System.out.println();
                System.out.println("testBase64 Failed on : " + testSize);
            }
            assertTrue(result);
        }

    }
}
