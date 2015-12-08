package org.apache.kerby.asn1;

import org.apache.kerby.asn1.parse.Asn1ParseResult;
import org.apache.kerby.asn1.type.Asn1Encodeable;
import org.apache.kerby.asn1.type.Asn1Type;

import java.io.IOException;

/**
 * Decode and bind a parsing result to an ASN1 object.
 */
public final class Asn1Binder {

    private Asn1Binder() {

    }

    public static void bind(Asn1ParseResult parseResult,
                            Asn1Type value) throws IOException {
        value.useDefinitiveLength(parseResult.isDefinitiveLength());
        ((Asn1Encodeable) value).decode(parseResult);
    }

    public static void bindWithTagging(Asn1ParseResult parseResult,
                                       Asn1Type value, TaggingOption taggingOption) throws IOException {
        if (!parseResult.isTagSpecific()) {
            throw new IllegalArgumentException(
                "Attempting to decode non-tagged value using tagging way");
        }
        ((Asn1Encodeable) value).taggedDecode(parseResult, taggingOption);
    }
}
