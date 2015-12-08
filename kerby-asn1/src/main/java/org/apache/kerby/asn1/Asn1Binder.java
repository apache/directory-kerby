package org.apache.kerby.asn1;

import org.apache.kerby.asn1.parse.Asn1ParsingResult;
import org.apache.kerby.asn1.type.Asn1Object;
import org.apache.kerby.asn1.type.Asn1Type;

import java.io.IOException;

/**
 * Decode and bind a parsing result to an ASN1 object.
 */
public final class Asn1Binder {

    private Asn1Binder() {

    }

    public static void bind(Asn1ParsingResult parsingResult,
                            Asn1Type value) throws IOException {
        value.useDefinitiveLength(parsingResult.isDefinitiveLength());
        ((Asn1Object) value).decode(parsingResult);
    }

    public static void bindWithTagging(Asn1ParsingResult parsingResult,
                                       Asn1Type value, TaggingOption taggingOption) throws IOException {
        if (!parsingResult.isTagSpecific()) {
            throw new IllegalArgumentException(
                "Attempting to decode non-tagged value using tagging way");
        }
        ((Asn1Object) value).taggedDecode(parsingResult, taggingOption);
    }
}
