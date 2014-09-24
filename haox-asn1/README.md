haox-asn1
=========

### A ASN1 parser with easy and simple API

```
// encoding
Asn1Integer aValue = new Asn1Integer(8899);
byte[] encoded = aValue.encode();

// decoding
byte[] contentToDecode = ...
Asn1Integer decodedValue = new Asn1Integer();
decodedValue.decode(contentToDecode);
Integer value = decodedValue.getValue();
```

### Data-driven ASN1 encoding/decoding framework and parser

With the following definition from Kerberos protocol
```
 AuthorizationData ::= SEQUENCE OF SEQUENCE {
     ad-type         [0] Int32,
     ad-data         [1] OCTET STRING
 }
 ```
 
You can model AuthzDataEntry as follows
```
public class AuthzDataEntry extends Asn1SequenceType {
    static int AD_TYPE = 0;
    static int AD_DATA = 1;

    public AuthzDataEntry() {
        super(new Asn1FieldInfo[] {
                new Asn1FieldInfo(AD_TYPE, Asn1Integer.class),
                new Asn1FieldInfo(AD_DATA, Asn1OctetString.class)
        });
    }

    public int getAuthzType() {
        Integer value = getFieldAsInteger(AD_TYPE);
        return value;
    }

    public byte[] getAuthzData() {
        return getFieldAsOctetBytes(AD_DATA);
    }
}
```

And then define AuthorizationData simply
```
public class AuthorizationData extends Asn1SequenceOf<AuthzDataEntry> {

}
```

Then you can process with above definitions, encode and decode, without caring about the details.

Think about how to implement the more complex sample from [ITU-T Rec. X.680 ISO/IEC 8824-1](http://www.itu.int/ITU-T/studygroups/com17/languages/X.690-0207.pdf), 
Please look at [PersonnelRecord.java](https://github.com/drankye/haox/blob/master/haox-asn1/src/test/java/org/haox/asn1/PersonnelRecord.java) unit test case.
```
A.1 ASN.1 description of the record structure
The structure of the hypothetical personnel record is formally described below using ASN.1 specified in
ITU-T Rec. X.680 | ISO/IEC 8824-1 for defining types.

PersonnelRecord ::= [APPLICATION 0] IMPLICIT SET {
    Name Name,
    title [0] VisibleString,
    number EmployeeNumber,
    dateOfHire [1] Date,
    nameOfSpouse [2] Name,
    children [3] IMPLICIT
    SEQUENCE OF ChildInformation DEFAULT {} 
}

ChildInformation ::= SET {
    name Name,
    dateOfBirth [0] Date
}

Name ::= [APPLICATION 1] IMPLICIT SEQUENCE {
    givenName VisibleString,
    initial VisibleString,
    familyName VisibleString
}

EmployeeNumber ::= [APPLICATION 2] IMPLICIT INTEGER
Date ::= [APPLICATION 3] IMPLICIT VisibleString -- YYYYMMDD
```

### Notes
* 90% tests coverage for DER encoding
* For BER & CER encoding, to be fully supported
* No extra dependency

### License
Apache V2 License



