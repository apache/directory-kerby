package org.haox.kerb.server;

import org.apache.directory.api.util.Strings;
import org.apache.directory.server.i18n.I18n;
import org.apache.directory.shared.kerberos.KerberosConstants;
import org.apache.directory.shared.kerberos.codec.options.ApOptions;
import org.apache.directory.shared.kerberos.exceptions.ErrorType;
import org.apache.directory.shared.kerberos.exceptions.KerberosException;
import org.haox.kerb.codec.KrbCodec;
import org.haox.kerb.server.shared.crypto.KeyUsage;
import org.haox.kerb.server.shared.crypto.encryption.CipherTextHandler;
import org.haox.kerb.server.shared.replay.ReplayCheckService;
import org.haox.kerb.server.shared.store.PrincipalStore;
import org.haox.kerb.server.shared.store.PrincipalStoreEntry;
import org.haox.kerb.spec.KrbException;
import org.haox.kerb.spec.type.KerberosTime;
import org.haox.kerb.spec.type.ap.ApReq;
import org.haox.kerb.spec.type.ap.Authenticator;
import org.haox.kerb.spec.type.common.*;
import org.haox.kerb.spec.type.ticket.EncTicketPart;
import org.haox.kerb.spec.type.ticket.Ticket;

import javax.security.auth.kerberos.KerberosPrincipal;
import java.net.InetAddress;
import java.text.ParseException;
import java.text.SimpleDateFormat;
import java.util.*;


/**
 * An utility class for Kerberos.
 */
public class KerberosUtils
{
    /** A constant for integer optional values */
    public static final int NULL = -1;

    /** An empty list of principal names */
    public static final List<String> EMPTY_PRINCIPAL_NAME = new ArrayList<String>();

    /** 
     * an order preserved map containing cipher names to the corresponding algorithm 
     * names in the descending order of strength
     */
    private static final Map<String, String> cipherAlgoMap = new LinkedHashMap<String, String>();

    public static final TimeZone UTC_TIME_ZONE = TimeZone.getTimeZone( "UTC" );

    /** Defines a default date format with a "yyyyMMddHHmmss'Z'" pattern */
    public static final SimpleDateFormat UTC_DATE_FORMAT = new SimpleDateFormat( "yyyyMMddHHmmss'Z'" );

    /**
     * Parse a KerberosPrincipal instance and return the names. The Principal name
     * is described in RFC 1964 : <br/>
     * <br/>
     * This name type corresponds to the single-string representation of a<br/>
     * Kerberos name.  (Within the MIT Kerberos V5 implementation, such<br/>
     * names are parseable with the krb5_parse_name() function.)  The<br/>
     * elements included within this name representation are as follows,<br/>
     * proceeding from the beginning of the string:<br/>
     * <br/>
     *  (1) One or more principal name components; if more than one<br/>
     *  principal name component is included, the components are<br/>
     *  separated by `/`.  Arbitrary octets may be included within<br/>
     *  principal name components, with the following constraints and<br/>
     *  special considerations:<br/>
     * <br/>
     *     (1a) Any occurrence of the characters `@` or `/` within a<br/>
     *     name component must be immediately preceded by the `\`<br/>
     *     quoting character, to prevent interpretation as a component<br/>
     *     or realm separator.<br/>
     * <br/>
     *     (1b) The ASCII newline, tab, backspace, and null characters<br/>
     *     may occur directly within the component or may be<br/>
     *     represented, respectively, by `\n`, `\t`, `\b`, or `\0`.<br/>
     * <br/>
     *     (1c) If the `\` quoting character occurs outside the contexts<br/>
     *     described in (1a) and (1b) above, the following character is<br/>
     *     interpreted literally.  As a special case, this allows the<br/>
     *     doubled representation `\\` to represent a single occurrence<br/>
     *     of the quoting character.<br/>
     * <br/>
     *     (1d) An occurrence of the `\` quoting character as the last<br/>
     *     character of a component is illegal.<br/>
     * <br/>
     *  (2) Optionally, a `@` character, signifying that a realm name<br/>
     *  immediately follows. If no realm name element is included, the<br/>
     *  local realm name is assumed.  The `/` , `:`, and null characters<br/>
     *  may not occur within a realm name; the `@`, newline, tab, and<br/>
     *  backspace characters may be included using the quoting<br/>
     *  conventions described in (1a), (1b), and (1c) above.<br/>
     * 
     * @param principal The principal to be parsed
     * @return The names as a List of nameComponent
     * 
     * @throws java.text.ParseException if the name is not valid
     */
    public static List<String> getNames( KerberosPrincipal principal ) throws ParseException
    {
        if ( principal == null )
        {
            return EMPTY_PRINCIPAL_NAME;
        }

        String names = principal.getName();

        if ( Strings.isEmpty( names ) )
        {
            // Empty name...
            return EMPTY_PRINCIPAL_NAME;
        }

        return getNames( names );
    }


    /**
     * Parse a PrincipalName and return the names.
     */
    public static List<String> getNames( String principalNames ) throws ParseException
    {
        if ( principalNames == null )
        {
            return EMPTY_PRINCIPAL_NAME;
        }

        List<String> nameComponents = new ArrayList<String>();

        // Start the parsing. Another State Machine :)
        char[] chars = principalNames.toCharArray();

        boolean escaped = false;
        boolean done = false;
        int start = 0;
        int pos = 0;

        for ( int i = 0; i < chars.length; i++ )
        {
            pos = i;

            switch ( chars[i] )
            {
                case '\\':
                    escaped = !escaped;
                    break;

                case '/':
                    if ( escaped )
                    {
                        escaped = false;
                    }
                    else
                    {
                        // We have a new name component
                        if ( i - start > 0 )
                        {
                            String nameComponent = new String( chars, start, i - start );
                            nameComponents.add( nameComponent );
                            start = i + 1;
                        }
                        else
                        {
                            throw new ParseException( I18n.err( I18n.ERR_628 ), i );
                        }
                    }

                    break;

                case '@':
                    if ( escaped )
                    {
                        escaped = false;
                    }
                    else
                    {
                        // We have reached the realm : let's get out
                        done = true;
                    }

                    break;

                default:
            }

            if ( done )
            {
                // We have a new name component
                if ( i - start > 0 )
                {
                    String nameComponent = new String( chars, start, i - start );
                    nameComponents.add( nameComponent );
                    start = i + 1;
                }
                else
                {
                    throw new ParseException( I18n.err( I18n.ERR_628 ), i );
                }

                break;
            }
            else if ( i + 1 == chars.length )
            {
                // We have a new name component
                String nameComponent = new String( chars, start, i - start + 1 );
                nameComponents.add( nameComponent );

                break;
            }
        }

        if ( escaped )
        {
            throw new ParseException( I18n.err( I18n.ERR_629 ), pos );
        }

        return nameComponents;
    }


    /**
     * Constructs a KerberosPrincipal from a PrincipalName and an
     * optional realm
     *
     * @param principal The principal name and type
     * @param realm The optional realm
     *
     * @return A KerberosPrincipal
     */
    public static KerberosPrincipal getKerberosPrincipal( PrincipalName principal, String realm ) throws KrbException {
        String name = principal.getName();

        if ( !Strings.isEmpty( realm ) )
        {
            name += '@' + realm;
        }

        return new KerberosPrincipal( name, principal.getNameType().getValue() );
    }


    /**
     * Get the matching encryption type from the configured types, searching
     * into the requested types. We returns the first we find.
     *
     * @param requestedTypes The client encryption types
     * @param configuredTypes The configured encryption types
     * @return The first matching encryption type.
     */
    public static EncryptionType getBestEncryptionType( Set<EncryptionType> requestedTypes,
        Set<EncryptionType> configuredTypes )
    {
        for ( EncryptionType encryptionType : configuredTypes )
        {
            if ( requestedTypes.contains( encryptionType ) )
            {
                return encryptionType;
            }
        }

        return null;
    }


    /**
     * Build a list of encryptionTypes
     *
     * @param encryptionTypes The encryptionTypes
     * @return A list comma separated of the encryptionTypes
     */
    public static String getEncryptionTypesString( Set<EncryptionType> encryptionTypes )
    {
        StringBuilder sb = new StringBuilder();
        boolean isFirst = true;

        for ( EncryptionType etype : encryptionTypes )
        {
            if ( isFirst )
            {
                isFirst = false;
            }
            else
            {
                sb.append( ", " );
            }

            sb.append( etype );
        }

        return sb.toString();
    }


    public static boolean isKerberosString( byte[] value )
    {
        if ( value == null )
        {
            return false;
        }

        for ( byte b : value )
        {
            if ( ( b < 0x20 ) || ( b > 0x7E ) )
            {
                return false;
            }
        }

        return true;
    }

    /**
     * Get a PrincipalStoreEntry given a principal.  The ErrorType is used to indicate
     * whether any resulting error pertains to a server or client.
     */
    public static PrincipalStoreEntry getEntry( KerberosPrincipal principal, PrincipalStore store, ErrorType errorType )
        throws KerberosException
    {
        PrincipalStoreEntry entry = null;

        try
        {
            entry = store.getPrincipal( principal );
        }
        catch ( Exception e )
        {
            throw new KerberosException( errorType, e );
        }

        if ( entry == null )
        {
            throw new KerberosException( errorType );
        }

        if ( entry.getKeyMap() == null || entry.getKeyMap().isEmpty() )
        {
            throw new KerberosException( ErrorType.KDC_ERR_NULL_KEY );
        }

        return entry;
    }


    /**
         * Verifies an AuthHeader using guidelines from RFC 1510 section A.10., "KRB_AP_REQ verification."
         *
         * @param authHeader
         * @param ticket
         * @param serverKey
         * @param clockSkew
         * @param replayCache
         * @param emptyAddressesAllowed
         * @param clientAddress
         * @param lockBox
         * @param authenticatorKeyUsage
         * @param isValidate
         * @return The authenticator.
         * @throws org.apache.directory.shared.kerberos.exceptions.KerberosException
         */
    public static Authenticator verifyAuthHeader( ApReq authHeader, Ticket ticket, EncryptionKey serverKey,
        long clockSkew, ReplayCheckService replayCache, boolean emptyAddressesAllowed, InetAddress clientAddress,
        CipherTextHandler lockBox, KeyUsage authenticatorKeyUsage, boolean isValidate ) throws KerberosException, KrbException {
        if ( authHeader.getPvno() != KerberosConstants.KERBEROS_V5 )
        {
            throw new KerberosException( ErrorType.KRB_AP_ERR_BADVERSION );
        }

        if (authHeader.getMsgType() != KrbMessageType.AP_REP)
        {
            throw new KerberosException( ErrorType.KRB_AP_ERR_MSG_TYPE );
        }

        if ( authHeader.getTicket().getTktvno() != KerberosConstants.KERBEROS_V5 )
        {
            throw new KerberosException( ErrorType.KRB_AP_ERR_BADVERSION );
        }

        EncryptionKey ticketKey = null;

        if ( authHeader.getApOptions().isFlagSet(ApOptions.USE_SESSION_KEY) )
        {
            ticketKey = authHeader.getTicket().getEncPart().getKey();
        }
        else
        {
            ticketKey = serverKey;
        }

        if ( ticketKey == null )
        {
            // TODO - check server key version number, skvno; requires store
            //            if ( false )
            //            {
            //                throw new KerberosException( ErrorType.KRB_AP_ERR_BADKEYVER );
            //            }

            throw new KerberosException( ErrorType.KRB_AP_ERR_NOKEY );
        }

        byte[] encTicketPartData = lockBox.decrypt(ticketKey, ticket.getEncryptedEncPart(),
            KeyUsage.AS_OR_TGS_REP_TICKET_WITH_SRVKEY );
        EncTicketPart encPart = KrbCodec.decode(encTicketPartData, EncTicketPart.class);
        ticket.setEncPart(encPart);

        byte[] authenticatorData = lockBox.decrypt( ticket.getEncPart().getKey(), authHeader.getEncryptedAuthenticator(),
            authenticatorKeyUsage );

        Authenticator authenticator = KrbCodec.decode(authenticatorData, Authenticator.class);

        if ( !authenticator.getCname().getName().equals( ticket.getEncPart().getCname().getName() ) )
        {
            throw new KerberosException( ErrorType.KRB_AP_ERR_BADMATCH );
        }

        if ( ticket.getEncPart().getClientAddresses() != null )
        {
            HostAddress tmp = new HostAddress();
            tmp.setAddress(clientAddress.getAddress());
            if ( !ticket.getEncPart().getClientAddresses().getElements().contains(tmp))
            {
                throw new KerberosException( ErrorType.KRB_AP_ERR_BADADDR );
            }
        }
        else
        {
            if ( !emptyAddressesAllowed )
            {
                throw new KerberosException( ErrorType.KRB_AP_ERR_BADADDR );
            }
        }

        KerberosPrincipal serverPrincipal = getKerberosPrincipal( ticket.getSname(), ticket.getRealm() );
        KerberosPrincipal clientPrincipal = getKerberosPrincipal( authenticator.getCname(), authenticator.getCrealm() );
        KerberosTime clientTime = authenticator.getCtime();
        int clientMicroSeconds = authenticator.getCusec();

        if ( replayCache != null )
        {
            if ( replayCache.isReplay( serverPrincipal, clientPrincipal, clientTime, clientMicroSeconds ) )
            {
                throw new KerberosException( ErrorType.KRB_AP_ERR_REPEAT );
            }

            replayCache.save( serverPrincipal, clientPrincipal, clientTime, clientMicroSeconds );
        }

        if ( !authenticator.getCtime().isInClockSkew( clockSkew ) )
        {
            throw new KerberosException( ErrorType.KRB_AP_ERR_SKEW );
        }

        /*
         * "The server computes the age of the ticket: local (server) time minus
         * the starttime inside the Ticket.  If the starttime is later than the
         * current time by more than the allowable clock skew, or if the INVALID
         * flag is set in the ticket, the KRB_AP_ERR_TKT_NYV error is returned."
         */
        KerberosTime startTime = ( ticket.getEncPart().getStartTime() != null ) ? ticket.getEncPart()
            .getStartTime() : ticket.getEncPart().getAuthTime();

        KerberosTime now = new KerberosTime();
        boolean isValidStartTime = startTime.lessThan( now );

        if ( !isValidStartTime || ( ticket.getEncPart().getFlags().isInvalid() && !isValidate ) )
        {
            // it hasn't yet become valid
            throw new KerberosException( ErrorType.KRB_AP_ERR_TKT_NYV );
        }

        // TODO - doesn't take into account skew
        if ( !ticket.getEncPart().getEndTime().greaterThan( now ) )
        {
            throw new KerberosException( ErrorType.KRB_AP_ERR_TKT_EXPIRED );
        }

        authHeader.getApOptions().setFlag(ApOptions.MUTUAL_REQUIRED);

        return authenticator;
    }
}
