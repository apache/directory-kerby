package org.haox.kerb.server.sam;

import org.haox.kerb.spec.type.common.SamType;

/**
 * Base class for all SAM subsystem errors.
 */
public class SamException extends Exception
{
    private static final long serialVersionUID = -677444708375928227L;

    /** the SAM type that caused this exception */
    private final SamType type;


    /**
     * Creates a SamException for a specific SamType.
     *
     * @param type the type value for the SAM algorithm associated with this exception
     */
    public SamException( SamType type )
    {
        super();

        this.type = type;
    }


    /**
     * Creates a SamException for a specific SamType, with message.
     *
     * @param type the type value for the SAM algorithm associated with this exception
     * @param message a message regarding the nature of the fault
     */
    public SamException( SamType type, String message )
    {
        super( message );

        this.type = type;
    }


    /**
     * Creates a SamException for a specific SamType, with the cause resulted in
     * this exception.
     *
     * @param type the type value for the SAM algorithm associated with this exception
     * @param cause the throwable that resulted in this exception being thrown
     */
    public SamException( SamType type, Throwable cause )
    {
        super( cause );

        this.type = type;
    }


    /**
     * Creates a SamException for a specific SamType, with a message and the
     * cause that resulted in this exception.
     *
     *
     * @param type the type value for the SAM algorithm associated with this exception
     * @param message a message regarding the nature of the fault
     * @param cause the throwable that resulted in this exception being thrown
     */
    public SamException( SamType type, String message, Throwable cause )
    {
        super( message, cause );

        this.type = type;
    }


    /**
     * Gets the registered SAM algorithm type associated with this SamException.
     *
     * @return the type value for the SAM algorithm associated with this exception
     */
    public SamType getSamType()
    {
        return this.type;
    }
}
