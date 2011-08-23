package info.agentbob.security.exception;

public class InvalidPrivateKeyException
    extends Exception
{
    private static final long serialVersionUID = 1L;

    public InvalidPrivateKeyException()
    {
    }

    public InvalidPrivateKeyException( String message )
    {
        super( message );
    }

    public InvalidPrivateKeyException( Throwable cause )
    {
        super( cause );
    }

    public InvalidPrivateKeyException( String message, Throwable cause )
    {
        super( message, cause );
    }

}
