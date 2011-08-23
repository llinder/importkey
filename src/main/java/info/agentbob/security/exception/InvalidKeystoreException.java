package info.agentbob.security.exception;

public class InvalidKeystoreException
    extends Exception
{
    private static final long serialVersionUID = 1L;

    public InvalidKeystoreException()
    {
        super();
    }

    public InvalidKeystoreException( String message )
    {
        super( message );
    }

    public InvalidKeystoreException( Throwable error )
    {
        super( error );
    }

    public InvalidKeystoreException( String message, Throwable error )
    {
        super( message, error );
    }

}
