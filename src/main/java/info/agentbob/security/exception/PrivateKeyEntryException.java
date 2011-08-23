package info.agentbob.security.exception;

public class PrivateKeyEntryException
    extends Exception
{

    private static final long serialVersionUID = 1L;

    public PrivateKeyEntryException()
    {
    }

    public PrivateKeyEntryException( String message )
    {
        super( message );
    }

    public PrivateKeyEntryException( Throwable cause )
    {
        super( cause );
    }

    public PrivateKeyEntryException( String message, Throwable cause )
    {
        super( message, cause );
    }

}
