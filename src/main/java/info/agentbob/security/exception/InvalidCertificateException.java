package info.agentbob.security.exception;

public class InvalidCertificateException
    extends Exception
{
    private static final long serialVersionUID = 1L;

    public InvalidCertificateException()
    {
    }

    public InvalidCertificateException( String message )
    {
        super( message );
    }

    public InvalidCertificateException( Throwable cause )
    {
        super( cause );
    }

    public InvalidCertificateException( String message, Throwable cause )
    {
        super( message, cause );
    }

}
