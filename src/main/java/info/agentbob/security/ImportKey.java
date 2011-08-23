package info.agentbob.security;

import info.agentbob.security.exception.InvalidCertificateException;
import info.agentbob.security.exception.InvalidKeystoreException;
import info.agentbob.security.exception.InvalidPrivateKeyException;
import info.agentbob.security.exception.PrivateKeyEntryException;

import java.io.BufferedReader;
import java.io.ByteArrayInputStream;
import java.io.DataInputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.security.KeyFactory;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.cert.Certificate;
import java.security.cert.CertificateFactory;
import java.security.spec.PKCS8EncodedKeySpec;
import java.util.Collection;

import org.apache.commons.cli.CommandLine;
import org.apache.commons.cli.CommandLineParser;
import org.apache.commons.cli.Options;
import org.apache.commons.cli.ParseException;
import org.apache.commons.cli.PosixParser;

/**
 * TODO need to write new documentation
 * 
 * @author Joachim Karrer, Jens Carlberg, Lance Linder
 * @version 1.2
 **/
public class ImportKey
{
    private static final String OPT_PRIVATE_KEY = "private-key";

    private static final String OPT_CERTIFICATE = "certificate";

    private static final String OPT_KEYSTORE = "keystore";

    private static final String OPT_ALIAS = "alias";

    public static void main( String args[] )
        throws IOException
    {

        // create the command line parser
        CommandLineParser parser = new PosixParser();

        // create the Options
        Options options = new Options();
        options.addOption( "k", OPT_PRIVATE_KEY, true, "private key file." );
        options.addOption( "a", OPT_ALIAS, true, "key alias." );
        options.addOption( "c", OPT_CERTIFICATE, true, "certificate file." );
        options.addOption( "s", OPT_KEYSTORE, true,
                           "java keystore file (if not specified defaults to ~/importkey.keystore" );

        File privateKey = null;
        File certificate = null;
        File keystore = null;
        String alias = "importkey";
        String password = null;

        try
        {
            // parse the command line arguments
            CommandLine line = parser.parse( options, args );

            // validate private key
            if ( line.hasOption( OPT_PRIVATE_KEY ) )
            {
                privateKey = new File( line.getOptionValue( OPT_PRIVATE_KEY ) );
                if ( !privateKey.exists() )
                {
                    System.out.println( "Private key " + privateKey.getAbsolutePath() + " doesn't exist." );
                    System.exit( 1 );
                }

            }
            else
            {
                System.out.println( "Must specify private key." );
                System.exit( 1 );
            }

            // validate alias
            if ( line.hasOption( OPT_ALIAS ) )
            {
                alias = line.getOptionValue( OPT_ALIAS );
            }

            // validate certificate
            if ( line.hasOption( OPT_CERTIFICATE ) )
            {
                certificate = new File( line.getOptionValue( OPT_CERTIFICATE ) );
                if ( !certificate.exists() )
                {
                    System.out.println( "Certificate " + certificate.getAbsolutePath() + " doesn't exist." );
                    System.exit( 1 );
                }

            }
            else
            {
                System.out.println( "Must specify certificate." );
                System.exit( 1 );
            }

            // validate keystore
            if ( line.hasOption( OPT_KEYSTORE ) )
            {
                keystore = new File( line.getOptionValue( OPT_KEYSTORE ) );
            }
            else
            {
                String path =
                    System.getProperty( "user.home" ) + System.getProperty( "file.separator" ) + "importkey.keystore";
                keystore = new File( path );

            }
        }
        catch ( ParseException exp )
        {
            System.out.println( "Unexpected exception:" + exp.getMessage() );
        }

        // Print execution information
        System.out.println( "Will perform import with the following:" );
        System.out.println( "Keystore: " + keystore.getAbsolutePath() );
        System.out.println( "Private Key: " + privateKey.getAbsolutePath() );
        System.out.println( "Certificate: " + certificate.getAbsolutePath() );
        System.out.println( "Alias: " + alias );
        System.out.println( "Hit any key to continue... (ctrl+c to cancel)" );
        System.in.read();

        // Read keystore password
        System.out.println( "Enter Keystore Password" );
        InputStreamReader converter = new InputStreamReader( System.in );
        BufferedReader in = new BufferedReader( converter );

        try
        {
            password = in.readLine();
        }
        catch ( IOException ioe )
        {
            System.out.println( "IO error trying to password" );
        }

        final ImportKey ik = new ImportKey();
        try
        {
            ik.doImport( privateKey, certificate, keystore, alias, password );
        }
        catch ( PrivateKeyEntryException e )
        {
            System.out.println( e.getMessage() );
            System.exit( 1 );
        }
        catch ( Exception e )
        {
            System.out.println( "Unexpected exception:" + e.getMessage() );
            System.exit( 1 );
        }

        System.out.println( "Import complete!" );
        System.exit( 0 );
    }

    private ImportKey()
    {

    }

    public void doImport( final File privateKey, final File certificate, final File keystore, final String alias,
                          final String password )
        throws InvalidKeystoreException, InvalidPrivateKeyException, InvalidCertificateException,
        PrivateKeyEntryException
    {

        // Load key store
        final KeyStore ks = getKeyStore( keystore, password );
        if ( ks == null )
            throw new InvalidKeystoreException( "Error creating/reading keystore " + keystore.getAbsolutePath() );

        // Load private key
        final PrivateKey key = getPrivateKey( privateKey );
        if ( key == null )
            throw new InvalidPrivateKeyException( "Error reading private key " + privateKey.getAbsolutePath() );

        // Load certificates
        final Collection<? extends Certificate> certs = getCertificateChain( certificate );
        if ( certs == null )
            throw new InvalidCertificateException( "Error reading private key " + privateKey.getAbsolutePath() );

        final Certificate[] certsArray = certs.toArray( new Certificate[0] );

        // Fill keystore
        try
        {
            ks.setKeyEntry( alias, key, password.toCharArray(), certsArray );
            ks.store( new FileOutputStream( keystore ), password.toCharArray() );
        }
        catch ( Exception e )
        {
            throw new PrivateKeyEntryException( "Error adding private key to keystore: " + e.getMessage() );
        }

    }

    /**
     * <p>
     * Creates an InputStream from a file, and fills it with the complete file. Thus, available() on the returned
     * InputStream will return the full number of bytes the file contains
     * </p>
     * 
     * @param fname The filename
     * @return The filled InputStream
     * @exception IOException, if the Streams couldn't be created.
     **/
    private InputStream fullStream( File file )
        throws IOException
    {
        final FileInputStream fis = new FileInputStream( file );
        final DataInputStream dis = new DataInputStream( fis );
        final byte[] bytes = new byte[dis.available()];
        dis.readFully( bytes );
        final ByteArrayInputStream bais = new ByteArrayInputStream( bytes );
        return bais;
    }

    private Collection<? extends Certificate> getCertificateChain( final File certificate )
    {
        Collection<? extends Certificate> collection = null;

        // loading CertificateChain
        try
        {
            final CertificateFactory cf = CertificateFactory.getInstance( "X.509" );
            final InputStream certstream = fullStream( certificate );

            collection = cf.generateCertificates( certstream );
        }
        catch ( Exception e )
        {
            System.out.println( "Error reading certificates : " + e.getMessage() );
        }

        return collection;
    }

    private PrivateKey getPrivateKey( final File keyfile )
    {
        // loading Key
        PrivateKey pkey = null;
        try
        {
            final InputStream fl = fullStream( keyfile );
            final byte[] key = new byte[fl.available()];
            final KeyFactory kf = KeyFactory.getInstance( "RSA" );
            fl.read( key, 0, fl.available() );
            fl.close();
            final PKCS8EncodedKeySpec keysp = new PKCS8EncodedKeySpec( key );
            pkey = kf.generatePrivate( keysp );
        }
        catch ( Exception e )
        {
            System.out.println( "Error reading private key : " + e.getMessage() );
        }
        return pkey;
    }

    private KeyStore getKeyStore( final File keystore, final String password )
    {
        KeyStore ks = null;

        try
        {
            ks = KeyStore.getInstance( "JKS", "SUN" );

            // Initialize new keystore
            if ( !keystore.exists() )
            {
                System.out.println( "Creating new keystore : " + keystore.getAbsolutePath() );
                ks.load( null, password.toCharArray() );
                ks.store( new FileOutputStream( keystore ), password.toCharArray() );
            }
            else
            {
                System.out.println( "Using exising keystore : " + keystore.getAbsolutePath() );
            }

            // Load keystore
            ks.load( new FileInputStream( keystore ), password.toCharArray() );
        }
        catch ( Exception e )
        {
            System.out.println( "Error getting keystore : " + e.getMessage() );
            return null;
        }

        return ks;
    }

}// KeyStore
