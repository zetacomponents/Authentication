<?php
/**
 * File containing the ezcAuthenticationLdapFilter class.
 *
 * Licensed to the Apache Software Foundation (ASF) under one
 * or more contributor license agreements.  See the NOTICE file
 * distributed with this work for additional information
 * regarding copyright ownership.  The ASF licenses this file
 * to you under the Apache License, Version 2.0 (the
 * "License"); you may not use this file except in compliance
 * with the License.  You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied.  See the License for the
 * specific language governing permissions and limitations
 * under the License.
 *
 * @license http://www.apache.org/licenses/LICENSE-2.0 Apache License, Version 2.0
 * @filesource
 * @package Authentication
 * @version //autogen//
 */

/**
 * Filter to authenticate against an LDAP directory.
 *
 * This filter depends on the PHP ldap extension. If this extension is not
 * installed then the constructor will throw an ezcExtensionNotFoundException.
 *
 * RFC: {@link http://www.faqs.org/rfcs/rfc4510.html}
 *
 * Example:
 * <code>
 * $credentials = new ezcAuthenticationPasswordCredentials( 'jan.modaal', 'qwerty' );
 * $ldap = new ezcAuthenticationLdapInfo( 'localhost', 'uid=%id%', 'dc=example,dc=com', 389 );
 * $authentication = new ezcAuthentication( $credentials );
 * $authentication->addFilter( new ezcAuthenticationLdapFilter( $ldap ) );
 * // add more filters if needed
 * if ( !$authentication->run() )
 * {
 *     // authentication did not succeed, so inform the user
 *     $status = $authentication->getStatus();
 *     $err = array(
 *             'ezcAuthenticationLdapFilter' => array(
 *                 ezcAuthenticationLdapFilter::STATUS_USERNAME_INCORRECT => 'Incorrect username',
 *                 ezcAuthenticationLdapFilter::STATUS_PASSWORD_INCORRECT => 'Incorrect password'
 *                 )
 *             );
 *     foreach ( $status as $line )
 *     {
 *         list( $key, $value ) = each( $line );
 *         echo $err[$key][$value] . "\n";
 *     }
 * }
 * else
 * {
 *     // authentication succeeded, so allow the user to see his content
 * }
 * </code>
 *
 * Extra data can be fetched from the LDAP server during the authentication
 * process, by registering the data to be fetched before calling run(). Example:
 * <code>
 * // $filter is an ezcAuthenticationLdapFilter object
 * $filter->registerFetchData( array( 'name', 'company', 'mobile' ) );
 *
 * // after run()
 * $data = $filter->fetchData();
 * </code>
 *
 * The $data array will be something like:
 * <code>
 * array( 'name' = > array( 'Dr. No' ),
 *        'company' => array( 'SPECTRE' ),
 *        'mobile' => array( '555-7732873' )
 *      );
 * </code>
 *
 * @property ezcAuthenticationLdapInfo $ldap
 *           Structure which holds the LDAP server hostname, entry format and base,
 *           and port.
 *
 * @package Authentication
 * @version //autogen//
 * @mainclass
 */
class ezcAuthenticationLdapFilter extends ezcAuthenticationFilter implements ezcAuthenticationDataFetch
{
    /**
     * Username is not found in the database.
     */
    const STATUS_USERNAME_INCORRECT = 1;

    /**
     * Password is incorrect.
     */
    const STATUS_PASSWORD_INCORRECT = 2;

    /**
     * Use plain-text password and no encryption for the connection (default).
     */
    const PROTOCOL_PLAIN = 1;

    /**
     * Use plain-text password and TLS connection.
     */
    const PROTOCOL_TLS = 2;

    /**
     * Holds the attributes which will be requested during the authentication
     * process.
     *
     * Usually it has this structure:
     * <code>
     * array( 'name', 'company', 'mobile' );
     * </code>
     *
     * @var array(string)
     */
    protected $requestedData = array();

    /**
     * Holds the extra data fetched during the authentication process.
     *
     * Usually it has this structure:
     * <code>
     * array( 'name' = > array( 'Dr. No' ),
     *        'company' => array( 'SPECTRE' ),
     *        'mobile' => array( '555-7732873' )
     *      );
     * </code>
     *
     * @var array(string=>mixed)
     */
    protected $data = array();

    /**
     * Holds the properties of this class.
     *
     * @var array(string=>mixed)
     */
    private $properties = array();

    /**
     * Creates a new object of this class.
     *
     * @throws ezcBaseExtensionNotFoundException
     *         if the PHP ldap extension is not installed
     * @param ezcAuthenticationLdapInfo $ldap How to connect to LDAP
     * @param ezcAuthenticationLdapOptions $options Options for this class
     */
    public function __construct( ezcAuthenticationLdapInfo $ldap, ?ezcAuthenticationLdapOptions $options = null )
    {
        if ( !ezcBaseFeatures::hasExtensionSupport( 'ldap' ) )
        {
            throw new ezcBaseExtensionNotFoundException( 'ldap', null, "PHP not configured with --with-ldap." );
        }

        $this->ldap = $ldap;
        $this->options = ( $options === null ) ? new ezcAuthenticationLdapOptions() : $options;
    }

    /**
     * Sets the property $name to $value.
     *
     * @throws ezcBasePropertyNotFoundException
     *         if the property $name does not exist
     * @throws ezcBaseValueException
     *         if $value is not correct for the property $name
     * @param string $name The name of the property to set
     * @param mixed $value The new value of the property
     * @ignore
     */
    public function __set( $name, $value )
    {
        switch ( $name )
        {
            case 'ldap':
                if ( $value instanceof ezcAuthenticationLdapInfo )
                {
                    $this->properties[$name] = $value;
                }
                else
                {
                    throw new ezcBaseValueException( $name, $value, 'ezcAuthenticationLdapInfo' );
                }
                break;

            default:
                throw new ezcBasePropertyNotFoundException( $name );
        }
    }

    /**
     * Returns the value of the property $name.
     *
     * @throws ezcBasePropertyNotFoundException
     *         if the property $name does not exist
     * @param string $name The name of the property for which to return the value
     * @return mixed
     * @ignore
     */
    public function __get( $name )
    {
        switch ( $name )
        {
            case 'ldap':
                return $this->properties[$name];

            default:
                throw new ezcBasePropertyNotFoundException( $name );
        }
    }

    /**
     * Returns true if the property $name is set, otherwise false.
     *
     * @param string $name The name of the property to test if it is set
     * @return bool
     * @ignore
     */
    public function __isset( $name )
    {
        switch ( $name )
        {
            case 'ldap':
                return isset( $this->properties[$name] );

            default:
                return false;
        }
    }

    /**
     * Runs the filter and returns a status code when finished.
     *
     * @throws ezcAuthenticationLdapException
     *         if the connecting and binding to the LDAP server could not be performed
     * @param ezcAuthenticationPasswordCredentials $credentials Authentication credentials
     * @return int
     */
    public function run( $credentials )
    {
        $protocol = 'ldap://'; // 'ldaps://' will be implemented later (if ever, as TLS is better)

        // null, false or empty string passwords are not accepted, as on some servers
        // they could cause the LDAP binding to succeed (unauthenticated bind).
        // The string '0' is a valid password, so empty() must not be used here.
        if ( $credentials->password === null || $credentials->password === false || (string) $credentials->password === '' )
        {
            return self::STATUS_PASSWORD_INCORRECT;
        }

        $connection = $this->ldapConnect( $this->ldap->host, $this->ldap->port );
        if ( !$connection )
        {
            // OpenLDAP 2.x.x will not throw an exception because $connection is always a resource
            throw new ezcAuthenticationLdapException( "Could not connect to host '{$protocol}{$this->ldap->host}:{$this->ldap->port}'." );
        }

        // without using version 3, TLS and other stuff won't work
        ldap_set_option( $connection, LDAP_OPT_PROTOCOL_VERSION, 3 );
        ldap_set_option( $connection, LDAP_OPT_REFERRALS, 0 );

        // try to use a TLS connection
        if ( $this->options->protocol === self::PROTOCOL_TLS || $this->ldap->protocol === self::PROTOCOL_TLS )
        {
            if ( $this->ldapStartTls( $connection ) )
            {
                // using TLS, so continue
            }
            else
            {
                throw new ezcAuthenticationLdapException( "Could not connect to host '{$protocol}{$this->ldap->host}:{$this->ldap->port}'." );
            }
        }

        // bind anonymously to see if username exists in the directory
        if ( @ldap_bind( $connection ) )
        {
            $search = @ldap_search( $connection, $this->ldap->base, $this->buildSearchFilter( $credentials->id ), $this->requestedData );
            if ( !$search || ldap_count_entries( $connection, $search ) === 0 )
            {
                ldap_close( $connection );
                return self::STATUS_USERNAME_INCORRECT;
            }

            // username exists, so get dn for it
            $entry = ldap_first_entry( $connection, $search );
            $entryDN = ldap_get_dn( $connection, $entry );

            // check if we can bind with the provided password
            if ( @ldap_bind( $connection, $entryDN, $credentials->password ) )
            {
                // retrieve extra authentication data
                if ( count( $this->requestedData ) > 0 )
                {
                    $attributes = ldap_get_attributes( $connection, $entry );
                    $this->storeFetchedData( $attributes, $entryDN );
                }

                ldap_close( $connection );
                return self::STATUS_OK;
            }
        }

        // bind failed, so something must be wrong (connection error or password incorrect)
        $err = ldap_errno( $connection );
        ldap_close( $connection );

        // error codes: 0 = success, 49 = invalidCredentials, 50 = insufficientAccessRights
        // so if any other codes appear it must mean that we could not connect to
        // the LDAP host
        if ( $err !== 0 && $err !== 49 && $err !== 50 )
        {
            throw new ezcAuthenticationLdapException( "Could not connect to host '{$protocol}{$this->ldap->host}:{$this->ldap->port}'", $err, ldap_err2str( $err ) );
        }

        return self::STATUS_PASSWORD_INCORRECT;
    }

    /**
     * Returns the LDAP search filter for the user $id.
     *
     * The placeholder %id% in the format of the LDAP info structure is
     * replaced with $id, escaped with ldap_escape() so that filter
     * metacharacters in the username (like '*', '(', ')' or a backslash) can not
     * change the meaning of the filter.
     *
     * @param string $id The username to search for
     * @return string
     */
    protected function buildSearchFilter( $id )
    {
        return str_replace( '%id%', ldap_escape( (string) $id, '', LDAP_ESCAPE_FILTER ), $this->ldap->format );
    }

    /**
     * Copies the requested attributes from $attributes into the fetched data.
     *
     * $attributes is an array as returned by ldap_get_attributes(). The case
     * of the requested attribute names is ignored, so requesting 'objectClass'
     * also works if the server returned only 'objectclass'. The data is
     * stored under the attribute name as requested.
     *
     * @param array(string=>mixed) $attributes The attributes of the LDAP entry
     * @param string $entryDN The DN of the LDAP entry
     */
    protected function storeFetchedData( array $attributes, $entryDN )
    {
        foreach ( $this->requestedData as $attribute )
        {
            // ignore case of $attribute
            $key = null;
            if ( isset( $attributes[$attribute] ) )
            {
                $key = $attribute;
            }
            elseif ( isset( $attributes[strtolower( $attribute )] ) )
            {
                $key = strtolower( $attribute );
            }

            if ( $key !== null )
            {
                for ( $i = 0; $i < $attributes[$key]['count']; $i++ )
                {
                    $this->data[$attribute][] = $attributes[$key][$i];
                }
            }

            // DN is a 'special' attribute and is not returned by ldap_get_attributes()
            if ( strtolower( $attribute ) == 'dn' )
            {
                // An entry can only have one DN
                $this->data[$attribute] = $entryDN;
            }
        }
    }

    /**
     * Returns the LDAP URI for $host and $port.
     *
     * If $host already is an URI (it contains a '/', like 'ldap://host' or
     * 'ldaps://host:636'), it is returned unchanged and $port is ignored,
     * which is how ldap_connect() treated its two arguments.
     *
     * Otherwise $host may be a single host name or, as accepted by
     * ldap_connect() with OpenLDAP, a list of host names separated by
     * whitespace ('ldap1 ldap2' or 'ldap1:10389 ldap2'), which the library
     * tries in turn. Every host in the list becomes its own URI, and the
     * URIs are joined with a space: 'ldap://ldap1:389 ldap://ldap2:389'.
     * A host that already carries a port keeps it, and $port is used for
     * the others. A bare IPv6 address is put in brackets.
     *
     * @param string $host The LDAP hostname, or a whitespace separated list of hostnames
     * @param int $port The LDAP port to connect to $host
     * @return string
     */
    protected function buildUri( $host, $port )
    {
        $host = (string) $host;
        if ( strpos( $host, '/' ) !== false )
        {
            return $host;
        }

        $hosts = preg_split( '/\s+/', trim( $host ), -1, PREG_SPLIT_NO_EMPTY );
        if ( count( $hosts ) === 0 )
        {
            $hosts = array( '' );
        }

        $uris = array();
        foreach ( $hosts as $entry )
        {
            if ( preg_match( '/^(\[[^\]]*\]|[^:]*):\d+$/', $entry ) )
            {
                // 'host:port' or '[ipv6]:port'
                $uris[] = 'ldap://' . $entry;
            }
            else if ( substr_count( $entry, ':' ) > 1 && $entry[0] !== '[' )
            {
                // bare IPv6 address
                $uris[] = 'ldap://[' . $entry . ']:' . (int) $port;
            }
            else
            {
                $uris[] = 'ldap://' . $entry . ':' . (int) $port;
            }
        }

        return implode( ' ', $uris );
    }

    /**
     * Wraps around the ldap_connect() function.
     *
     * Returns the connection if it was successful.
     *
     * The host and port are passed to ldap_connect() as one URI, because
     * calling ldap_connect() with two arguments is deprecated since PHP 8.3.
     *
     * @param string $host The LDAP hostname
     * @param int $port The LDAP port to connect to $host, default 389
     * @return mixed
     */
    protected function ldapConnect( $host, $port = 389 )
    {
        return ldap_connect( $this->buildUri( $host, $port ) );
    }

    /**
     * Wraps around the ldap_start_tls() function.
     *
     * Returns true if it was possible to start a TLS connection on the provided
     * $connection.
     *
     * @param mixed $connection An established LDAP connection
     * @return bool
     */
    protected function ldapStartTls( $connection )
    {
        return @ldap_start_tls( $connection );
    }

    /**
     * Registers which extra data to fetch during the authentication process.
     *
     * The input $data is an array of attributes to request, for example:
     * <code>
     * array( 'name', 'company', 'mobile' );
     * </code>
     *
     * @param array(string) $data A list of attributes to fetch during authentication
     */
    public function registerFetchData( array $data = array() )
    {
        $this->requestedData = $data;
    }

    /**
     * Returns the extra data fetched during the authentication process.
     *
     * The return is something like:
     * <code>
     * array( 'name' = > array( 'Dr. No' ),
     *        'company' => array( 'SPECTRE' ),
     *        'mobile' => array( '555-7732873' )
     *      );
     * </code>
     *
     * @return array(string=>mixed)
     */
    public function fetchData()
    {
        return $this->data;
    }
}
?>
