<?php
/**
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
 * @subpackage Tests
 */

include_once( 'tests/test.php' );
include_once( 'data/ldap_wrapper.php' );

/**
 * Tests for the LDAP filter which do not need an LDAP server.
 *
 * @package Authentication
 * @version //autogen//
 * @subpackage Tests
 */
class ezcAuthenticationLdapOfflineTest extends ezcAuthenticationTest
{
    public static function suite()
    {
        return new PHPUnit\Framework\TestSuite( "ezcAuthenticationLdapOfflineTest" );
    }

    public function setUp() : void
    {
        if ( !ezcBaseFeatures::hasExtensionSupport( 'ldap' ) )
        {
            $this->markTestSkipped( "PHP must be compiled with --with-ldap." );
        }
    }

    private function createFilter( $format = 'uid=%id%' )
    {
        $ldap = new ezcAuthenticationLdapInfo( 'localhost', $format, 'dc=example,dc=com', 389 );
        return new ezcAuthenticationLdapWrapper( $ldap );
    }

    public function testLdapSearchFilterPlainId()
    {
        $filter = $this->createFilter();
        $this->assertEquals( 'uid=jan.modaal', $filter->buildSearchFilter( 'jan.modaal' ) );
    }

    public function testLdapSearchFilterEscapesWildcard()
    {
        $filter = $this->createFilter();
        $this->assertEquals( 'uid=\2a', $filter->buildSearchFilter( '*' ) );
    }

    public function testLdapSearchFilterEscapesInjection()
    {
        $filter = $this->createFilter( '(&(objectClass=person)(uid=%id%))' );
        $this->assertEquals( '(&(objectClass=person)(uid=x\29\28uid=y))', $filter->buildSearchFilter( 'x)(uid=y' ) );
    }

    public function testLdapSearchFilterEscapesBackslashAndNul()
    {
        $filter = $this->createFilter();
        $this->assertEquals( 'uid=a\5cb\00', $filter->buildSearchFilter( "a\\b\0" ) );
    }

    public function testLdapSearchFilterKeepsUtf8()
    {
        $filter = $this->createFilter();
        $this->assertEquals( 'uid=Ruşinică Piţigoi', $filter->buildSearchFilter( 'Ruşinică Piţigoi' ) );
    }

    public function testLdapUri()
    {
        $filter = $this->createFilter();
        $this->assertEquals( 'ldap://localhost:389', $filter->buildUri( 'localhost', 389 ) );
        $this->assertEquals( 'ldap://ldap.example.com:10389', $filter->buildUri( 'ldap.example.com', '10389' ) );
    }

    public function testLdapUriAlreadyUri()
    {
        $filter = $this->createFilter();
        $this->assertEquals( 'ldaps://ldap.example.com:636', $filter->buildUri( 'ldaps://ldap.example.com:636', 389 ) );
        $this->assertEquals( 'ldap://ldap.example.com', $filter->buildUri( 'ldap://ldap.example.com', 389 ) );
    }

    public function testLdapUriSingleHostWithPort()
    {
        $filter = $this->createFilter();
        $this->assertEquals( 'ldap://ldap.example.com:10389', $filter->buildUri( 'ldap.example.com:10389', 389 ) );
    }

    public function testLdapUriHostList()
    {
        $filter = $this->createFilter();
        $this->assertEquals( 'ldap://ldap1.example.com:389 ldap://ldap2.example.com:389', $filter->buildUri( 'ldap1.example.com ldap2.example.com', 389 ) );
        $this->assertEquals( 'ldap://ldap1:10389 ldap://ldap2:10389 ldap://ldap3:10389', $filter->buildUri( "  ldap1\tldap2\n ldap3 ", 10389 ) );
    }

    public function testLdapUriHostListWithPorts()
    {
        $filter = $this->createFilter();
        $this->assertEquals( 'ldap://ldap1:10389 ldap://ldap2:389', $filter->buildUri( 'ldap1:10389 ldap2', 389 ) );
        $this->assertEquals( 'ldap://ldap1:389 ldap://ldap2:10636', $filter->buildUri( 'ldap1 ldap2:10636', 389 ) );
    }

    public function testLdapUriIpv6()
    {
        $filter = $this->createFilter();
        $this->assertEquals( 'ldap://[::1]:389', $filter->buildUri( '::1', 389 ) );
        $this->assertEquals( 'ldap://[::1]:389', $filter->buildUri( '[::1]', 389 ) );
        $this->assertEquals( 'ldap://[2001:db8::1]:10389 ldap://ldap2:389', $filter->buildUri( '[2001:db8::1]:10389 ldap2', 389 ) );
    }

    public function testLdapUriLdapsList()
    {
        $filter = $this->createFilter();
        $this->assertEquals( 'ldaps://ldap1:636 ldaps://ldap2:636', $filter->buildUri( 'ldaps://ldap1:636 ldaps://ldap2:636', 389 ) );
        $this->assertEquals( 'ldaps://ldap1', $filter->buildUri( 'ldaps://ldap1', 389 ) );
    }

    public function testLdapConnectWithoutDeprecation()
    {
        $filter = $this->createFilter();
        $deprecations = array();
        set_error_handler( function ( $errno, $errstr ) use ( &$deprecations )
        {
            $deprecations[] = $errstr;
            return true;
        }, E_DEPRECATED );
        try
        {
            // ldap_connect() with an URI does not contact the server
            $connection = $filter->parentLdapConnect( 'localhost', 389 );
        }
        finally
        {
            restore_error_handler();
        }
        $this->assertNotFalse( $connection );
        $this->assertEquals( array(), $deprecations );
        ldap_close( $connection );
    }

    public function testLdapPasswordEmptyStringNotSent()
    {
        $filter = $this->createFilter();
        $credentials = new ezcAuthenticationPasswordCredentials( 'jan.modaal', '' );
        $this->assertEquals( ezcAuthenticationLdapFilter::STATUS_PASSWORD_INCORRECT, $filter->run( $credentials ) );
        $this->assertEquals( array(), $filter->connectCalls );
    }

    public function testLdapPasswordNullNotSent()
    {
        $filter = $this->createFilter();
        $credentials = new ezcAuthenticationPasswordCredentials( 'jan.modaal', null );
        $this->assertEquals( ezcAuthenticationLdapFilter::STATUS_PASSWORD_INCORRECT, $filter->run( $credentials ) );
        $this->assertEquals( array(), $filter->connectCalls );
    }

    public function testLdapPasswordZeroIsAccepted()
    {
        $filter = $this->createFilter();
        $credentials = new ezcAuthenticationPasswordCredentials( 'jan.modaal', '0' );
        try
        {
            $filter->run( $credentials );
            $this->fail( 'Expected exception was not thrown.' );
        }
        catch ( ezcAuthenticationLdapException $e )
        {
            // the password '0' passed the empty password check and the filter
            // tried to connect to the server
            $this->assertEquals( array( array( 'localhost', 389 ) ), $filter->connectCalls );
        }
    }

    public function testLdapFetchDataLowerCaseAttribute()
    {
        $filter = $this->createFilter();
        $filter->registerFetchData( array( 'objectClass', 'uid' ) );
        $attributes = array(
            'objectclass' => array( 'count' => 2, 0 => 'top', 1 => 'person' ),
            'uid' => array( 'count' => 1, 0 => 'jan.modaal' ),
        );
        $filter->storeFetchedData( $attributes, 'uid=jan.modaal,dc=example,dc=com' );
        $expected = array(
            'objectClass' => array( 'top', 'person' ),
            'uid' => array( 'jan.modaal' ),
        );
        $this->assertEquals( $expected, $filter->fetchData() );
    }

    public function testLdapFetchDataExactCaseAndDn()
    {
        $filter = $this->createFilter();
        $filter->registerFetchData( array( 'objectClass', 'dn', 'mobile' ) );
        $attributes = array(
            'objectClass' => array( 'count' => 1, 0 => 'person' ),
        );
        $filter->storeFetchedData( $attributes, 'uid=jan.modaal,dc=example,dc=com' );
        $expected = array(
            'objectClass' => array( 'person' ),
            'dn' => 'uid=jan.modaal,dc=example,dc=com',
        );
        $this->assertEquals( $expected, $filter->fetchData() );
    }
}
?>
