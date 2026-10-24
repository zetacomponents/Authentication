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

/**
 * Class which exposes the protected methods from the LDAP filter.
 *
 * For testing purposes only. ldapConnect() does not connect anywhere, it
 * records the host and port and returns false.
 *
 * @package Authentication
 * @version //autogen//
 * @subpackage Tests
 * @access private
 */
class ezcAuthenticationLdapWrapper extends ezcAuthenticationLdapFilter
{
    /**
     * The arguments of each call to ldapConnect().
     *
     * @var array(array(mixed))
     */
    public $connectCalls = array();

    public function buildSearchFilter( $id )
    {
        return parent::buildSearchFilter( $id );
    }

    public function buildUri( $host, $port )
    {
        return parent::buildUri( $host, $port );
    }

    public function storeFetchedData( array $attributes, $entryDN )
    {
        parent::storeFetchedData( $attributes, $entryDN );
    }

    public function parentLdapConnect( $host, $port = 389 )
    {
        return parent::ldapConnect( $host, $port );
    }

    protected function ldapConnect( $host, $port = 389 )
    {
        $this->connectCalls[] = array( $host, $port );
        return false;
    }
}
?>
