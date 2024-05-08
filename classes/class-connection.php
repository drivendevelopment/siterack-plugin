<?php

namespace SiteRack;

// Disable direct load
if ( ! defined( 'ABSPATH' ) ) {
    die( 'Access denied.' );
}

class Connection {

    /**
     * The SiteRack site ID.
     */
    public $site_id;

    /**
     * The connection's secret.
     */
    public $secret;

    /**
     * The connection's access token for communicating with the SiteRack API.
     */
    public $access_token;

    /**
     * The connection's public key that can be used to manually connect the
     * site to SiteRack.
     */
    public $public_key;

    public function __construct( $props = array() ) {
        if ( ! empty( $props['site_id'] ) ) {
            $this->site_id = $props['site_id'];
        }

        if ( ! empty( $props['secret'] ) ) {
            $this->secret = $props['secret'];
        }

        if ( ! empty( $props['access_token'] ) ) {
            $this->access_token = $props['access_token'];
        }

        if ( ! empty( $props['public_key'] ) ) {
            $this->public_key = $props['public_key'];
        }
    }

    /**
     * Returns the connection for the specified site or creates a new one
     * if it doesn't exist.
     * 
     * @param int $site_id
     *  The SiteRack site ID.
     * 
     * @return Connection
     *  The connection object.
     */
    public static function find_or_create( $site_id ) {
        $connections = Plugin::get_instance()->get_connections();

        foreach ( $connections as $connection ) {
            if ( $connection->site_id == $site_id ) {
                return $connection;
            }
        }

        $connection             = new Connection();
        $connection->site_id    = $site_id;
        $connection->secret     = Plugin::get_instance()->generate_token();
        $connection->public_key = bin2hex( random_bytes( 16 ) );

        $connection->save();

        return $connection;
    }

    /**
     * Saves the connection to the database.
     */
    public function save() {
        $connections    = Plugin::get_instance()->get_connections();
        $new_connection = $this;

        $connections = array_filter( $connections, fn( $connection ) => $connection->site_id != $this->site_id );
        $connections[] = $this;

        $connections = array_map( function( $connection ) {
            return array(
                'site_id'       => $connection->site_id,
                'secret'        => $connection->secret,
                'access_token'  => $connection->access_token,
                'public_key'    => $connection->public_key,
            );
        }, $connections );

        update_site_option( 'siterack_connections', $connections );
    }
}