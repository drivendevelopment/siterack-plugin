<?php

namespace SiteRack;

use WP_User;
use WP_Error;
use Exception;
use SiteRack\REST_API\v1\REST_API;
use SiteRack\EDD\EDD_SL_Plugin_Updater;

// Disable direct load
if ( ! defined( 'ABSPATH' ) ) {
    die( 'Access denied.' );
}

/**
 * Main plugin class.
 */
final class Plugin extends Singleton {

    public $siterack_app_url = 'https://dashboard.siterack.app/';

    /**
     * Holds an instance of the class.
     *
     * @var Singleton
     */
    protected static $instance;

    protected function __construct() {
        // Register autoload function
        spl_autoload_register( array( $this, 'autoload' ) );

        // Override SiteRack app URL if an alternate URL is defined (useful
        // for testing and local development)
        if ( defined( 'SITERACK_APP_URL' ) ) {
            $this->siterack_app_url = SITERACK_APP_URL;
        }

        add_action( 'init',             array( $this, 'init' ) );
        add_action( 'admin_init',       array( $this, 'init_updates' ) );
        add_action( 'rest_api_init',    array( $this, 'init_rest_api' ) );
    }

    /**
     * Class autoloader.
     */
    public function autoload( $class ) {
        $path = strtolower( $class );
        $path = str_replace( '_', '-', $path );

        // Convert to an array
        $path = explode( '\\', $path );
    
        // Nothing to do if we don't have anything
        if ( empty( $path[0] ) ) return;

        // Only worry about our namespace
        if ( 'siterack' != $path[0] ) return;

        // Remove the root namespace
        unset( $path[0] );

        // Get the class name
        $class = array_pop( $path );

        // Glue it back together
        $path = join( DIRECTORY_SEPARATOR, $path );
        $path = dirname( dirname( __FILE__ ) ) . DIRECTORY_SEPARATOR . 'classes' . DIRECTORY_SEPARATOR . $path . DIRECTORY_SEPARATOR . 'class-' . $class . '.php';

        include_once( $path );
    }

    /**
     * Returns the plugin's version.
     * 
     * Note: the pro version is used when the pro version of the plugin
     * is installed.
     *
     * @return string
     *  The plugin's current version.
     */
    public function get_version() {
        static $version = false;

        $plugin_file 	= dirname( dirname( __FILE__ ) ) . DIRECTORY_SEPARATOR . 'siterack.php';

        if ( ! $version && function_exists( 'get_plugin_data' ) ) {
            $plugin_data 	= get_plugin_data( $plugin_file );
            $version 		= $plugin_data['Version'];
        }

        return $version;
    }

    /**
     * WordPress init action.
     */
    public function init() {	
        $this->maybe_do_login();
        $this->maybe_init_connection();
        $this->maybe_refresh_connection_token();
    }

    /**
     * WordPress init REST API action.
     */
    public function init_rest_api() {
        new REST_API();
    }

    /**
     * Handles requests to log the user in via their SiteRack dashboard.
     */
    private function maybe_do_login() {
        global $wpdb;

        // Check for SiteRack login action
        if ( isset( $_GET['action'] ) && 'siterack_login' == $_GET['action'] ) {
            try {
                if ( empty( $_GET['token'] ) ) {
                    throw new Exception( __( 'Missing login token.', 'siterack' ) );
                }

                $token 		= sanitize_text_field( $_GET['token'] );
                $user_id 	= $wpdb->get_var( $wpdb->prepare( "SELECT user_id FROM {$wpdb->usermeta} WHERE meta_key = 'siterack_login_token' AND meta_value = %s", $token ) );

                if ( ! $user_id ) {
                    throw new Exception( __( 'Invalid login token.', 'siterack' ) );
                }

                $expiration = get_user_meta( $user_id, 'siterack_login_token_expiration', true );
        
                if ( time() > $expiration ) {
                    delete_user_meta( $user_id, 'siterack_login_token' );
                    delete_user_meta( $user_id, 'siterack_login_token_expiration' );

                    throw new Exception( __( 'Login token expired.', 'siterack' ) );
                }

                $user = get_user_by( 'id', $user_id );

                if ( $user && ! is_wp_error( $user ) ) {
                    delete_user_meta( $user_id, 'siterack_login_token' );
                    delete_user_meta( $user_id, 'siterack_login_token_expiration' );

                    wp_clear_auth_cookie();
                    wp_set_current_user( $user->ID );
                    wp_set_auth_cookie( $user->ID );
                
                    wp_safe_redirect( user_admin_url() );
    
                    exit();
                } else {
                    throw new Exception( __( 'Invalid user.', 'siterack' ) );
                }		
            } catch ( Exception $e ) {
                wp_die( $e->getMessage() );
            }
        }
    }

    /**
     * Handles requests to connect the site to SiteRack when connecting using credentials (connections
     * made using a connection token/key are handled by the REST API).
     */
    public function maybe_init_connection() {
        $action     = empty( $_GET['action'] ) ? false : sanitize_text_field( $_GET['action'] );
        $site_id    = empty( $_GET['site_id'] ) ? false : absint( $_GET['site_id'] );
        $user       = wp_get_current_user();

        // Bail if we're not initializing the plugin
        if ( 'siterack_init' != $action ) return;

        // Clean the output buffer to avoid any warnings or other output from
        // potentially breaking the JSON response
        ob_clean();

        header( 'Content-Type: application/json; charset=utf-8' );

        // Bail if the site ID is missing
        if ( ! $site_id ) {
            wp_send_json_error( __( 'Missing site ID.', 'siterack' ) );
        }

        // Only allow logged-in users to perform this action
        if ( 0 == $user->ID ) {
            wp_send_json_error( __( 'User not logged in.', 'siterack' ) );
        }

        // Only allow administrators to perform this action
        if ( ! in_array( 'administrator', $user->roles ) ) {
            wp_send_json_error( __( 'Only administrators may initialize SiteRack.', 'siterack' ) );
        }

        wp_send_json_success( $this->init_connection( $site_id, $user ) );

        exit();
    }

    /**
     * Refreshes the connection token for the current user if it has expired
     * (or creates one if it doesn't exist).
     */
    public function maybe_refresh_connection_token() {
        // Only refresh if the user is logged in
        if ( ! is_user_logged_in() ) return;

        $token = $this->get_connection_token();

        // Only refresh if the token is expired
        if ( $token && ! $this->is_connection_token_expired( $token ) ) return;

        $token = $this->generate_token();

        update_user_meta(
            get_current_user_id(),
            'siterack_connection_token',
            $token
        );

        // Expire token after 15 minutes
        update_user_meta(
            get_current_user_id(),
            'siterack_connection_token_expiration',
            time() + ( 60 * 15 )
        );
    }

    /**
     * Initializes the site secret and returns an access token for the user.
     * 
     * @param int $site_id
     *  The SiteRack site ID.
     * 
     * @param WP_User $user
     *  The user to generate an access token for.
     * 
     * @param string $access_token
     *  SiteRack access token.
     * 
     * @return array
     *  An array containing basic data about the site that is used when adding
     *  the site to the user's dashboard along with an access token.
     */
    public function init_connection( int $site_id, WP_User $user, string $access_token = '' ) {
        $connection = Connection::find_or_create( $site_id );
        
        if ( ! $connection->access_token ) {
            $connection->access_token = $access_token;

            $connection->save();
        }

        // Generate a JSON web token for the user
        $token = new JSON_Web_Token( $connection->secret );
        $token = $token->generate( $user->ID );

        return array(
            'name' 				=> get_bloginfo( 'name' ),			
            'user_id' 			=> $user->ID,
            'user_login'        => $user->user_login,
            'user_email' 		=> $user->user_email,
            'user_display_name' => $user->display_name,
            'user_avatar_url' 	=> get_avatar_url( $user->ID ),
            'token' 			=> $token,
        );
    }

    /**
     * Initializes the EDD plugin updater.
     */
    public function init_updates() {
        $plugin_file = dirname( dirname( __FILE__ ) ) . DIRECTORY_SEPARATOR . 'siterack.php';
        $plugin_data = get_plugin_data( $plugin_file );

        $edd_updater = new EDD_SL_Plugin_Updater(
            'https://siterack.app',
            $plugin_file,
            array(
                'license'   => '',
                'version'   => $plugin_data['Version'],
                'item_name' => $plugin_data['Name'],
                'author'    => $plugin_data['Author'],
            )
        );
    }

    /**
     * Returns the connection token for the current user.
     */
    public function get_connection_token() {
        return get_user_meta(
            get_current_user_id(),
            'siterack_connection_token',
            true
        );
    }

    /**
     * Generates a random token.
     */
    public function generate_token() {
        return bin2hex( random_bytes( 32 ) );
    }

    /**
     * Returns true if the user's connection token is expired.
     * 
     * @param string $token
     *  The connection token to check.
     * 
     * @param int $user_id
     *  The user ID to check.  Defaults to the current user.
     * 
     * @return bool
     *  True if the token is expired, false otherwise.
     */
    public function is_connection_token_expired( $token, $user_id = false ) {
        if ( ! $user_id ) {
            $user_id = get_current_user_id();
        }
        
        $expiration = ( int ) get_user_meta(
            $user_id,
            'siterack_connection_token_expiration',
            true
        );

        return time() > $expiration;
    }

    /**
     * Returns the first user matching the specified meta key and value.
     * 
     * @param string $key
     *  The meta key to search for.
     *
     * @param string $value
     *  The meta value to search for.
     * 
     * @return WP_User|false
     *  The user matching the specified meta key and value, or false if no user found.
     */
    public function get_user_by_meta( $key, $value ) {
        $user = get_users( array(
            'meta_key'      => $key,
            'meta_value'    => $value,
            'number'        => 1,
        ) );

        return empty( $user[0] ) ? false : $user[0];       
    }

    /**
     * Gets the SiteRack connections for this site.
     */
    public function get_connections() {
        $connections    = array();
        $items          = get_site_option( 'siterack_connections', array() );

        foreach ( $items as $props ) {
            $connections[] = new Connection( $props );
        }

        return $connections;
    }
}