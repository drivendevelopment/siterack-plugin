<?php

namespace SiteRack;

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

    /**
     * Holds an instance of the class.
     *
     * @var Singleton
     */
    protected static $instance;

    protected function __construct() {
        // Register autoload function
        spl_autoload_register( array( $this, 'autoload' ) );

        add_action( 'init', array( $this, 'init' ) );
        add_action( 'admin_init', array( $this, 'init_updates' ) );
        add_action( 'rest_api_init', array( $this, 'init_rest_api' ) );
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
        $this->maybe_init_plugin();
    }

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

    public function maybe_init_plugin() {
        $action = empty( $_GET['action'] ) ? false : $_GET['action'];

        // Bail if we're not initializing the plugin
        if ( 'siterack_init' != $action ) return;

        // Clean the output buffer to avoid any warnings or other output from
        // potentially breaking the JSON response
        ob_clean();

        header( 'Content-Type: application/json; charset=utf-8' );

        $user 		= wp_get_current_user();
        $secret 	= get_option( 'siterack_secret', false );

        // Only allow logged-in users to perform this action
        if ( 0 == $user->ID ) {
            wp_send_json_error( __( 'User not logged in.', 'siterack' ) );
        }

        // Only allow administrators to perform this action
        if ( ! in_array( 'administrator', $user->roles ) ) {
            wp_send_json_error( __( 'Only administrators may initialize SiteRack.', 'siterack' ) );
        }

        // Only generate a secret if the site doesn't already has one
        if ( ! $secret ) {
            // Generate a secret
            $secret = bin2hex( random_bytes( 32 ) );

            // Save the secret
            update_option( 'siterack_secret', $secret );
        }

        // Generate a token.  This has to be done after the secret is saved
        // as the token is signed with the secret
        $token = new JSON_Web_Token();
        $token = $token->generate( $user->ID );

        wp_send_json_success( array(
            'name' 				=> get_bloginfo( 'name' ),			
            'user_id' 			=> $user->ID,
            'user_email' 		=> $user->user_email,
            'user_display_name' => $user->display_name,
            'user_avatar_url' 	=> get_avatar_url( $user->ID ),
            'token' 			=> $token,
        ) );

        exit();
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
}