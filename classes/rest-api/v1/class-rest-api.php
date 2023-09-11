<?php

namespace SiteRack\REST_API\v1;

use Exception;
use WP_Error;
use WP_REST_Request;
use WP_REST_Controller;
use WP_REST_Server;
use SiteRack\JSON_Web_Token;

// Disable direct load
if ( ! defined( 'ABSPATH' ) ) {
    die( 'Access denied.' );
}

class REST_API extends WP_REST_Controller {

    protected $version = 1;

    protected $base = 'siterack/v1';

    private $token_error;

    public function __construct() {
        add_filter( 'determine_current_user', array( $this, 'determine_current_user' ) );

        $this->register_routes();
    }

    public function register_routes() {
        register_rest_route( $this->base, '/login-url', array(
            array(
                'methods'               => WP_REST_Server::CREATABLE,
                'callback'              => array( $this, 'login_url' ),
                'permission_callback'   => array( $this, 'login_url_permission_callback' ),
                'args' => array(
                    'user_id' => array(
                        'required' => true,
                    )
                ),
            ),
        ) );

        register_rest_route( $this->base, '/users', array(
            array(
                'methods'               => WP_REST_Server::READABLE,
                'callback'              => array( $this, 'users' ),
                'permission_callback'   => array( $this, 'is_admin' ),
            ),
        ) );	
        
        register_rest_route( $this->base, '/users/token', array(
            array(
                'methods'               => WP_REST_Server::CREATABLE,
                'callback'              => array( $this, 'user_token' ),
                'permission_callback'   => '__return_true',
                'args' => array(
                    'username' => array(
                        'required'          => true,
                        'sanitize_callback' => 'sanitize_text_field',
                    ),
                    'password' => array(
                        'required'          => true,
                        'sanitize_callback' => 'sanitize_text_field',
                    ),					
                ),				
            ),
        ) );
        
        register_rest_route( $this->base, '/roles', array(
            array(
                'methods'               => WP_REST_Server::READABLE,
                'callback'              => array( $this, 'roles' ),
                'permission_callback'   => array( $this, 'is_admin' ),
            ),
        ) );        
    }  

    /**
     * Intercepts REST API requests and sets the current user to the one found in
     * the SiteRack JSON web token (if a user isn't already set).  If the token
     * doesn't exist or is invalid, nothing is changed.
     * 
     * Adapted from JWT Authentication for WP REST API plugin by Enrique Chavez.
     */
    public function determine_current_user( $user_id ) {
        /**
         * This hook only should run on the REST API requests to determine
         * if the user in the token (if any) is valid; for any other
         * calls (ex. wp-admin/.*), return the user.
         **/
        $rest_api_slug = rest_get_url_prefix();
        $requested_url = sanitize_url( $_SERVER['REQUEST_URI'] );

        // If we already have a valid user, or we have an invalid url, don't attempt to validate token
        if ( ! defined( 'REST_REQUEST' ) || ! REST_REQUEST || strpos( $requested_url, $rest_api_slug ) === false || $user_id ) {
            return $user_id;
        }

        // If the request URI is for validating the token don't do anything
        $validate_uri = strpos( $requested_url, 'token/validate' );

        if ( $validate_uri > 0 ) {
            return $user_id;
        }

        $json_web_token = new JSON_Web_Token();
        $token 			= $json_web_token->get_token_from_header();
        $token 			= $json_web_token->validate( $token );

        if ( is_wp_error( $token ) ) {
            //$this->token_error = $token;

            return $user_id;
        }

        // Everything is ok, return the user ID stored in the token
        return $token->data->user_id;
    }

    public function rest_pre_dispatch( $request ) {
        if ( is_wp_error( $this->token_error ) ) {
            return $this->token_error;
        }

        return $request;
    }

    /**
     * Ensure that the user ID that a login URL is being requested for matches
     * the user ID in the authenticaiton token.
     */
    public function login_url_permission_callback( WP_REST_Request $request ) {
        $user_id = $request->get_param( 'user_id' );

        return get_current_user_id() == $user_id;
    }

    /**
     * Checks that an authentication token is present and valid.
     */
    public function has_valid_token( WP_REST_Request $request ) {
        $json_web_token = new JSON_Web_Token();
        $token          = $json_web_token->get_token_from_header();
        $token          = $json_web_token->validate( $token );

        return ! is_wp_error( $token );
    }

    /**
     * Checks that the current user is an administrator.
     */
    public function is_admin() {
        $user = wp_get_current_user();

        return ! empty( $user->roles ) && in_array( 'administrator', $user->roles );
    }

    /**
     * Returns a URL that can be used to log the user into the site.
     */
    public function login_url( WP_REST_Request $request ) {
        $user_id    = $request->get_param( 'user_id' );
        $token      = bin2hex( random_bytes( 32 ) );

        update_user_meta( $user_id, 'siterack_login_token', $token );
        update_user_meta( $user_id, 'siterack_login_token_expiration', strtotime( '+1 minute' ) );
        
        $url = add_query_arg( array(
            'action'    => 'siterack_login',
            'token'     => $token,
        ), get_site_url() );

        return $url;
    }

    /**
     * Returns the site's roles.
     */
    public function roles() {
        $roles      = array();
        $wp_roles 	= wp_roles();
        $names      = $wp_roles->get_names();
    
        foreach ( $names as $role => $name ) {
            $roles[] = array(
                'role'	=> $role,
                'name'	=> $name,
            );
        }

        return $roles;
    }

    /**
     * Returns the site's users.
     */
    public function users() {
        $users = get_users( array(
            'fields' => array( 'ID', 'user_login', 'user_email', 'display_name' ),
        ) );

        foreach ( $users as &$user ) {
            $user->avatar_url   = get_avatar_url( $user->ID );
            $user->first_name   = get_user_meta( $user->ID, 'first_name', true );
            $user->last_name    = get_user_meta( $user->ID, 'last_name', true );
        }

        return $users;
    }

    /**
     * Checks the user's credentials and, if valid, returns a JSON web token that
     * can be used to authenticate future requests as the user.
     */
    public function user_token( WP_REST_Request $request ) {
        $username   = $request->get_param( 'username' );
        $password   = $request->get_param( 'password' );
        $user       = wp_authenticate( $username, $password );

        if ( is_wp_error( $user ) ) {
            return new WP_Error(
                'siterack_error',
                $user->get_error_message(),
                array( 'status' => 401 )
            );
        } else {
            $json_web_token = new JSON_Web_Token();
            $token          = $json_web_token->generate( $user->ID );

            return array(
                'token' => $token,
            );
        }
    }
}
