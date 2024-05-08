<?php

namespace SiteRack\REST_API\v1;

use Exception;
use WP_Error;
use WP_REST_Request;
use WP_REST_Controller;
use WP_REST_Server;
use Plugin_Upgrader;

use SiteRack\Plugin;
use SiteRack\Cache_Helper;
use SiteRack\JSON_Web_Token;
use SiteRack\Empty_Upgrader_Skin;

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
        register_rest_route( $this->base, '/connect', array(
            array(
                'methods'               => WP_REST_Server::CREATABLE,
                'callback'              => array( $this, 'connect' ),
                'permission_callback'   => '__return_true',
                'args' => array(
                    'token' => array(
                        'required'          => true,
                        'sanitize_callback' => 'sanitize_text_field',
                    )
                ),
            ),
        ) );

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
        
        register_rest_route( $this->base, '/cache/flush', array(
            array(
                'methods'               => WP_REST_Server::CREATABLE,
                'callback'              => array( $this, 'flush_cache' ),
                'permission_callback'   => array( $this, 'has_valid_token' ),
            ),
        ) );  

        register_rest_route( $this->base, '/roles', array(
            array(
                'methods'               => WP_REST_Server::READABLE,
                'callback'              => array( $this, 'roles' ),
                'permission_callback'   => array( $this, 'is_admin' ),
            ),
        ) );   
        
        register_rest_route( $this->base, '/plugins', array(
            array(
                'methods'               => WP_REST_Server::READABLE,
                'callback'              => array( $this, 'plugins' ),
                'permission_callback'   => array( $this, 'is_admin' ),
            ),           
        ) );  
        
        register_rest_route( $this->base, '/plugins/update', array(
            array(
                'methods'               => WP_REST_Server::CREATABLE,
                'callback'              => array( $this, 'update_plugins' ),
                'permission_callback'   => array( $this, 'is_admin' ),
            ),            
        ) );  
        
        register_rest_route( $this->base, '/plugins/delete', array(
            array(
                'methods'               => WP_REST_Server::CREATABLE,
                'callback'              => array( $this, 'delete_plugins' ),
                'permission_callback'   => array( $this, 'is_admin' ),
            ),            
        ) ); 

        register_rest_route( $this->base, '/plugins/activate', array(
            array(
                'methods'               => WP_REST_Server::CREATABLE,
                'callback'              => array( $this, 'activate_plugin' ),
                'permission_callback'   => array( $this, 'is_admin' ),
                'args' => array(
                    'plugin' => array(
                        'required'          => true,
                        'sanitize_callback' => 'sanitize_text_field',
                    ),
                    'network_wide' => array(
                        'default'           => false,
                        'sanitize_callback' => 'rest_sanitize_boolean',
                    ),		
                ),	                
            ),            
        ) );

        register_rest_route( $this->base, '/plugins/bulk-activate', array(
            array(
                'methods'               => WP_REST_Server::CREATABLE,
                'callback'              => array( $this, 'activate_plugins' ),
                'permission_callback'   => array( $this, 'is_admin' ),
                'args' => array(
                    'plugins' => array(
                        'required'          => true,
                        'sanitize_callback' => function( $param, $request, $key ){
                            return array_map( 'sanitize_text_field', $param );
                        },
                    ),
                    'network_wide' => array(
                        'default'           => false,
                        'sanitize_callback' => 'rest_sanitize_boolean',
                    ),	                    			
                ),	                
            ),            
        ) );

        register_rest_route( $this->base, '/plugins/deactivate', array(
            array(
                'methods'               => WP_REST_Server::CREATABLE,
                'callback'              => array( $this, 'deactivate_plugin' ),
                'permission_callback'   => array( $this, 'is_admin' ),
                'args' => array(
                    'plugin' => array(
                        'required'          => true,
                        'sanitize_callback' => 'sanitize_text_field',
                    ),
                    'network_wide' => array(
                        'default'           => false,
                        'sanitize_callback' => 'rest_sanitize_boolean',
                    ),                    		
                ),	                
            ),            
        ) ); 

        register_rest_route( $this->base, '/plugins/bulk-deactivate', array(
            array(
                'methods'               => WP_REST_Server::CREATABLE,
                'callback'              => array( $this, 'deactivate_plugins' ),
                'permission_callback'   => array( $this, 'is_admin' ),
                'args' => array(
                    'plugins' => array(
                        'required'          => true,
                        'sanitize_callback' => function( $param, $request, $key ){
                            return array_map( 'sanitize_text_field', $param );
                        },
                    ),	
                    'network_wide' => array(
                        'default'           => false,
                        'sanitize_callback' => 'rest_sanitize_boolean',
                    ),	                    			
                ),	                
            ),            
        ) );           
    }  

    /**
     * Checks the request for a JSON web token and attempts to decode it
     * by looping through the site's connections until one is found that
     * can decode the token.
     * 
     * @return mixed
     *  The decoded token or false on failure.
     */
    private function get_decoded_token() {
        $token = isset( $_SERVER['HTTP_X_SITERACK_TOKEN'] ) ? sanitize_text_field( $_SERVER['HTTP_X_SITERACK_TOKEN'] ) : false;

        // Nothing we can do if we don't have a token
        if ( ! $token ) {
            return false;
        }

        $decoded_token  = false;
        $connections    = Plugin::get_instance()->get_connections();

        foreach ( $connections as $connection ) {
            $json_web_token = new JSON_Web_Token( $connection->secret );
            $decoded_token  = $json_web_token->validate( $token );

            if ( is_wp_error( $token ) ) {
                // Didn't work, try next connection
                continue;
            } else {
                return $decoded_token;
            }
        }

        return false;
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

        /*
        $json_web_token = new JSON_Web_Token();
        $token 			= $json_web_token->get_token_from_header();
        $token 			= $json_web_token->validate( $token );

        if ( is_wp_error( $token ) ) {
            //$this->token_error = $token;

            return $user_id;
        }
        */
        $token = $this->get_decoded_token();

        if ( ! $token ) {
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
     * Finds the user with the specified connection token, and, if the token
     * hasn't expired, issues a JSON web token for the user.
     */
    public function connect( WP_REST_Request $request ) {
        $plugin = Plugin::get_instance();
        $token  = $request->get_param( 'token' );
        $user   = $plugin->get_user_by_meta( 'siterack_connection_token', $token );

        if ( ! $user ) {
            return new WP_Error(
                'siterack_connection_user_not_found',
                __( 'Invaid connection token.', 'siterack' ),
                array( 'status' => 401 )
            );
        }

        if ( $plugin->is_connection_token_expired( $token, $user->ID ) ) {
            return new WP_Error(
                'siterack_connection_token_expired',
                __( 'Connection token has expired.', 'siterack' ),
                array( 'status' => 401 )
            );
        }

        return $plugin->init_plugin( $user );
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
        // TODO: Review native WP users endpoint to see if it can be used instead
        // TODO: Add pagination
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

    /**
     * Returns the site's plugins.
     */
    public function plugins( WP_REST_Request $request ) {
        if ( ! function_exists( 'get_plugins' ) ) {
            require_once ABSPATH . 'wp-admin/includes/plugin.php';
        }

        if ( ! function_exists( 'get_plugin_updates' ) ) {
            require_once ABSPATH . 'wp-admin/includes/update.php';
        }

        // Force WordPress to check for updates
        wp_update_plugins();

        $plugins        = get_plugins();
        $updates        = get_plugin_updates();
        $active_plugins = ( array ) get_option( 'active_plugins', array() );

        foreach ( $plugins as $slug => $plugin ) {
            $plugins[ $slug ]['slug']     = $slug;
            $plugins[ $slug ]['status']   = 'inactive';

            // Check if plugin is active
            if ( in_array( $slug, $active_plugins ) ) {
                $plugins[ $slug ]['status'] = 'active';
            }

            // Append update info if available
            if ( isset( $updates[ $slug ]->update ) ) {
                $plugins[ $slug ]['update'] = $updates[ $slug ]->update;
            }
        }

        return array_values( $plugins );
    }

    /**
     * Updates the specified plugins.
     */
    public function update_plugins( WP_REST_Request $request ) {
        if ( ! class_exists( 'Plugin_Upgrader' ) ) {
            require_once ABSPATH . 'wp-admin/includes/misc.php';
            require_once ABSPATH . 'wp-admin/includes/file.php';
            require_once ABSPATH . 'wp-admin/includes/plugin.php';
            require_once ABSPATH . 'wp-admin/includes/class-wp-upgrader.php';
            require_once ABSPATH . 'wp-admin/includes/class-plugin-upgrader.php';
        }

        $results    = array();
        $plugins    = $request->get_param( 'plugins' );
        $skin       = new Empty_Upgrader_Skin();
        $upgrader   = new Plugin_Upgrader( $skin );

        foreach ( $plugins as $plugin ) {
            $result = $upgrader->upgrade( $plugin );
    
            if ( true === $result ) {
                $results[] = array(
                    'plugin'    => $plugin,
                    'success'   => true,
                    'error'     => false,
                );
            } elseif ( is_wp_error( $result ) ) {
                $results[] = array(
                    'plugin'    => $plugin,
                    'success'   => false,
                    'error'     => $result->get_error_message(),
                );
            } elseif ( false === $result ) {
                $results[] = array(
                    'plugin'    => $plugin,
                    'success'   => false,
                    'error'     => end( $skin->feedback ),
                );
            } else {
                $error = __( 'An unknown error occurred.', 'siterack' );
    
                if ( is_wp_error( $skin->result ) ) {
                    $error = $skin->result->get_error_message();
                }
    
                $results[] = array(
                    'plugin'    => $plugin,
                    'success'   => false,
                    'error'     => $error,
                );
            }
        }

        return $results;
    }

    /**
     * Deletes the specified plugins.
     */
    public function delete_plugins( WP_REST_Request $request ) {
        if ( ! function_exists( 'delete_plugins' ) ) {
            require_once ABSPATH . 'wp-admin/includes/plugin.php';
        }

        if ( ! function_exists( 'request_filesystem_credentials' ) ) {
            require_once ABSPATH . 'wp-admin/includes/file.php';
        }

        $results            = array();
        $error              = false;
        $error_message      = '';
        $plugins            = $request->get_param( 'plugins' );
        $active_plugins     = ( array ) get_option( 'active_plugins', array() );
        $plugins_to_delete  = array_diff( $plugins, $active_plugins );

        // delete_plugins outputs a form if credentials are needed or invalid. Capture
        // the output if any to prevent it from interfering with the API response.
        ob_start();

        $result = delete_plugins( $plugins_to_delete );

        ob_end_clean();

        if ( is_wp_error( $result ) ) {
            $error          = true;
            $error_message  = $result->get_error_message();
        } elseif ( true !== $result ) {
            // If the result isn't a WP_Error and it's also not true (i.e. failed) then
            // it should be due to not having permission to write to the filesystem.
            $error          = true;
            $error_message  = __( 'Filesystem is not writable.', 'siterack' );
        }

        foreach ( $plugins as $plugin ) {
            if ( in_array( $plugin, $active_plugins ) ) {
                $results[] = array(
                    'plugin'    => $plugin,
                    'success'   => false,
                    'error'     => __( 'Plugin cannot be deleted because it is active.', 'siterack' ),
                );
            } else {
                $results[] = array(
                    'plugin'    => $plugin,
                    'success'   => ! $error,
                    'error'     => $error ? $error_message : false,
                );
            }            
        }

        return $results;
    }

    /**
     * Activates a single plugin.
     */
    public function activate_plugin( WP_REST_Request $request ) {
        if ( ! function_exists( 'activate_plugin' ) ) {
            require_once ABSPATH . 'wp-admin/includes/plugin.php';
        }

        $plugin         = $request->get_param( 'plugin' );
        $network_wide   = $request->get_param( 'network_wide' );
        $result         = activate_plugin( $plugin, '', $network_wide );

        if ( is_wp_error( $result ) ) {
            return $result;
        } else {
            return true;
        }
    }

    /**
     * Activates multiple plugins at once.
     */
    public function activate_plugins( WP_REST_Request $request ) {
        if ( ! function_exists( 'activate_plugins' ) ) {
            require_once ABSPATH . 'wp-admin/includes/plugin.php';
        }

        $plugins        = $request->get_param( 'plugins' );
        $network_wide   = $request->get_param( 'network_wide' );
        $result         = activate_plugins( $plugins, '', $network_wide );

        if ( is_wp_error( $result ) ) {
            return $result;
        } else {
            return true;
        }
    }

    /**
     * Deactivates a single plugin.
     */
    public function deactivate_plugin( WP_REST_Request $request ) {
        if ( ! function_exists( 'deactivate_plugins' ) ) {
            require_once ABSPATH . 'wp-admin/includes/plugin.php';
        }

        $plugin         = $request->get_param( 'plugin' );
        $network_wide   = $request->get_param( 'network_wide' );
        
        deactivate_plugins( $plugin, false, $network_wide );

        return true;
    }     
    /**
     * Deactivates multiple plugins at once.
     */
    public function deactivate_plugins( WP_REST_Request $request ) {
        if ( ! function_exists( 'deactivate_plugins' ) ) {
            require_once ABSPATH . 'wp-admin/includes/plugin.php';
        }

        $plugins        = $request->get_param( 'plugins' );
        $network_wide   = $request->get_param( 'network_wide' );
        
        deactivate_plugins( $plugins, false, $network_wide );

        return true;
    }    

    /**
     * Flushes the site's cache.
     */
    public function flush_cache( WP_REST_Request $request ) {
        $cache_helper = new Cache_Helper();

        $cache_helper->flush_all();

        return true;
    }
}