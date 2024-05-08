<?php

namespace SiteRack;

use Exception;
use WP_Error;
use Firebase\JWT\JWT;
use Firebase\JWT\Key;

// Disable direct load
if ( ! defined( 'ABSPATH' ) ) {
    die( 'Access denied.' );
}

/**
 * Handles generating and validating JSON Web Tokens.
 */
class JSON_Web_Token {

    private string $secret;

    public string $algorithm = 'HS256';

    public function __construct( $secret = '' ) {
        $this->secret = $secret;
    }

    public function get_token_from_header() {
        return isset( $_SERVER['HTTP_X_SITERACK_TOKEN'] ) ? sanitize_text_field( $_SERVER['HTTP_X_SITERACK_TOKEN'] ) : false;
    }

    public function generate( $user_id ) {
        $issued_at  = time();
        $expire     = $issued_at + ( DAY_IN_SECONDS * 365 );

        $token = [
            'iss'  => get_bloginfo( 'url' ),
            'iat'  => $issued_at,
            'nbf'  => $issued_at,
            'exp'  => $expire,
            'data' => [
                'user_id' => $user_id,
            ],
        ];

        $token = JWT::encode(
            $token,
            $this->secret,
            $this->algorithm
        );

        return $token;
    }  
    
    public function validate( $token ) {
        if ( ! $token ) {
            return new WP_Error(
                'siterack_missing_token',
                __( 'Missing token.', 'siterack' ),
                [
                    'status' => 403,
                ]
            );
        }

        if ( ! $this->secret ) {
            return new WP_Error(
                'siterack_missing_secret',
                __( 'Missing site secret.', 'siterack' ),
                [
                    'status' => 403,
                ]
            );
        }

        try {
            $token = JWT::decode( $token, new Key( $this->secret, $this->algorithm ) );
// TODO: validate expiration
            // Validate iss
            if ( get_bloginfo( 'url' ) !== $token->iss ) {
                return new WP_Error(
                    'siterack_bad_iss',
                    __( 'Issuer mismatch.', 'siterack' ),
                    [
                        'status' => 403,
                    ]
                );
            }

            if ( empty( $token->data->user_id ) ) {
                return new WP_Error(
                    'siterack_missing_user_id',
                    __( 'User ID not found in the token', 'siterack' ),
                    [
                        'status' => 403,
                    ]
                );
            }

            return $token;
        } catch ( Exception $e ) {
            // Something were wrong trying to decode the token
            return new WP_Error(
                'siterack_invalid_token',
                $e->getMessage(),
                [
                    'status' => 403,
                ]
            );
        }
    }	
}
