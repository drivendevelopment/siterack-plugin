<?php

namespace SiteRack;

require_once ABSPATH . 'wp-admin/includes/class-wp-upgrader-skin.php';

class Empty_Upgrader_Skin extends \WP_Upgrader_Skin {

    public $feedback = array();

    public $errors = array();

	public function header() {}

	public function footer() {}

	public function before() {}

	public function after() {}

	protected function decrement_update_count( $type ) {}

	public function bulk_header() {}

	public function bulk_footer() {}

    public function error( $errors ) {
        $this->errors = $errors;
    }
    
	public function feedback( $feedback, ...$args ) {
		if ( isset( $this->upgrader->strings[ $feedback ] ) ) {
			$feedback = $this->upgrader->strings[ $feedback ];
		}

		if ( str_contains( $feedback, '%' ) ) {
			if ( $args ) {
				$args     = array_map( 'strip_tags', $args );
				$args     = array_map( 'esc_html', $args );
				$feedback = vsprintf( $feedback, $args );
			}
		}

		if ( empty( $feedback ) ) {
			return;
		}
		
        $this->feedback[] = $feedback;
	}    
}