<?php

namespace SiteRack;

require_once ABSPATH . 'wp-admin/includes/class-wp-upgrader-skin.php';

/**
 * Suppresses output from the WP_Upgrader class so that we can update plugins
 * via the REST API without the upgrader outputting messages.
 */
class Empty_Upgrader_Skin extends \WP_Upgrader_Skin {

    public $feedback = array();

	public function header() {}

	public function footer() {}

	public function before() {}

	public function after() {}

	protected function decrement_update_count( $type ) {}

	public function bulk_header() {}

	public function bulk_footer() {}
    
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