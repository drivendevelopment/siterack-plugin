<?php

namespace SiteRack;

class Cache_Helper {

    public function flush_all() {
        $this->flush_wp_rocket_cache();
        $this->flush_wp_engine_cache();
        $this->flush_wp_cache();
        $this->flush_w3tc_cache();
        $this->flush_wp_super_cache();
    }
    
    public function flush_wp_engine_cache() {
        if ( ! class_exists( 'WpeCommon' ) ) {
            return false;
        }
    
        if ( method_exists( 'WpeCommon', 'purge_memcached' ) ) {
            \WpeCommon::purge_memcached();
        }
    
        if ( method_exists( 'WpeCommon', 'clear_maxcdn_cache' ) ) {
            \WpeCommon::clear_maxcdn_cache();
        }
    
        if ( method_exists( 'WpeCommon', 'purge_varnish_cache' ) ) {
            \WpeCommon::purge_varnish_cache();
        }        
    }

    public function flush_wp_rocket_cache() {
        // Clear cache and preload if preload is enabled
        if ( function_exists( 'rocket_clean_domain' ) ) {
            rocket_clean_domain();
         }
        
        // Clear minified CSS and JavaScript files
        if ( function_exists( 'rocket_clean_minify' ) ) {
            rocket_clean_minify();
        }        
    }

    public function flush_wp_cache() {
        global $wp_object_cache;
    
        if ( $wp_object_cache && is_object( $wp_object_cache ) ) {
            wp_cache_flush();
        }        
    }

    public function flush_w3tc_cache() {
        if ( function_exists( 'w3tc_flush_all' ) ) {
            w3tc_flush_all();
        }        
    }

    public function flush_wp_super_cache() {
        if ( function_exists( 'prune_super_cache' ) && function_exists( 'get_supercache_dir' ) ) {
            prune_super_cache( get_supercache_dir(), true );
            
            return true;
        }

        return false;
    }
}