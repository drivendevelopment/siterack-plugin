<?php
/*

Plugin Name: SiteRack
Plugin URI: https://siterack.app
Description: Manage all your WordPress sites from a single dashboard with SiteRack.
Version: 0.0.6
Author: Site Rack
Author URI: https://siterack.app
Text Domain: siterack
License: GPLv2 or later

Copyright 2023 Driven Development, LLC (email : hello@siterack.app)

This program is free software; you can redistribute it and/or modify
it under the terms of the GNU General Public License, version 2, as
published by the Free Software Foundation.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with this program; if not, write to the Free Software
Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA  02110-1301  USA

*/

require 'vendor/autoload.php';

require_once( dirname( __FILE__ ) . '/classes/class-singleton.php' );
require_once( dirname( __FILE__ ) . '/classes/class-plugin.php' );

use SiteRack\Plugin;

Plugin::get_instance();