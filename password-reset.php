<?php
/*
 * Plugin Name: Password Reset
 * Plugin URI: trepmal.com
 * Description:
 * Version:
 * Author: Kailey Lampert
 * Author URI: kaileylampert.com
 * License: GPLv2 or later
 * License URI: http://www.gnu.org/licenses/gpl-2.0.html
 * TextDomain: password-reset
 * DomainPath:
 * Network: false
 */

$password_reset = new Password_Reset();

class Password_Reset {

	function __construct() {

		add_action( 'password_reset', array( &$this, 'password_reset'), 10, 2 );

		add_action( 'set_logged_in_cookie', array( &$this, 'set_logged_in_cookie' ), 10, 5 );
		add_filter( 'login_message', array( &$this, 'login_message' ) );

		add_action( 'user_row_actions', array( &$this, 'user_row_actions' ) );
		add_filter( 'manage_users_columns', array( &$this, 'manage_users_columns' ) );
		add_filter( 'manage_users_custom_column', array( &$this, 'manage_users_custom_column' ), 10, 3 );

		add_filter( 'wp_ajax_set_password_reset', array( &$this, 'set_password_reset_cb' ) );

	}

	function password_reset( $user, $new_pass ) {
		// if reset flag present
		if ( '' != ( $reset = get_user_meta( $user->ID, 'password_reset', true ) ) ) {
			delete_user_meta( $user->ID, 'password_reset' );
		}
	}

	function set_logged_in_cookie( $logged_in_cookie, $expire, $expiration, $user_id, $logged_in ) {

		// if reset flag present
		if ( '' != ( $reset = get_user_meta( $user_id, 'password_reset', true ) ) ) {
			// don't let the cookies cause confusion
			wp_clear_auth_cookie();

			// get login name
			$user = get_user_by( 'id', $user_id );
			$user_login = $user->user_login;

			// get/generate reset key
			global $wpdb;
			$key = $wpdb->get_var($wpdb->prepare("SELECT user_activation_key FROM $wpdb->users WHERE user_login = %s", $user_login));
			if ( empty($key) ) {
				// Generate something random for a key...
				$key = wp_generate_password(20, false);
				do_action('retrieve_password_key', $user_login, $key);
				// Now insert the new md5 key into the db
				$wpdb->update($wpdb->users, array('user_activation_key' => $key), array('user_login' => $user_login));
			}

			// redirect user to reset page
			$url = network_site_url("wp-login.php?action=rp&key=$key&login=" . rawurlencode($user_login), 'login');
			wp_redirect( $url );
			exit;
		}
	}

	function login_message( $m ) {
		if ( isset( $_GET['action'] ) && $_GET['action'] == 'rp' )
			return $m . '<p class="message">'. __( 'A password-reset has been initiated for your account.', 'password-reset' ) .'</p>';
		return $m;
	}

	function user_row_actions( $actions ) {
		$actions[] = '<a href="#" class="set-password-reset">'. __( 'Password Reset', 'password-reset' ) .'</a>';
		return $actions;
	}

	function manage_users_columns( $columns ) {
		// totally hacking this hook in here so we don't have to check screen ids
		add_action( 'admin_footer', array( &$this, 'admin_footer' ) );

		$columns['reset'] = __( 'Password Reset', 'password-reset' );
		return $columns;
	}

	function manage_users_custom_column( $x, $column, $user_id ) {
		if ( $column != 'reset' ) return $x;

		$x = '<span class="password-reset">';
		if ( '' != ( $reset = get_user_meta( $user_id, 'password_reset', true ) ) ) {
			$x .= __( 'Password reset initiated.', 'password-reset' );
		}
		$x .= '</span>';
		return $x;
	}

	function admin_footer() {
		?><script>
		jQuery(document).ready(function($) {
			$('body').on( 'click', '.set-password-reset', function(ev) {
				ev.preventDefault();

				var $tr = $(this).closest('tr');
				id = $tr.attr('id').replace( 'user-', '' );

				$.post( ajaxurl, {
					action: 'set_password_reset',
					user_id: id
				}, function( response ) {

					if ( response == 'required' ) {
						$tr.find( '.password-reset' ).html( '<?php _e( 'Password reset required', 'password-reset' ); ?>' );
					} else {
						$tr.find( '.password-reset' ).html( '' );
					}

				});
			});
		});
		</script><?php
	}

	// ajax callback
	function set_password_reset_cb() {
		$user_id = intval( $_POST['user_id'] );
		$user = get_user_by( 'id', $user_id );
		if ( !$user ) return false;

		$status = get_user_meta( $user_id, 'password_reset', 0 );
		if ( ! empty( $status ) ) {
			delete_user_meta( $user_id, 'password_reset' );
			die( 'not-required' );
		} else {
			update_user_meta( $user_id, 'password_reset', 1 );
			die( 'required' );
		}
	}

}

// eof