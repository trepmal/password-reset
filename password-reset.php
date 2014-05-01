<?php
/*
 * Plugin Name: Password Reset
 * Plugin URI: trepmal.com
 * Description:
 * Version: 0.5
 * Author: Kailey Lampert
 * Author URI: kaileylampert.com
 * License: GPLv2 or later
 * License URI: http://www.gnu.org/licenses/gpl-2.0.html
 * TextDomain: password-reset
 * DomainPath:
 * Network:
 */

$password_reset = new Password_Reset();

class Password_Reset {

	/* ::__construct
	 *
	 * Get hooked in
	 *
	 * @return void
	 */
	function __construct() {

		add_action( 'password_reset',             array( $this, 'password_reset' ), 10, 2 );

		add_action( 'set_logged_in_cookie',       array( $this, 'set_logged_in_cookie' ), 10, 5 );
		add_filter( 'login_message',              array( $this, 'login_message' ) );

		add_action( 'user_row_actions',           array( $this, 'user_row_actions' ), 10, 2 );
		add_filter( 'manage_users_columns',       array( $this, 'manage_users_columns' ) );
		add_filter( 'manage_users_custom_column', array( $this, 'manage_users_custom_column' ), 10, 3 );

		add_filter( 'wp_ajax_set_password_reset', array( $this, 'set_password_reset_cb' ) );

	}

	/* ::password_reset
	 *
	 * If the user is resetting their password, remove the requirement
	 *
	 * @param obj $user User object for user resetting their password
	 * @param string $new_pass User's new password
	 * @return void
	 */
	function password_reset( $user, $new_pass ) {
		delete_user_meta( $user->ID, 'password_reset' );
	}

	/* ::set_logged_in_cookie
	 *
	 * If current user is required to reset their password. Make sure they're authenticated (that they've made it this far)
	 * delete any existing cookies, fetch a reset key and send them on to the reset password screen
	 * This all happens before they're allowed into the admin
	 *
	 * @param ? $logged_in_cookie
	 * @param ? $expire
	 * @param ? $expiration
	 * @param int $user_id
	 * @param string $logged_in
	 * @return void
	 */
	function set_logged_in_cookie( $logged_in_cookie, $expire, $expiration, $user_id, $logged_in ) {

		if ( $this->user_reset_required( $user_id ) ) {
			// don't let the cookies cause confusion
			wp_clear_auth_cookie();

			// get login name
			$user       = get_user_by( 'id', $user_id );
			$user_login = $user->user_login;

			// get/generate reset key
			global $wpdb;
			$key = $wpdb->get_var(
				$wpdb->prepare(
					"SELECT user_activation_key FROM $wpdb->users WHERE user_login = %s",
					$user_login
				)
			);

			if ( empty( $key ) ) {
				// Generate something random for a key...
				$key = wp_generate_password( 20, false );
				do_action('retrieve_password_key', $user_login, $key );

				global $wp_hasher;
				// Now insert the key, hashed, into the DB.
				if ( empty( $wp_hasher ) ) {
					require_once ABSPATH . 'wp-includes/class-phpass.php';
					$wp_hasher = new PasswordHash( 8, true );
				}
				$hasher = $wp_hasher->HashPassword( $key );

				// Now insert the new md5 key into the db
				$wpdb->update( $wpdb->users,
					array( 'user_activation_key' => $hasher ),
					array( 'user_login'          => $user_login )
				);
			}

			// redirect user to reset page
			$url = network_site_url("wp-login.php?action=rp&key={$key}&login=" . rawurlencode( $user_login ), 'login');
			wp_redirect( $url );
			exit;
		}
	}

	/* ::login_message
	 *
	 * If the user is on the 'rp' (reset password) page, tell them why
	 * We should check if this user if forced to reset their password or not, but the text is generic enough to get away without that.
	 *
	 * @param string $m Current HTML for login message
	 * @return string HTML
	 */
	function login_message( $m ) {
		if ( isset( $_GET['action'] ) && $_GET['action'] == 'rp' ) {
			return $m . '<p class="message">'. __( 'A password-reset has been initiated for your account.', 'password-reset' ) .'</p>';
		}
		return $m;
	}

	/* ::user_row_actions
	 *
	 * Insert the admin switch in the user row
	 *
	 * @param array $actions Current user actions
	 * @param obj $user User object
	 * @return array
	 */
	function user_row_actions( $actions, $user ) {
		if ( current_user_can( 'edit_user', $user->ID ) ) {
			$actions['password-reset-action'] = '<a href="#" class="set-password-reset">'. __( 'Password Reset', 'password-reset' ) .'</a>';
		}
		return $actions;
	}

	/* ::manage_users_columns
	 *
	 * Create a column in the Users table
	 * Hackish: add admin_footer hook here so we don't have to check screen ids
	 *
	 * @param array $columns Columns for user list table
	 * @return array
	 */
	function manage_users_columns( $columns ) {
		// totally hacking this hook in here so we don't have to check screen ids
		add_action( 'admin_footer', array( $this, 'admin_footer' ) );

		$columns['reset'] = __( 'Password Reset', 'password-reset' );
		return $columns;
	}

	/* ::manage_users_custom_column
	 *
	 * Populate our custom column
	 * Indicate whether the current user is required to change their password.
	 *
	 * @param string $x HTML for column
	 * @param string $column Column ID
	 * @param int $user_id Current user
	 * @return string HTML
	 */
	function manage_users_custom_column( $x, $column, $user_id ) {
		if ( $column != 'reset' ) {
			return $x;
		}

		$x = '<span class="password-reset">';
		if ( $this->user_reset_required( $user_id ) ) {
			$x .= __( 'Password reset initiated.', 'password-reset' );
		}
		$x .= '</span>';
		return $x;
	}

	/* ::admin_footer
	 *
	 * jQuery for the user row switch
	 *
	 * @return void
	 */
	function admin_footer() {
		?><script>
		jQuery(document).ready(function($) {
			$('body').on( 'click', '.set-password-reset', function(ev) {
				ev.preventDefault();

				var $tr = $(this).closest('tr'),
					id = $tr.attr('id').replace( 'user-', '' );

				$.post( ajaxurl, {
					action: 'set_password_reset',
					user_id: id
				}, function( response ) {

					if ( ! response.success ) {
						alert( response.data );
						return;
					}

					$tr.find( '.password-reset' ).html( response.data );

				}, 'json' );
			});
		});
		</script><?php
	}

	/* ::set_password_reset_cb
	 *
	 * Ajax callback
	 * Toggle the password requirement setting for given user
	 *
	 * @return void
	 */
	function set_password_reset_cb() {
		$user_id = intval( $_POST['user_id'] );
		$user = get_user_by( 'id', $user_id );
		if ( ! $user ) {
			return false;
		}

		// cap check
		if ( ! current_user_can('edit_user', $user_id ) ) {
			wp_send_json_error( 'You do not have permission to edit this user.', 'password-reset' );
		}

		// this is a simple toggle. if set, unset; otherwise set.
		if ( $this->user_reset_required( $user_id ) ) {
			delete_user_meta( $user_id, 'password_reset' );
			wp_send_json_success( 'Password reset no longer required.', 'password-reset' );
		} else {
			update_user_meta( $user_id, 'password_reset', 1 );
			wp_send_json_success( 'Password reset required.', 'password-reset' );
		}
	}

	/* ::user_reset_required
	 *
	 * Check if given user is required to reset their password
	 *
	 * @param int $user_id User ID to check
	 * @return bool
	 */
	function user_reset_required( $user_id ) {
		$reset = get_user_meta( $user_id, 'password_reset', true );
		return ! empty( $reset );
	}

}

// eof