<?php
/**
 * Plugin Name: Force Login to View Page
 * Plugin URI: http://absolutodesigns.com/plugins
 * Description: Force users to login before viewing pages. Exclude specific pages and allow certain user roles to bypass the requirement.
 * Version: 1.0.0
 * Author: Absoluto Designs
 * Author URI: http://absolutodesigns.com
 * Requires at least: 5.0
 * Requires PHP: 7.0
 * Tested up to: 6.4
 * Network: false
 * License: GPL v2 or later
 * License URI: https://www.gnu.org/licenses/gpl-2.0.html
 * Text Domain: force-login-view
 * Domain Path: /languages
 */

// Exit if accessed directly
if (!defined('ABSPATH')) {
    exit;
}

// Check WordPress version
if (version_compare(get_bloginfo('version'), '5.0', '<')) {
    add_action('admin_notices', function() {
        echo '<div class="error"><p>';
        printf(
            esc_html__('Force Login to View Page requires WordPress 5.0 or higher. You are running WordPress %s. Please upgrade WordPress to activate this plugin.', 'force-login-view'),
            esc_html(get_bloginfo('version'))
        );
        echo '</p></div>';
    });
    return;
}

// Check PHP version
if (version_compare(PHP_VERSION, '7.0', '<')) {
    add_action('admin_notices', function() {
        echo '<div class="error"><p>';
        printf(
            esc_html__('Force Login to View Page requires PHP 7.0 or higher. You are running PHP %s. Please upgrade PHP to activate this plugin.', 'force-login-view'),
            esc_html(PHP_VERSION)
        );
        echo '</p></div>';
    });
    return;
}

// Define plugin constants
define('FLV_VERSION', '1.0.0');
define('FLV_PLUGIN_DIR', plugin_dir_path(__FILE__));
define('FLV_PLUGIN_URL', plugin_dir_url(__FILE__));
define('FLV_MIN_WP_VERSION', '5.0');
define('FLV_MIN_PHP_VERSION', '7.0');

class Force_Login_View {
    
    /**
     * Instance of this class
     */
    private static $instance = null;
    
    /**
     * Get instance of this class
     */
    public static function get_instance() {
        if (null === self::$instance) {
            self::$instance = new self();
        }
        return self::$instance;
    }
    
    /**
     * Constructor
     */
    private function __construct() {
        // Hook into WordPress
        add_action('template_redirect', array($this, 'force_login_redirect'));
        add_action('admin_menu', array($this, 'add_admin_menu'));
        add_action('admin_init', array($this, 'register_settings'));
        add_action('admin_enqueue_scripts', array($this, 'enqueue_admin_scripts'));
        add_action('login_message', array($this, 'display_login_message'));
        add_action('admin_bar_menu', array($this, 'add_admin_bar_notice'), 999);
        
        // Add settings link to plugin actions
        $plugin_file = plugin_basename(__FILE__);
        add_filter("plugin_action_links_{$plugin_file}", array($this, 'add_plugin_action_links'));
    }
    
    /**
     * Force login redirect
     */
    public function force_login_redirect() {
        // Check if plugin is enabled
        $plugin_enabled = get_option('flv_enabled', '1');
        if ($plugin_enabled !== '1') {
            return;
        }
        
        // Don't redirect if user is logged in and has bypass permission
        if (is_user_logged_in() && $this->can_bypass_login()) {
            return;
        }
        
        // Don't redirect if current page is excluded
        if ($this->is_page_excluded()) {
            return;
        }
        
        // Don't redirect if post type is excluded
        if ($this->is_post_type_excluded()) {
            return;
        }
        
        // Don't redirect if category/tag is excluded
        if ($this->is_taxonomy_excluded()) {
            return;
        }
        
        // Don't redirect RSS feeds if excluded
        if ($this->is_rss_excluded() && (is_feed() || is_comment_feed())) {
            return;
        }
        
        // Don't redirect REST API if excluded
        if ($this->is_rest_api_excluded() && $this->is_rest_api_request()) {
            return;
        }
        
        // Check bypass key/token
        if ($this->has_bypass_key()) {
            return;
        }
        
        // Check IP whitelist
        if ($this->is_ip_whitelisted()) {
            return;
        }
        
        // Check if maintenance mode is enabled
        if ($this->is_maintenance_mode()) {
            $this->show_maintenance_page();
            return;
        }
        
        // Don't redirect AJAX requests if option is enabled
        if ($this->exclude_ajax() && wp_doing_ajax()) {
            return;
        }
        
        // Don't redirect archive/search pages if excluded
        if ($this->is_archive_excluded() && (is_archive() || is_search() || is_404())) {
            return;
        }
        
        // Don't redirect if already on login page
        if (is_admin() || $this->is_login_page()) {
            return;
        }
        
        // Redirect to login page
        if (!is_user_logged_in()) {
            // Sanitize current URL
            $protocol = is_ssl() ? 'https://' : 'http://';
            $host = isset($_SERVER['HTTP_HOST']) ? sanitize_text_field(wp_unslash($_SERVER['HTTP_HOST'])) : '';
            $request_uri = isset($_SERVER['REQUEST_URI']) ? esc_url_raw(wp_unslash($_SERVER['REQUEST_URI'])) : '';
            $current_url = $protocol . $host . $request_uri;
            
            $redirect_back = get_option('flv_redirect_back', '1');
            $custom_redirect = get_option('flv_custom_redirect_url', '');
            
            // Get custom login page URL
            $custom_login_url = get_option('flv_custom_login_url', '');
            
            if (!empty($custom_login_url)) {
                // Validate custom login URL
                $custom_login_url = esc_url_raw($custom_login_url);
                
                // Use custom login URL
                if ($redirect_back === '1') {
                    $redirect_url = add_query_arg('redirect_to', rawurlencode($current_url), $custom_login_url);
                } elseif (!empty($custom_redirect)) {
                    $redirect_url = add_query_arg('redirect_to', rawurlencode(esc_url_raw($custom_redirect)), $custom_login_url);
                } else {
                    $redirect_url = add_query_arg('redirect_to', rawurlencode(home_url()), $custom_login_url);
                }
            } else {
                // Use default WordPress login
                if ($redirect_back === '1') {
                    $redirect_url = wp_login_url($current_url);
                } elseif (!empty($custom_redirect)) {
                    $redirect_url = wp_login_url(esc_url_raw($custom_redirect));
                } else {
                    $redirect_url = wp_login_url(home_url());
                }
            }
            
            // Allow filtering of redirect URL
            $redirect_url = apply_filters('flv_login_redirect_url', $redirect_url, $current_url);
            
            // Sanitize final redirect URL
            $redirect_url = esc_url_raw($redirect_url);
            
            wp_safe_redirect($redirect_url);
            exit;
        }
    }
    
    /**
     * Check if user can bypass login requirement
     */
    private function can_bypass_login() {
        $bypass_roles = get_option('flv_bypass_roles', array());
        $bypass_users = get_option('flv_bypass_users', array());
        
        // Check user roles
        if (!empty($bypass_roles)) {
            $user = wp_get_current_user();
            if (!empty($user->roles)) {
                foreach ($user->roles as $role) {
                    if (in_array($role, $bypass_roles)) {
                        return true;
                    }
                }
            }
        }
        
        // Check specific users
        if (!empty($bypass_users)) {
            $current_user_id = get_current_user_id();
            if (in_array($current_user_id, array_map('intval', $bypass_users))) {
                return true;
            }
        }
        
        return false;
    }
    
    /**
     * Check if current page is excluded
     */
    private function is_page_excluded() {
        $excluded_pages = get_option('flv_excluded_pages', array());
        
        if (empty($excluded_pages)) {
            return false;
        }
        
        // Check if current page/post ID is excluded
        if (is_singular()) {
            $current_id = get_queried_object_id();
            if (in_array($current_id, array_map('intval', $excluded_pages))) {
                return true;
            }
        }
        
        // Check if current page template is excluded
        $excluded_templates = get_option('flv_excluded_templates', array());
        if (!empty($excluded_templates) && is_page()) {
            $template = get_page_template_slug();
            if (!empty($template) && in_array($template, $excluded_templates)) {
                return true;
            }
        }
        
        return false;
    }
    
    /**
     * Check if current page is login page
     */
    private function is_login_page() {
        return in_array($GLOBALS['pagenow'], array('wp-login.php', 'wp-register.php'));
    }
    
    /**
     * Check if current post type is excluded
     */
    private function is_post_type_excluded() {
        $excluded_post_types = get_option('flv_excluded_post_types', array());
        
        if (empty($excluded_post_types)) {
            return false;
        }
        
        if (is_singular()) {
            $post_type = get_post_type();
            if (in_array($post_type, $excluded_post_types)) {
                return true;
            }
        }
        
        if (is_post_type_archive()) {
            $post_type = get_post_type();
            if (in_array($post_type, $excluded_post_types)) {
                return true;
            }
        }
        
        return false;
    }
    
    /**
     * Check if current taxonomy term is excluded
     */
    private function is_taxonomy_excluded() {
        $excluded_categories = get_option('flv_excluded_categories', array());
        $excluded_tags = get_option('flv_excluded_tags', array());
        
        if (empty($excluded_categories) && empty($excluded_tags)) {
            return false;
        }
        
        if (is_category()) {
            $category_id = get_queried_object_id();
            if (in_array($category_id, array_map('intval', $excluded_categories))) {
                return true;
            }
        }
        
        if (is_tag()) {
            $tag_id = get_queried_object_id();
            if (in_array($tag_id, array_map('intval', $excluded_tags))) {
                return true;
            }
        }
        
        if (is_singular()) {
            // Check if post belongs to excluded category
            $categories = wp_get_post_categories(get_the_ID());
            if (!empty($categories) && !empty($excluded_categories)) {
                foreach ($categories as $cat_id) {
                    if (in_array($cat_id, array_map('intval', $excluded_categories))) {
                        return true;
                    }
                }
            }
            
            // Check if post has excluded tag
            $tags = wp_get_post_tags(get_the_ID(), array('fields' => 'ids'));
            if (!empty($tags) && !empty($excluded_tags)) {
                foreach ($tags as $tag_id) {
                    if (in_array($tag_id, array_map('intval', $excluded_tags))) {
                        return true;
                    }
                }
            }
        }
        
        return false;
    }
    
    /**
     * Check if RSS feeds are excluded
     */
    private function is_rss_excluded() {
        return get_option('flv_exclude_rss', '0') === '1';
    }
    
    /**
     * Check if REST API is excluded
     */
    private function is_rest_api_excluded() {
        return get_option('flv_exclude_rest_api', '0') === '1';
    }
    
    /**
     * Check if current request is REST API
     */
    private function is_rest_api_request() {
        if (defined('REST_REQUEST') && REST_REQUEST) {
            return true;
        }
        
        if (!isset($_SERVER['REQUEST_URI'])) {
            return false;
        }
        
        $rest_prefix = trailingslashit(rest_get_url_prefix());
        $request_uri = sanitize_text_field(wp_unslash($_SERVER['REQUEST_URI']));
        
        return strpos($request_uri, $rest_prefix) !== false;
    }
    
    /**
     * Check if bypass key is present in URL
     */
    private function has_bypass_key() {
        $bypass_key = get_option('flv_bypass_key', '');
        if (empty($bypass_key)) {
            return false;
        }
        
        $key_param = isset($_GET['flv_bypass']) ? sanitize_text_field(wp_unslash($_GET['flv_bypass'])) : '';
        return $key_param === $bypass_key;
    }
    
    /**
     * Check if current IP is whitelisted
     */
    private function is_ip_whitelisted() {
        $whitelisted_ips = get_option('flv_whitelist_ips', '');
        if (empty($whitelisted_ips)) {
            return false;
        }
        
        $current_ip = $this->get_client_ip();
        $ips = array_map('trim', explode("\n", $whitelisted_ips));
        
        foreach ($ips as $ip) {
            if (empty($ip)) {
                continue;
            }
            
            // Support CIDR notation
            if (strpos($ip, '/') !== false) {
                if ($this->ip_in_range($current_ip, $ip)) {
                    return true;
                }
            } else {
                if ($current_ip === $ip) {
                    return true;
                }
            }
        }
        
        return false;
    }
    
    /**
     * Get client IP address
     */
    private function get_client_ip() {
        $ip_keys = array('HTTP_CLIENT_IP', 'HTTP_X_FORWARDED_FOR', 'HTTP_X_FORWARDED', 'HTTP_X_CLUSTER_CLIENT_IP', 'HTTP_FORWARDED_FOR', 'HTTP_FORWARDED', 'REMOTE_ADDR');
        
        foreach ($ip_keys as $key) {
            if (isset($_SERVER[$key]) && !empty($_SERVER[$key])) {
                $ip_value = sanitize_text_field(wp_unslash($_SERVER[$key]));
                foreach (explode(',', $ip_value) as $ip) {
                    $ip = trim($ip);
                    // Validate IP address
                    if (filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_NO_PRIV_RANGE | FILTER_FLAG_NO_RES_RANGE) !== false) {
                        return $ip;
                    }
                }
            }
        }
        
        // Fallback to REMOTE_ADDR
        if (isset($_SERVER['REMOTE_ADDR'])) {
            $remote_addr = sanitize_text_field(wp_unslash($_SERVER['REMOTE_ADDR']));
            if (filter_var($remote_addr, FILTER_VALIDATE_IP) !== false) {
                return $remote_addr;
            }
        }
        
        return '0.0.0.0';
    }
    
    /**
     * Check if IP is in CIDR range
     */
    private function ip_in_range($ip, $range) {
        if (strpos($range, '/') === false) {
            return $ip === $range;
        }
        
        list($subnet, $mask) = explode('/', $range);
        $ip_long = ip2long($ip);
        $subnet_long = ip2long($subnet);
        $mask_long = -1 << (32 - (int)$mask);
        
        return ($ip_long & $mask_long) === ($subnet_long & $mask_long);
    }
    
    /**
     * Check if maintenance mode is enabled
     */
    private function is_maintenance_mode() {
        return get_option('flv_maintenance_mode', '0') === '1';
    }
    
    /**
     * Show maintenance page
     */
    private function show_maintenance_page() {
        $maintenance_message = get_option('flv_maintenance_message', __('We are currently performing scheduled maintenance. Please check back soon.', 'force-login-view'));
        $maintenance_title = get_option('flv_maintenance_title', __('Site Under Maintenance', 'force-login-view'));
        
        status_header(503);
        nocache_headers();
        
        ?>
        <!DOCTYPE html>
        <html <?php language_attributes(); ?>>
        <head>
            <meta charset="<?php bloginfo('charset'); ?>">
            <meta name="viewport" content="width=device-width, initial-scale=1">
            <title><?php echo esc_html($maintenance_title); ?></title>
            <style>
                body {
                    font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Oxygen-Sans, Ubuntu, Cantarell, "Helvetica Neue", sans-serif;
                    background: #f5f5f5;
                    margin: 0;
                    padding: 0;
                    display: flex;
                    align-items: center;
                    justify-content: center;
                    min-height: 100vh;
                }
                .maintenance-container {
                    background: #fff;
                    padding: 48px;
                    border-radius: 8px;
                    box-shadow: 0 2px 8px rgba(0,0,0,0.1);
                    max-width: 600px;
                    text-align: center;
                }
                h1 {
                    color: #202124;
                    font-size: 32px;
                    font-weight: 400;
                    margin: 0 0 16px 0;
                }
                p {
                    color: #5f6368;
                    font-size: 16px;
                    line-height: 1.6;
                    margin: 0;
                }
            </style>
        </head>
        <body>
            <div class="maintenance-container">
                <h1><?php echo esc_html($maintenance_title); ?></h1>
                <p><?php echo esc_html($maintenance_message); ?></p>
            </div>
        </body>
        </html>
        <?php
        exit;
    }
    
    /**
     * Check if AJAX requests should be excluded
     */
    private function exclude_ajax() {
        return get_option('flv_exclude_ajax', '0') === '1';
    }
    
    /**
     * Check if archive/search pages are excluded
     */
    private function is_archive_excluded() {
        return get_option('flv_exclude_archives', '0') === '1';
    }
    
    /**
     * Add admin menu
     */
    public function add_admin_menu() {
        add_options_page(
            __('Force Login View Settings', 'force-login-view'),
            __('Force Login View', 'force-login-view'),
            'manage_options',
            'force-login-view',
            array($this, 'render_settings_page')
        );
    }
    
    /**
     * Add settings link to plugin actions
     */
    public function add_plugin_action_links($links) {
        $settings_link = '<a href="' . admin_url('options-general.php?page=force-login-view') . '">' . __('Settings', 'force-login-view') . '</a>';
        array_unshift($links, $settings_link);
        return $links;
    }
    
    /**
     * Display custom login message
     */
    public function display_login_message($message) {
        $login_message = get_option('flv_login_message', '');
        if (!empty($login_message)) {
            $message .= '<div class="flv-login-message" style="background: #e8f0fe; border-left: 4px solid #4285f4; padding: 12px 16px; margin-bottom: 20px; border-radius: 4px;"><p style="margin: 0; color: #202124;">' . esc_html($login_message) . '</p></div>';
        }
        return $message;
    }
    
    /**
     * Add admin bar notice
     */
    public function add_admin_bar_notice($wp_admin_bar) {
        if (!current_user_can('manage_options')) {
            return;
        }
        
        $enabled = get_option('flv_enabled', '1');
        if ($enabled === '1') {
            $wp_admin_bar->add_node(array(
                'id' => 'flv-active',
                'title' => '<span class="ab-icon dashicons-lock" style="margin-top: 3px;"></span> ' . __('Force Login Active', 'force-login-view'),
                'href' => admin_url('options-general.php?page=force-login-view'),
                'meta' => array(
                    'title' => __('Force Login to View Page is active', 'force-login-view')
                )
            ));
        }
    }
    
    /**
     * Register settings
     */
    public function register_settings() {
        // Register settings with sanitization callbacks for defense in depth
        register_setting('flv_settings', 'flv_enabled', array('sanitize_callback' => array($this, 'sanitize_checkbox')));
        register_setting('flv_settings', 'flv_excluded_pages', array('sanitize_callback' => array($this, 'sanitize_int_array')));
        register_setting('flv_settings', 'flv_excluded_templates', array('sanitize_callback' => array($this, 'sanitize_text_array')));
        register_setting('flv_settings', 'flv_excluded_post_types', array('sanitize_callback' => array($this, 'sanitize_key_array')));
        register_setting('flv_settings', 'flv_excluded_categories', array('sanitize_callback' => array($this, 'sanitize_int_array')));
        register_setting('flv_settings', 'flv_excluded_tags', array('sanitize_callback' => array($this, 'sanitize_int_array')));
        register_setting('flv_settings', 'flv_exclude_rss', array('sanitize_callback' => array($this, 'sanitize_checkbox')));
        register_setting('flv_settings', 'flv_exclude_rest_api', array('sanitize_callback' => array($this, 'sanitize_checkbox')));
        register_setting('flv_settings', 'flv_bypass_roles', array('sanitize_callback' => array($this, 'sanitize_key_array')));
        register_setting('flv_settings', 'flv_bypass_users', array('sanitize_callback' => array($this, 'sanitize_int_array')));
        register_setting('flv_settings', 'flv_redirect_back', array('sanitize_callback' => array($this, 'sanitize_checkbox')));
        register_setting('flv_settings', 'flv_custom_redirect_url', array('sanitize_callback' => 'esc_url_raw'));
        register_setting('flv_settings', 'flv_custom_login_url', array('sanitize_callback' => 'esc_url_raw'));
        register_setting('flv_settings', 'flv_login_message', array('sanitize_callback' => 'sanitize_textarea_field'));
        register_setting('flv_settings', 'flv_bypass_key', array('sanitize_callback' => 'sanitize_text_field'));
        register_setting('flv_settings', 'flv_whitelist_ips', array('sanitize_callback' => 'sanitize_textarea_field'));
        register_setting('flv_settings', 'flv_maintenance_mode', array('sanitize_callback' => array($this, 'sanitize_checkbox')));
        register_setting('flv_settings', 'flv_maintenance_title', array('sanitize_callback' => 'sanitize_text_field'));
        register_setting('flv_settings', 'flv_maintenance_message', array('sanitize_callback' => 'sanitize_textarea_field'));
        register_setting('flv_settings', 'flv_exclude_ajax', array('sanitize_callback' => array($this, 'sanitize_checkbox')));
        register_setting('flv_settings', 'flv_exclude_archives', array('sanitize_callback' => array($this, 'sanitize_checkbox')));
    }
    
    /**
     * Sanitize checkbox value
     */
    public function sanitize_checkbox($value) {
        return ($value === '1' || $value === 1 || $value === true) ? '1' : '0';
    }
    
    /**
     * Sanitize integer array
     */
    public function sanitize_int_array($value) {
        if (!is_array($value)) {
            return array();
        }
        return array_map('absint', $value);
    }
    
    /**
     * Sanitize text array
     */
    public function sanitize_text_array($value) {
        if (!is_array($value)) {
            return array();
        }
        return array_map('sanitize_text_field', $value);
    }
    
    /**
     * Sanitize key array
     */
    public function sanitize_key_array($value) {
        if (!is_array($value)) {
            return array();
        }
        return array_map('sanitize_key', $value);
    }
    
    /**
     * Enqueue admin scripts
     */
    public function enqueue_admin_scripts($hook) {
        if ($hook !== 'settings_page_force-login-view') {
            return;
        }
        
        // Enqueue WordPress dashicons
        wp_enqueue_style('dashicons');
        
        // Enqueue WordPress jQuery (default library per Guideline 13)
        wp_enqueue_script('jquery');
        
        // Enqueue custom admin styles
        wp_add_inline_style('dashicons', $this->get_admin_styles());
        
        // Convert multi-select dropdowns to user-friendly checkbox lists
        wp_add_inline_script('jquery', $this->get_checkbox_selector_script());
        
        // IP whitelist functionality (works with or without Select2)
        wp_add_inline_script('jquery', '
            jQuery(document).ready(function($) {
                // Add current IP to whitelist
                $("#flv-add-current-ip").on("click", function(e) {
                    e.preventDefault();
                    var currentIP = $("#flv-current-ip").data("ip");
                    var textarea = $("#flv_whitelist_ips");
                    var currentValue = textarea.val().trim();
                    var ipLines = currentValue ? currentValue.split("\\n") : [];
                    
                    // Check if IP already exists
                    var ipExists = false;
                    for (var i = 0; i < ipLines.length; i++) {
                        if (ipLines[i].trim() === currentIP) {
                            ipExists = true;
                            break;
                        }
                    }
                    
                    if (!ipExists && currentIP && currentIP !== "0.0.0.0") {
                        // Add IP to textarea
                        if (currentValue) {
                            textarea.val(currentValue + "\\n" + currentIP);
                        } else {
                            textarea.val(currentIP);
                        }
                        
                        // Show success feedback
                        var button = $(this);
                        var originalText = button.text();
                        button.text("' . esc_js(__('Added!', 'force-login-view')) . '").css("background-color", "#34a853").css("color", "#fff");
                        
                        setTimeout(function() {
                            button.text(originalText).css("background-color", "").css("color", "");
                        }, 2000);
                    } else if (ipExists) {
                        // Show already exists feedback
                        var button = $(this);
                        var originalText = button.text();
                        button.text("' . esc_js(__('Already added', 'force-login-view')) . '").css("background-color", "#ff9800").css("color", "#fff");
                        
                        setTimeout(function() {
                            button.text(originalText).css("background-color", "").css("color", "");
                        }, 2000);
                    }
                });
            });
        ');
    }
    
    /**
     * Get checkbox selector JavaScript
     */
    private function get_checkbox_selector_script() {
        return '
        jQuery(document).ready(function($) {
            // Convert all multi-select dropdowns to checkbox lists
            $("select[multiple]").each(function() {
                var $select = $(this);
                var selectId = $select.attr("id");
                var selectName = $select.attr("name");
                
                // Create checkbox container
                var $container = $("<div>").addClass("flv-checkbox-selector").attr("data-select-id", selectId);
                
                // Create search box
                var $searchBox = $("<input>")
                    .attr("type", "text")
                    .addClass("flv-checkbox-search")
                    .attr("placeholder", "' . esc_js(__('Search...', 'force-login-view')) . '");
                
                // Create select all/none buttons
                var $buttonContainer = $("<div>").addClass("flv-checkbox-buttons");
                var $selectAll = $("<button>")
                    .attr("type", "button")
                    .addClass("button button-small flv-select-all")
                    .text("' . esc_js(__('Select All', 'force-login-view')) . '");
                var $deselectAll = $("<button>")
                    .attr("type", "button")
                    .addClass("button button-small flv-deselect-all")
                    .text("' . esc_js(__('Deselect All', 'force-login-view')) . '");
                var $selectedCount = $("<span>").addClass("flv-selected-count");
                
                $buttonContainer.append($selectAll).append($deselectAll).append($selectedCount);
                
                // Create checkbox list container
                var $checkboxList = $("<div>").addClass("flv-checkbox-list");
                
                // Create checkboxes from options
                $select.find("option").each(function() {
                    var $option = $(this);
                    var value = $option.val();
                    var text = $option.text();
                    var isSelected = $option.prop("selected");
                    
                    var $checkboxItem = $("<label>").addClass("flv-checkbox-item");
                    var $checkbox = $("<input>")
                        .attr("type", "checkbox")
                        .attr("value", value)
                        .attr("data-select-id", selectId)
                        .prop("checked", isSelected);
                    
                    var $checkboxText = $("<span>").addClass("flv-checkbox-text").text(text);
                    
                    $checkboxItem.append($checkbox).append($checkboxText);
                    $checkboxList.append($checkboxItem);
                });
                
                // Hide original select
                $select.hide();
                
                // Assemble container
                $container.append($searchBox);
                $container.append($buttonContainer);
                $container.append($checkboxList);
                
                // Insert after select
                $select.after($container);
                
                // Update selected count
                function updateCount() {
                    var count = $container.find("input[type=checkbox]:checked").length;
                    var total = $container.find("input[type=checkbox]").length;
                    $selectedCount.text("(' . esc_js(__('Selected', 'force-login-view')) . ': " + count + " / " + total + ")");
                }
                updateCount();
                
                // Search functionality
                $searchBox.on("keyup", function() {
                    var searchTerm = $(this).val().toLowerCase();
                    $checkboxList.find(".flv-checkbox-item").each(function() {
                        var text = $(this).find(".flv-checkbox-text").text().toLowerCase();
                        if (text.indexOf(searchTerm) !== -1) {
                            $(this).show();
                        } else {
                            $(this).hide();
                        }
                    });
                });
                
                // Select All
                $selectAll.on("click", function() {
                    $checkboxList.find("input[type=checkbox]:visible").prop("checked", true).trigger("change");
                });
                
                // Deselect All
                $deselectAll.on("click", function() {
                    $checkboxList.find("input[type=checkbox]:visible").prop("checked", false).trigger("change");
                });
                
                // Sync checkboxes with hidden select
                $container.on("change", "input[type=checkbox]", function() {
                    var $checkbox = $(this);
                    var value = $checkbox.val();
                    var isChecked = $checkbox.prop("checked");
                    
                    $select.find("option[value=\'" + value + "\']").prop("selected", isChecked);
                    updateCount();
                });
            });
        });
        ';
    }
    
    /**
     * Get admin styles
     */
    private function get_admin_styles() {
        return '
            * {
                box-sizing: border-box;
            }
            
            :root {
                /* Google Colors */
                --google-blue: #4285f4;
                --google-blue-hover: #357ae8;
                --google-blue-light: #e8f0fe;
                --google-success: #34a853;
                --google-text-primary: #202124;
                --google-text-secondary: #5f6368;
                --google-border: #dadce0;
                --google-bg: #ffffff;
                --google-bg-secondary: #f8f9fa;
            }
            
            body {
                font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Oxygen-Sans, Ubuntu, Cantarell, "Helvetica Neue", sans-serif;
            }
            
            /* Fit within WordPress admin wpbody-content */
            #wpbody-content .flv-wrap-material {
                background: #ffffff;
                margin: 0;
                padding: 20px 0;
                box-sizing: border-box;
                overflow-x: hidden;
                width: 100%;
            }
            
            .flv-settings-wrapper {
                width: 100%;
                max-width: 100%;
                margin: 0;
                padding: 0 20px;
                box-sizing: border-box;
                overflow-x: hidden;
            }
            
            .flv-columns {
                display: grid;
                grid-template-columns: repeat(2, minmax(0, 1fr));
                gap: 24px;
                margin-top: 0;
                width: 100%;
                box-sizing: border-box;
                align-items: start;
            }
            
            .flv-column {
                display: flex;
                flex-direction: column;
                min-width: 0;
                width: 100%;
                max-width: 100%;
                box-sizing: border-box;
            }
            
            .flv-column:first-child {
                grid-column: 1;
            }
            
            .flv-column:last-child {
                grid-column: 2;
            }
            
            .flv-column .flv-card {
                margin-bottom: 24px;
                width: 100%;
                box-sizing: border-box;
                overflow-x: hidden;
            }
            
            .flv-column .flv-card:last-child {
                margin-bottom: 0;
            }
            
            .flv-full-width {
                grid-column: 1 / -1;
                margin-bottom: 24px;
                width: 100%;
                box-sizing: border-box;
                overflow-x: hidden;
            }
            
            .flv-full-width:last-child {
                margin-bottom: 0;
            }
            
            .flv-header {
                background: #ffffff;
                padding: 0 0 32px 0;
                margin-bottom: 32px;
                border-bottom: 1px solid var(--google-border);
                width: 100%;
                box-sizing: border-box;
            }
            
            .flv-header h1 {
                margin: 0 0 8px 0;
                font-size: 32px;
                font-weight: 400;
                line-height: 1.2;
                color: var(--google-text-primary);
                display: flex;
                align-items: center;
                letter-spacing: -0.5px;
                gap: 12px;
            }
            
            .flv-absoluto-link {
                font-size: 14px;
                font-weight: 600;
                color: var(--google-text-secondary);
                text-decoration: none;
                text-transform: lowercase;
                padding: 4px 8px;
                border-radius: 4px;
                transition: color 0.2s ease, background-color 0.2s ease;
                margin-left: auto;
            }
            
            .flv-absoluto-link:hover {
                color: var(--google-blue);
                background-color: var(--google-blue-light);
            }
            
            .flv-header p {
                margin: 0;
                color: var(--google-text-secondary);
                font-size: 14px;
                line-height: 1.5;
                font-weight: 400;
            }
            
            .flv-card {
                background: var(--google-bg);
                border: 1px solid var(--google-border);
                margin-bottom: 24px;
                border-radius: 8px;
                overflow: hidden;
                transition: box-shadow 0.2s ease;
                width: 100%;
                box-sizing: border-box;
            }
            
            .flv-card:hover {
                box-shadow: 0 1px 2px 0 rgba(60,64,67,.3), 0 1px 3px 1px rgba(60,64,67,.15);
            }
            
            .flv-card-header {
                padding: 20px 24px;
                border-bottom: 1px solid var(--google-border);
                background: var(--google-bg);
                width: 100%;
                box-sizing: border-box;
            }
            
            .flv-card-header h2 {
                margin: 0;
                font-size: 16px;
                font-weight: 500;
                line-height: 1.5;
                color: var(--google-text-primary);
                display: flex;
                align-items: center;
                letter-spacing: 0;
                word-wrap: break-word;
                overflow-wrap: break-word;
            }
            
            .flv-card-body {
                padding: 24px;
                width: 100%;
                box-sizing: border-box;
            }
            
            .flv-form-group {
                margin-bottom: 32px;
                width: 100%;
                box-sizing: border-box;
            }
            
            .flv-form-group:last-child {
                margin-bottom: 0;
            }
            
            .flv-form-group label {
                display: block;
                font-weight: 500;
                margin-bottom: 8px;
                color: var(--google-text-primary);
                font-size: 14px;
                letter-spacing: 0;
                word-wrap: break-word;
                overflow-wrap: break-word;
            }
            
            .flv-form-group .description {
                margin-top: 8px;
                margin-bottom: 0;
                color: var(--google-text-secondary);
                font-size: 13px;
                line-height: 1.5;
                font-weight: 400;
                word-wrap: break-word;
                overflow-wrap: break-word;
            }
            
            .flv-form-group select,
            .flv-form-group input[type="text"],
            .flv-form-group input[type="url"],
            .flv-form-group textarea {
                width: 100%;
                max-width: 100%;
                box-sizing: border-box;
            }
            
            .flv-form-group select,
            .flv-form-group input[type="text"],
            .flv-form-group input[type="url"] {
                height: 32px;
                min-height: 32px;
                padding: 4px 8px;
                font-size: 14px;
                line-height: 1.5;
            }
            
            .flv-submit-section {
                background: var(--google-bg);
                border: 1px solid var(--google-border);
                padding: 20px 24px;
                margin-top: 32px;
                border-radius: 8px;
                display: flex;
                align-items: center;
                justify-content: space-between;
                width: 100%;
                box-sizing: border-box;
                flex-wrap: wrap;
            }
            
            .flv-submit-section .description {
                margin: 0;
                color: var(--google-text-secondary);
                font-size: 13px;
                font-weight: 400;
                word-wrap: break-word;
                overflow-wrap: break-word;
                flex: 1;
                min-width: 0;
            }
            
            .flv-submit-section .button-primary {
                background: var(--google-blue);
                border: none;
                border-radius: 4px;
                padding: 10px 24px;
                font-size: 14px;
                font-weight: 500;
                transition: background-color 0.2s ease, box-shadow 0.2s ease;
                color: #ffffff;
                min-width: 88px;
                box-shadow: none;
                text-transform: none;
                letter-spacing: 0;
            }
            
            .flv-submit-section .button-primary:hover {
                background: var(--google-blue-hover);
                box-shadow: 0 1px 2px 0 rgba(60,64,67,.3), 0 1px 3px 1px rgba(60,64,67,.15);
            }
            
            .flv-submit-section .button-primary:active {
                box-shadow: 0 1px 2px 0 rgba(60,64,67,.3), 0 2px 6px 2px rgba(60,64,67,.15);
            }
            
            /* Add IP Button */
            #flv-add-current-ip {
                vertical-align: middle;
                height: auto;
                padding: 4px 12px;
                font-size: 12px;
                line-height: 1.5;
                transition: background-color 0.2s ease, color 0.2s ease;
            }
            
            #flv-add-current-ip:hover {
                background-color: var(--google-blue);
                color: #fff;
                border-color: var(--google-blue);
            }
            
            /* Powered by Absoluto Designs */
            .flv-powered-by {
                margin-top: 32px;
                padding-top: 24px;
                border-top: 1px solid var(--google-border);
                text-align: center;
            }
            
            .flv-powered-by p {
                margin: 0;
                font-size: 13px;
                color: var(--google-text-secondary);
                font-weight: 400;
            }
            
            .flv-powered-by a {
                color: var(--google-blue);
                text-decoration: none;
                font-weight: 500;
                transition: color 0.2s ease;
            }
            
            .flv-powered-by a:hover {
                color: var(--google-blue-hover);
                text-decoration: underline;
            }
            
            /* Checkbox Selector Styling - User-friendly multi-select */
            .flv-checkbox-selector {
                margin-top: 8px;
                border: 1px solid var(--google-border);
                border-radius: 4px;
                background: var(--google-bg);
                padding: 12px;
            }
            
            .flv-checkbox-search {
                width: 100%;
                padding: 8px 12px;
                border: 1px solid var(--google-border);
                border-radius: 4px;
                font-size: 14px;
                margin-bottom: 12px;
                box-sizing: border-box;
            }
            
            .flv-checkbox-search:focus {
                outline: none;
                border-color: var(--google-blue);
                box-shadow: 0 0 0 2px rgba(66, 133, 244, 0.1);
            }
            
            .flv-checkbox-buttons {
                display: flex;
                align-items: center;
                gap: 8px;
                margin-bottom: 12px;
                padding-bottom: 12px;
                border-bottom: 1px solid var(--google-border);
            }
            
            .flv-selected-count {
                margin-left: auto;
                font-size: 13px;
                color: var(--google-text-secondary);
                font-weight: 500;
            }
            
            .flv-checkbox-list {
                max-height: 300px;
                overflow-y: auto;
                overflow-x: hidden;
                padding: 4px 0;
            }
            
            .flv-checkbox-list::-webkit-scrollbar {
                width: 8px;
            }
            
            .flv-checkbox-list::-webkit-scrollbar-track {
                background: var(--google-bg-secondary);
                border-radius: 4px;
            }
            
            .flv-checkbox-list::-webkit-scrollbar-thumb {
                background: var(--google-border);
                border-radius: 4px;
            }
            
            .flv-checkbox-list::-webkit-scrollbar-thumb:hover {
                background: var(--google-text-secondary);
            }
            
            .flv-checkbox-item {
                display: flex;
                align-items: center;
                padding: 8px 12px;
                margin: 2px 0;
                border-radius: 4px;
                cursor: pointer;
                transition: background-color 0.15s ease;
                user-select: none;
            }
            
            .flv-checkbox-item:hover {
                background-color: var(--google-bg-secondary);
            }
            
            .flv-checkbox-item input[type="checkbox"] {
                margin-right: 10px;
                width: 18px;
                height: 18px;
                cursor: pointer;
                accent-color: var(--google-blue);
            }
            
            .flv-checkbox-item input[type="checkbox"]:checked {
                accent-color: var(--google-blue);
            }
            
            .flv-checkbox-text {
                font-size: 14px;
                color: var(--google-text-primary);
                flex: 1;
                line-height: 1.5;
            }
            
            .flv-checkbox-item input[type="checkbox"]:checked + .flv-checkbox-text {
                color: var(--google-blue);
                font-weight: 500;
            }
            
            /* Legacy Select2 Styling (kept for backward compatibility if Select2 is used) */
            .select2-container {
                width: 100% !important;
                max-width: 100% !important;
                box-sizing: border-box !important;
            }
            
            .select2-container--default .select2-selection--multiple {
                border: 1px solid var(--google-border);
                border-radius: 4px;
                min-height: 32px;
                height: auto;
                padding: 2px 6px;
                transition: all 0.2s cubic-bezier(0.4, 0, 0.2, 1);
                background: var(--google-bg);
                width: 100%;
                max-width: 100%;
                box-sizing: border-box;
                line-height: 1.5;
            }
            
            .select2-container--default.select2-container--focus .select2-selection--multiple {
                border-color: var(--google-blue);
                box-shadow: 0 0 0 2px rgba(66, 133, 244, 0.1), 0 0 0 1px var(--google-blue);
                outline: none;
            }
            
            .select2-container--default .select2-selection--multiple .select2-selection__rendered {
                padding: 0;
                display: flex;
                flex-wrap: wrap;
                gap: 4px;
            }
            
            .select2-container--default .select2-selection--multiple .select2-selection__choice {
                background: linear-gradient(135deg, #e8f0fe 0%, #d2e3fc 100%);
                border: 1px solid rgba(66, 133, 244, 0.2);
                color: var(--google-blue);
                padding: 3px 10px 3px 24px;
                border-radius: 16px;
                margin-top: 1px;
                margin-bottom: 1px;
                font-size: 12px;
                font-weight: 500;
                transition: all 0.2s cubic-bezier(0.4, 0, 0.2, 1);
                position: relative;
                display: inline-flex;
                align-items: center;
                box-shadow: 0 1px 2px rgba(66, 133, 244, 0.1);
                line-height: 1.3;
                max-width: 100%;
                word-break: break-word;
            }
            
            .select2-container--default .select2-selection--multiple .select2-selection__choice:hover {
                background: linear-gradient(135deg, #d2e3fc 0%, #b8d4f5 100%);
                border-color: rgba(66, 133, 244, 0.4);
                box-shadow: 0 2px 4px rgba(66, 133, 244, 0.15);
                transform: translateY(-1px);
            }
            
            .select2-container--default .select2-selection--multiple .select2-selection__choice__display {
                flex: 1;
                min-width: 0;
                overflow: hidden;
                text-overflow: ellipsis;
                padding-left: 0;
                margin-left: 0;
            }
            
            .select2-container--default .select2-selection--multiple .select2-selection__choice__remove {
                color: var(--google-blue);
                font-weight: 700;
                transition: all 0.2s cubic-bezier(0.4, 0, 0.2, 1);
                position: absolute;
                top: 50%;
                left: 3px;
                transform: translateY(-50%);
                margin: 0;
                font-size: 14px;
                line-height: 1;
                cursor: pointer;
                width: 16px;
                height: 16px;
                display: flex;
                align-items: center;
                justify-content: center;
                border-radius: 50%;
                background: rgba(255, 255, 255, 0.8);
                opacity: 0.7;
            }
            
            .select2-container--default .select2-selection--multiple .select2-selection__choice:hover .select2-selection__choice__remove {
                opacity: 1;
                background: rgba(255, 255, 255, 1);
                color: #ea4335;
            }
            
            .select2-container--default .select2-selection--multiple .select2-selection__choice__remove:hover {
                background: #ea4335;
                color: #fff;
                transform: translateY(-50%) scale(1.1);
                box-shadow: 0 2px 4px rgba(234, 67, 53, 0.3);
            }
            
            .select2-container--default .select2-selection--multiple .select2-selection__choice__remove:active {
                transform: translateY(-50%) scale(0.95);
            }
            
            .select2-container--default .select2-search--inline .select2-search__field {
                margin-top: 1px;
                margin-bottom: 1px;
                padding: 0;
                font-size: 13px;
                font-family: "Inter", sans-serif;
                line-height: 1.4;
                height: auto;
                min-height: 20px;
            }
            
            .select2-container--default .select2-selection--multiple .select2-selection__choice + .select2-search--inline {
                margin-left: 4px;
            }
            
            .select2-dropdown {
                border: 1px solid var(--google-border);
                border-radius: 4px;
                box-shadow: 0 2px 8px rgba(60,64,67,.3);
                margin-top: 4px;
                overflow: hidden;
            }
            
            .select2-results__option {
                padding: 10px 16px;
                font-size: 14px;
                transition: background-color 0.15s ease;
                font-family: "Inter", sans-serif;
            }
            
            .select2-results__option--highlighted {
                background: var(--google-blue-light);
                color: var(--google-text-primary);
            }
            
            /* Success Notice Google Styling */
            .notice.notice-success {
                border-left: 4px solid var(--google-success);
                border-radius: 4px;
                padding: 12px 16px;
                margin-bottom: 24px;
                background: var(--google-bg);
                border-left-width: 4px;
                box-shadow: none;
            }
            
            .notice.notice-success p {
                margin: 0;
                font-size: 14px;
                color: var(--google-text-primary);
                font-weight: 400;
                display: flex;
                align-items: center;
            }
            
            .notice.notice-success p::before {
                content: "✓";
                color: var(--google-success);
                margin-right: 12px;
                font-size: 18px;
                font-weight: 600;
            }
            
            .notice.notice-success strong {
                color: var(--google-text-primary);
                font-weight: 500;
            }
            
            /* Ensure compatibility with WordPress admin wpbody-content */
            #wpbody-content .wrap.flv-wrap-material {
                position: relative;
                overflow-x: hidden;
                overflow-y: visible;
                margin: 0;
            }
            
            /* Prevent horizontal overflow */
            .flv-form-group code {
                word-break: break-all;
                overflow-wrap: break-word;
                max-width: 100%;
                display: inline-block;
            }
            
            .flv-form-group p {
                word-wrap: break-word;
                overflow-wrap: break-word;
            }
            
            /* Responsive Design */
            @media screen and (max-width: 1200px) {
                .flv-columns {
                    grid-template-columns: 1fr;
                }
                
                .flv-full-width {
                    grid-column: 1;
                }
            }
            
            @media screen and (max-width: 782px) {
                #wpbody-content .flv-wrap-material {
                    padding: 20px 0;
                }
                
                .flv-settings-wrapper {
                    padding: 0 10px;
                }
                
                .flv-header {
                    padding-bottom: 24px;
                }
                
                .flv-header h1 {
                    font-size: 24px;
                }
                
                .flv-card-header,
                .flv-card-body {
                    padding: 16px;
                }
                
                .flv-submit-section {
                    flex-direction: column;
                    align-items: stretch;
                    padding: 16px;
                }
                
                .flv-submit-section .button-primary {
                    width: 100%;
                    margin-top: 12px;
                }
                
                .flv-submit-section .description {
                    text-align: left;
                    margin-bottom: 0;
                    flex: none;
                }
                
                .flv-header h1 {
                    flex-wrap: wrap;
                }
                
                .flv-absoluto-link {
                    margin-left: 0;
                    margin-top: 8px;
                }
                
                .flv-powered-by {
                    margin-top: 24px;
                    padding-top: 20px;
                }
            }
        ';
    }
    
    /**
     * Render settings page
     */
    public function render_settings_page() {
        if (!current_user_can('manage_options')) {
            return;
        }
        
        // Handle form submission
        if (isset($_POST['flv_save_settings']) && check_admin_referer('flv_settings_nonce')) {
            // Verify user capability
            if (!current_user_can('manage_options')) {
                wp_die(__('You do not have sufficient permissions to access this page.', 'force-login-view'));
            }
            
            // Save plugin enabled status
            $enabled = isset($_POST['flv_enabled']) && '1' === sanitize_text_field(wp_unslash($_POST['flv_enabled'])) ? '1' : '0';
            update_option('flv_enabled', $enabled);
            
            // Save excluded pages - sanitize as integers
            $excluded_pages = array();
            if (isset($_POST['flv_excluded_pages']) && is_array($_POST['flv_excluded_pages'])) {
                $excluded_pages = array_map('absint', array_map('wp_unslash', $_POST['flv_excluded_pages']));
            }
            update_option('flv_excluded_pages', $excluded_pages);
            
            // Save excluded templates - sanitize text fields
            $excluded_templates = array();
            if (isset($_POST['flv_excluded_templates']) && is_array($_POST['flv_excluded_templates'])) {
                $excluded_templates = array_map('sanitize_text_field', array_map('wp_unslash', $_POST['flv_excluded_templates']));
            }
            update_option('flv_excluded_templates', $excluded_templates);
            
            // Save excluded post types - sanitize text fields
            $excluded_post_types = array();
            if (isset($_POST['flv_excluded_post_types']) && is_array($_POST['flv_excluded_post_types'])) {
                $excluded_post_types = array_map('sanitize_key', array_map('wp_unslash', $_POST['flv_excluded_post_types']));
            }
            update_option('flv_excluded_post_types', $excluded_post_types);
            
            // Save excluded categories - sanitize as integers
            $excluded_categories = array();
            if (isset($_POST['flv_excluded_categories']) && is_array($_POST['flv_excluded_categories'])) {
                $excluded_categories = array_map('absint', array_map('wp_unslash', $_POST['flv_excluded_categories']));
            }
            update_option('flv_excluded_categories', $excluded_categories);
            
            // Save excluded tags - sanitize as integers
            $excluded_tags = array();
            if (isset($_POST['flv_excluded_tags']) && is_array($_POST['flv_excluded_tags'])) {
                $excluded_tags = array_map('absint', array_map('wp_unslash', $_POST['flv_excluded_tags']));
            }
            update_option('flv_excluded_tags', $excluded_tags);
            
            // Save RSS exclusion
            $exclude_rss = isset($_POST['flv_exclude_rss']) && '1' === sanitize_text_field(wp_unslash($_POST['flv_exclude_rss'])) ? '1' : '0';
            update_option('flv_exclude_rss', $exclude_rss);
            
            // Save REST API exclusion
            $exclude_rest_api = isset($_POST['flv_exclude_rest_api']) && '1' === sanitize_text_field(wp_unslash($_POST['flv_exclude_rest_api'])) ? '1' : '0';
            update_option('flv_exclude_rest_api', $exclude_rest_api);
            
            // Save bypass roles - sanitize keys
            $bypass_roles = array();
            if (isset($_POST['flv_bypass_roles']) && is_array($_POST['flv_bypass_roles'])) {
                $bypass_roles = array_map('sanitize_key', array_map('wp_unslash', $_POST['flv_bypass_roles']));
            }
            update_option('flv_bypass_roles', $bypass_roles);
            
            // Save bypass users - sanitize as integers
            $bypass_users = array();
            if (isset($_POST['flv_bypass_users']) && is_array($_POST['flv_bypass_users'])) {
                $bypass_users = array_map('absint', array_map('wp_unslash', $_POST['flv_bypass_users']));
            }
            update_option('flv_bypass_users', $bypass_users);
            
            // Save redirect options
            $redirect_back = isset($_POST['flv_redirect_back']) && '1' === sanitize_text_field(wp_unslash($_POST['flv_redirect_back'])) ? '1' : '0';
            update_option('flv_redirect_back', $redirect_back);
            
            $custom_redirect = isset($_POST['flv_custom_redirect_url']) ? esc_url_raw(wp_unslash($_POST['flv_custom_redirect_url'])) : '';
            update_option('flv_custom_redirect_url', $custom_redirect);
            
            // Save custom login URL
            $custom_login_url = isset($_POST['flv_custom_login_url']) ? esc_url_raw(wp_unslash($_POST['flv_custom_login_url'])) : '';
            update_option('flv_custom_login_url', $custom_login_url);
            
            // Save login message
            $login_message = isset($_POST['flv_login_message']) ? sanitize_textarea_field(wp_unslash($_POST['flv_login_message'])) : '';
            update_option('flv_login_message', $login_message);
            
            // Save bypass key - sanitize text field
            $bypass_key = isset($_POST['flv_bypass_key']) ? sanitize_text_field(wp_unslash($_POST['flv_bypass_key'])) : '';
            update_option('flv_bypass_key', $bypass_key);
            
            // Save IP whitelist - sanitize textarea
            $whitelist_ips = isset($_POST['flv_whitelist_ips']) ? sanitize_textarea_field(wp_unslash($_POST['flv_whitelist_ips'])) : '';
            update_option('flv_whitelist_ips', $whitelist_ips);
            
            // Save maintenance mode
            $maintenance_mode = isset($_POST['flv_maintenance_mode']) && '1' === sanitize_text_field(wp_unslash($_POST['flv_maintenance_mode'])) ? '1' : '0';
            update_option('flv_maintenance_mode', $maintenance_mode);
            
            $maintenance_title = isset($_POST['flv_maintenance_title']) ? sanitize_text_field(wp_unslash($_POST['flv_maintenance_title'])) : '';
            update_option('flv_maintenance_title', $maintenance_title);
            
            $maintenance_message = isset($_POST['flv_maintenance_message']) ? sanitize_textarea_field(wp_unslash($_POST['flv_maintenance_message'])) : '';
            update_option('flv_maintenance_message', $maintenance_message);
            
            // Save AJAX exclusion
            $exclude_ajax = isset($_POST['flv_exclude_ajax']) && '1' === sanitize_text_field(wp_unslash($_POST['flv_exclude_ajax'])) ? '1' : '0';
            update_option('flv_exclude_ajax', $exclude_ajax);
            
            // Save archive exclusion
            $exclude_archives = isset($_POST['flv_exclude_archives']) && '1' === sanitize_text_field(wp_unslash($_POST['flv_exclude_archives'])) ? '1' : '0';
            update_option('flv_exclude_archives', $exclude_archives);
            
            // Add settings saved notice
            add_settings_error(
                'flv_settings',
                'flv_settings_saved',
                __('Settings saved successfully.', 'force-login-view'),
                'updated'
            );
        }
        
        // Display settings errors
        settings_errors('flv_settings');
        
        // Get current settings
        $enabled = get_option('flv_enabled', '1');
        $excluded_pages = get_option('flv_excluded_pages', array());
        $excluded_templates = get_option('flv_excluded_templates', array());
        $excluded_post_types = get_option('flv_excluded_post_types', array());
        $excluded_categories = get_option('flv_excluded_categories', array());
        $excluded_tags = get_option('flv_excluded_tags', array());
        $exclude_rss = get_option('flv_exclude_rss', '0');
        $exclude_rest_api = get_option('flv_exclude_rest_api', '0');
        $bypass_roles = get_option('flv_bypass_roles', array());
        $bypass_users = get_option('flv_bypass_users', array());
        $redirect_back = get_option('flv_redirect_back', '1');
        $custom_redirect = get_option('flv_custom_redirect_url', '');
        $custom_login_url = get_option('flv_custom_login_url', '');
        $login_message = get_option('flv_login_message', '');
        $bypass_key = get_option('flv_bypass_key', '');
        $whitelist_ips = get_option('flv_whitelist_ips', '');
        $maintenance_mode = get_option('flv_maintenance_mode', '0');
        $maintenance_title = get_option('flv_maintenance_title', __('Site Under Maintenance', 'force-login-view'));
        $maintenance_message = get_option('flv_maintenance_message', __('We are currently performing scheduled maintenance. Please check back soon.', 'force-login-view'));
        $exclude_ajax = get_option('flv_exclude_ajax', '0');
        $exclude_archives = get_option('flv_exclude_archives', '0');
        
        // Get all pages for dropdown
        $all_pages = get_pages(array('sort_column' => 'post_title'));
        
        // Get all users for dropdown
        $all_users = get_users(array('orderby' => 'display_name'));
        
        // Get all user roles
        $all_roles = wp_roles()->get_names();
        
        // Get all page templates
        $all_templates = wp_get_theme()->get_page_templates();
        
        // Get all post types
        $post_types = get_post_types(array('public' => true), 'objects');
        
        // Get all categories
        $categories = get_categories(array('hide_empty' => false));
        
        // Get all tags
        $tags = get_tags(array('hide_empty' => false));
        
        // Get current IP for display
        $ip_keys = array('HTTP_CLIENT_IP', 'HTTP_X_FORWARDED_FOR', 'HTTP_X_FORWARDED', 'HTTP_X_CLUSTER_CLIENT_IP', 'HTTP_FORWARDED_FOR', 'HTTP_FORWARDED', 'REMOTE_ADDR');
        $current_ip_display = '0.0.0.0';
        foreach ($ip_keys as $key) {
            if (array_key_exists($key, $_SERVER) === true) {
                $server_value = sanitize_text_field(wp_unslash($_SERVER[$key]));
                foreach (explode(',', $server_value) as $ip) {
                    $ip = trim($ip);
                    if (filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_NO_PRIV_RANGE | FILTER_FLAG_NO_RES_RANGE) !== false) {
                        $current_ip_display = sanitize_text_field($ip);
                        break 2;
                    }
                }
            }
        }
        if ($current_ip_display === '0.0.0.0') {
            $current_ip_display = isset($_SERVER['REMOTE_ADDR']) ? sanitize_text_field(wp_unslash($_SERVER['REMOTE_ADDR'])) : '0.0.0.0';
        }
        ?>
        <div class="wrap flv-wrap-material">
            <div class="flv-settings-wrapper">
                <div class="flv-header">
                    <h1>
                        <?php echo esc_html(get_admin_page_title()); ?>
                        <a href="http://absolutodesigns.com/plugins" target="_blank" rel="noopener noreferrer" class="flv-absoluto-link">absoluto designs</a>
                    </h1>
                    <p><?php _e('Configure which pages require login and which users can bypass the requirement.', 'force-login-view'); ?></p>
                </div>
                
                <form method="post" action="">
                    <?php wp_nonce_field('flv_settings_nonce'); ?>
                    
                    <!-- General Settings Section - Full Width -->
                    <div class="flv-card flv-full-width">
                        <div class="flv-card-header" style="display: flex; justify-content: space-between; align-items: center;">
                            <h2 style="margin: 0;"><?php _e('General Settings', 'force-login-view'); ?></h2>
                            <?php submit_button(__('Save Changes', 'force-login-view'), 'primary', 'flv_save_settings', false); ?>
                        </div>
                        <div class="flv-card-body">
                            <div class="flv-form-group">
                                <label>
                                    <input type="checkbox" name="flv_enabled" value="1" <?php checked($enabled, '1'); ?>>
                                    <?php _e('Enable Force Login', 'force-login-view'); ?>
                                </label>
                                <p class="description">
                                    <?php _e('Uncheck to temporarily disable the login requirement without deactivating the plugin.', 'force-login-view'); ?>
                                </p>
                            </div>
                        </div>
                    </div>
                    
                    <!-- Two Column Layout -->
                    <div class="flv-columns">
                        <!-- Left Column: Content Exclusions -->
                        <div class="flv-column">
                            <!-- Excluded Pages Section -->
                            <div class="flv-card">
                        <div class="flv-card-header" style="display: flex; justify-content: space-between; align-items: center;">
                            <h2 style="margin: 0;"><?php _e('Excluded Pages', 'force-login-view'); ?></h2>
                            <?php submit_button(__('Save Changes', 'force-login-view'), 'primary', 'flv_save_settings', false); ?>
                        </div>
                        <div class="flv-card-body">
                            <div class="flv-form-group">
                                <label for="flv_excluded_pages"><?php _e('Pages Accessible Without Login', 'force-login-view'); ?></label>
                                <select id="flv_excluded_pages" name="flv_excluded_pages[]" multiple="multiple">
                                    <?php if (!empty($all_pages)) : ?>
                                        <?php foreach ($all_pages as $page) : ?>
                                            <option value="<?php echo esc_attr($page->ID); ?>" <?php selected(in_array($page->ID, $excluded_pages)); ?>>
                                                <?php echo esc_html($page->post_title); ?> (ID: <?php echo esc_html($page->ID); ?>)
                                            </option>
                                        <?php endforeach; ?>
                                    <?php else : ?>
                                        <option disabled><?php _e('No pages found.', 'force-login-view'); ?></option>
                                    <?php endif; ?>
                                </select>
                                <p class="description">
                                    <?php _e('Select pages that should be publicly accessible without requiring login. Leave empty to require login for all pages.', 'force-login-view'); ?>
                                </p>
                            </div>
                        </div>
                    </div>
                    
                    <!-- Excluded Templates Section -->
                    <?php if (!empty($all_templates)) : ?>
                    <div class="flv-card">
                        <div class="flv-card-header" style="display: flex; justify-content: space-between; align-items: center;">
                            <h2 style="margin: 0;"><?php _e('Excluded Page Templates', 'force-login-view'); ?></h2>
                            <?php submit_button(__('Save Changes', 'force-login-view'), 'primary', 'flv_save_settings', false); ?>
                        </div>
                        <div class="flv-card-body">
                            <div class="flv-form-group">
                                <label for="flv_excluded_templates"><?php _e('Page Templates Accessible Without Login', 'force-login-view'); ?></label>
                                <select id="flv_excluded_templates" name="flv_excluded_templates[]" multiple="multiple">
                                    <?php foreach ($all_templates as $template_name => $template_filename) : ?>
                                        <option value="<?php echo esc_attr($template_filename); ?>" <?php selected(in_array($template_filename, $excluded_templates)); ?>>
                                            <?php echo esc_html($template_name); ?>
                                        </option>
                                    <?php endforeach; ?>
                                </select>
                                <p class="description">
                                    <?php _e('Select page templates that should be publicly accessible. All pages using these templates will be accessible without login.', 'force-login-view'); ?>
                                </p>
                            </div>
                        </div>
                    </div>
                    <?php endif; ?>
                    
                    <!-- Excluded Post Types Section -->
                    <div class="flv-card">
                        <div class="flv-card-header" style="display: flex; justify-content: space-between; align-items: center;">
                            <h2 style="margin: 0;"><?php _e('Excluded Post Types', 'force-login-view'); ?></h2>
                            <?php submit_button(__('Save Changes', 'force-login-view'), 'primary', 'flv_save_settings', false); ?>
                        </div>
                        <div class="flv-card-body">
                            <div class="flv-form-group">
                                <label for="flv_excluded_post_types"><?php _e('Post Types Accessible Without Login', 'force-login-view'); ?></label>
                                <select id="flv_excluded_post_types" name="flv_excluded_post_types[]" multiple="multiple">
                                    <?php foreach ($post_types as $post_type) : ?>
                                        <option value="<?php echo esc_attr($post_type->name); ?>" <?php selected(in_array($post_type->name, $excluded_post_types)); ?>>
                                            <?php echo esc_html($post_type->label); ?> (<?php echo esc_html($post_type->name); ?>)
                                        </option>
                                    <?php endforeach; ?>
                                </select>
                                <p class="description">
                                    <?php _e('Select post types that should be publicly accessible. All posts of selected types will be accessible without login.', 'force-login-view'); ?>
                                </p>
                            </div>
                        </div>
                    </div>
                    
                    <!-- Excluded Categories Section -->
                    <?php if (!empty($categories)) : ?>
                    <div class="flv-card">
                        <div class="flv-card-header" style="display: flex; justify-content: space-between; align-items: center;">
                            <h2 style="margin: 0;"><?php _e('Excluded Categories', 'force-login-view'); ?></h2>
                            <?php submit_button(__('Save Changes', 'force-login-view'), 'primary', 'flv_save_settings', false); ?>
                        </div>
                        <div class="flv-card-body">
                            <div class="flv-form-group">
                                <label for="flv_excluded_categories"><?php _e('Categories Accessible Without Login', 'force-login-view'); ?></label>
                                <select id="flv_excluded_categories" name="flv_excluded_categories[]" multiple="multiple">
                                    <?php foreach ($categories as $category) : ?>
                                        <option value="<?php echo esc_attr($category->term_id); ?>" <?php selected(in_array($category->term_id, $excluded_categories)); ?>>
                                            <?php echo esc_html($category->name); ?> (<?php echo esc_html($category->slug); ?>)
                                        </option>
                                    <?php endforeach; ?>
                                </select>
                                <p class="description">
                                    <?php _e('Select categories that should be publicly accessible. Posts in these categories will be accessible without login.', 'force-login-view'); ?>
                                </p>
                            </div>
                        </div>
                    </div>
                    <?php endif; ?>
                    
                    <!-- Excluded Tags Section -->
                    <?php if (!empty($tags)) : ?>
                    <div class="flv-card">
                        <div class="flv-card-header" style="display: flex; justify-content: space-between; align-items: center;">
                            <h2 style="margin: 0;"><?php _e('Excluded Tags', 'force-login-view'); ?></h2>
                            <?php submit_button(__('Save Changes', 'force-login-view'), 'primary', 'flv_save_settings', false); ?>
                        </div>
                        <div class="flv-card-body">
                            <div class="flv-form-group">
                                <label for="flv_excluded_tags"><?php _e('Tags Accessible Without Login', 'force-login-view'); ?></label>
                                <select id="flv_excluded_tags" name="flv_excluded_tags[]" multiple="multiple">
                                    <?php foreach ($tags as $tag) : ?>
                                        <option value="<?php echo esc_attr($tag->term_id); ?>" <?php selected(in_array($tag->term_id, $excluded_tags)); ?>>
                                            <?php echo esc_html($tag->name); ?> (<?php echo esc_html($tag->slug); ?>)
                                        </option>
                                    <?php endforeach; ?>
                                </select>
                                <p class="description">
                                    <?php _e('Select tags that should be publicly accessible. Posts with these tags will be accessible without login.', 'force-login-view'); ?>
                                </p>
                            </div>
                        </div>
                    </div>
                    <?php endif; ?>
                    
                    <!-- RSS & API Exclusion Section -->
                    <div class="flv-card">
                        <div class="flv-card-header" style="display: flex; justify-content: space-between; align-items: center;">
                            <h2 style="margin: 0;"><?php _e('RSS & API Settings', 'force-login-view'); ?></h2>
                            <?php submit_button(__('Save Changes', 'force-login-view'), 'primary', 'flv_save_settings', false); ?>
                        </div>
                        <div class="flv-card-body">
                            <div class="flv-form-group">
                                <label>
                                    <input type="checkbox" name="flv_exclude_rss" value="1" <?php checked($exclude_rss, '1'); ?>>
                                    <?php _e('Exclude RSS Feeds', 'force-login-view'); ?>
                                </label>
                                <p class="description">
                                    <?php _e('Allow RSS feeds to be accessible without login. This is useful for feed readers and syndication.', 'force-login-view'); ?>
                                </p>
                            </div>
                            <div class="flv-form-group">
                                <label>
                                    <input type="checkbox" name="flv_exclude_rest_api" value="1" <?php checked($exclude_rest_api, '1'); ?>>
                                    <?php _e('Exclude REST API', 'force-login-view'); ?>
                                </label>
                                <p class="description">
                                    <?php _e('Allow WordPress REST API endpoints to be accessible without login. Useful for headless WordPress setups.', 'force-login-view'); ?>
                                </p>
                            </div>
                            <div class="flv-form-group">
                                <label>
                                    <input type="checkbox" name="flv_exclude_ajax" value="1" <?php checked($exclude_ajax, '1'); ?>>
                                    <?php _e('Exclude AJAX Requests', 'force-login-view'); ?>
                                </label>
                                <p class="description">
                                    <?php _e('Allow AJAX requests to bypass login requirement. Useful for frontend interactions that don\'t require authentication.', 'force-login-view'); ?>
                                </p>
                            </div>
                            <div class="flv-form-group">
                                <label>
                                    <input type="checkbox" name="flv_exclude_archives" value="1" <?php checked($exclude_archives, '1'); ?>>
                                    <?php _e('Exclude Archive & Search Pages', 'force-login-view'); ?>
                                </label>
                                <p class="description">
                                    <?php _e('Allow archive pages, search results, and 404 pages to be accessible without login.', 'force-login-view'); ?>
                                </p>
                            </div>
                        </div>
                    </div>
                    
                    <!-- IP Whitelist Section -->
                    <div class="flv-card">
                        <div class="flv-card-header" style="display: flex; justify-content: space-between; align-items: center;">
                            <h2 style="margin: 0;"><?php _e('IP Whitelist', 'force-login-view'); ?></h2>
                            <?php submit_button(__('Save Changes', 'force-login-view'), 'primary', 'flv_save_settings', false); ?>
                        </div>
                        <div class="flv-card-body">
                            <div class="flv-form-group">
                                <label for="flv_whitelist_ips"><?php _e('Whitelisted IP Addresses', 'force-login-view'); ?></label>
                                <textarea id="flv_whitelist_ips" name="flv_whitelist_ips" rows="5" placeholder="192.168.1.1&#10;10.0.0.0/8&#10;172.16.0.0/12" style="width: 100%; padding: 8px; border: 1px solid var(--google-border); border-radius: 4px; font-family: monospace;"><?php echo esc_textarea($whitelist_ips); ?></textarea>
                                <p class="description">
                                    <?php _e('Enter IP addresses (one per line) that should bypass login requirement. Supports CIDR notation (e.g., 192.168.1.0/24).', 'force-login-view'); ?>
                                    <br><strong><?php _e('Your current IP:', 'force-login-view'); ?></strong> 
                                    <code id="flv-current-ip" data-ip="<?php echo esc_attr($current_ip_display); ?>"><?php echo esc_html($current_ip_display); ?></code>
                                    <button type="button" id="flv-add-current-ip" class="button button-small" style="margin-left: 8px;">
                                        <?php _e('Add to Whitelist', 'force-login-view'); ?>
                                    </button>
                                </p>
                            </div>
                        </div>
                    </div>
                        </div>
                        <!-- Right Column: Access Control & Redirects -->
                        <div class="flv-column">
                            <!-- Bypass Roles Section -->
                            <div class="flv-card">
                        <div class="flv-card-header" style="display: flex; justify-content: space-between; align-items: center;">
                            <h2 style="margin: 0;"><?php _e('Bypass Roles', 'force-login-view'); ?></h2>
                            <?php submit_button(__('Save Changes', 'force-login-view'), 'primary', 'flv_save_settings', false); ?>
                        </div>
                        <div class="flv-card-body">
                            <div class="flv-form-group">
                                <label for="flv_bypass_roles"><?php _e('User Roles That Can Bypass Login', 'force-login-view'); ?></label>
                                <select id="flv_bypass_roles" name="flv_bypass_roles[]" multiple="multiple">
                                    <?php foreach ($all_roles as $role_key => $role_name) : ?>
                                        <option value="<?php echo esc_attr($role_key); ?>" <?php selected(in_array($role_key, $bypass_roles)); ?>>
                                            <?php echo esc_html($role_name); ?>
                                        </option>
                                    <?php endforeach; ?>
                                </select>
                                <p class="description">
                                    <?php _e('Select user roles that can view all pages without being redirected to login, even if they are not excluded pages.', 'force-login-view'); ?>
                                </p>
                            </div>
                        </div>
                    </div>
                    
                    <!-- Bypass Users Section -->
                    <div class="flv-card">
                        <div class="flv-card-header" style="display: flex; justify-content: space-between; align-items: center;">
                            <h2 style="margin: 0;"><?php _e('Bypass Users', 'force-login-view'); ?></h2>
                            <?php submit_button(__('Save Changes', 'force-login-view'), 'primary', 'flv_save_settings', false); ?>
                        </div>
                        <div class="flv-card-body">
                            <div class="flv-form-group">
                                <label for="flv_bypass_users"><?php _e('Specific Users That Can Bypass Login', 'force-login-view'); ?></label>
                                <select id="flv_bypass_users" name="flv_bypass_users[]" multiple="multiple">
                                    <?php foreach ($all_users as $user) : ?>
                                        <option value="<?php echo esc_attr($user->ID); ?>" <?php selected(in_array($user->ID, $bypass_users)); ?>>
                                            <?php echo esc_html($user->display_name); ?> (<?php echo esc_html($user->user_email); ?>)
                                        </option>
                                    <?php endforeach; ?>
                                </select>
                                <p class="description">
                                    <?php _e('Select specific users that can view all pages without being redirected to login, regardless of their role or page exclusions.', 'force-login-view'); ?>
                                </p>
                            </div>
                        </div>
                    </div>
                    
                    <!-- Redirect Settings Section -->
                    <div class="flv-card">
                        <div class="flv-card-header" style="display: flex; justify-content: space-between; align-items: center;">
                            <h2 style="margin: 0;"><?php _e('Redirect Settings', 'force-login-view'); ?></h2>
                            <?php submit_button(__('Save Changes', 'force-login-view'), 'primary', 'flv_save_settings', false); ?>
                        </div>
                        <div class="flv-card-body">
                            <div class="flv-form-group">
                                <label>
                                    <input type="radio" name="flv_redirect_back" value="1" <?php checked($redirect_back, '1'); ?>>
                                    <?php _e('Redirect back to original page after login', 'force-login-view'); ?>
                                </label>
                                <p class="description" style="margin-top: 8px;">
                                    <?php _e('Users will be redirected back to the page they were trying to access after logging in.', 'force-login-view'); ?>
                                </p>
                            </div>
                            <div class="flv-form-group">
                                <label>
                                    <input type="radio" name="flv_redirect_back" value="0" <?php checked($redirect_back, '0'); ?>>
                                    <?php _e('Use custom redirect URL', 'force-login-view'); ?>
                                </label>
                                <input type="url" name="flv_custom_redirect_url" value="<?php echo esc_attr($custom_redirect); ?>" placeholder="<?php echo esc_attr(home_url()); ?>" style="width: 100%; max-width: 500px; margin-top: 8px; padding: 8px; border: 1px solid var(--google-border); border-radius: 4px;">
                                <p class="description">
                                    <?php _e('Enter a custom URL where users should be redirected after login. Leave empty to redirect to homepage.', 'force-login-view'); ?>
                                </p>
                            </div>
                            <div class="flv-form-group">
                                <label for="flv_custom_login_url"><?php _e('Custom Login Page URL', 'force-login-view'); ?></label>
                                <input type="url" id="flv_custom_login_url" name="flv_custom_login_url" value="<?php echo esc_attr($custom_login_url); ?>" placeholder="<?php echo esc_attr(wp_login_url()); ?>" style="width: 100%; max-width: 500px; padding: 8px; border: 1px solid var(--google-border); border-radius: 4px;">
                                <p class="description">
                                    <?php _e('Optional: Enter a custom login page URL. Leave empty to use the default WordPress login page.', 'force-login-view'); ?>
                                </p>
                            </div>
                        </div>
                    </div>
                    
                    <!-- Login Message Section -->
                    <div class="flv-card">
                        <div class="flv-card-header" style="display: flex; justify-content: space-between; align-items: center;">
                            <h2 style="margin: 0;"><?php _e('Login Message', 'force-login-view'); ?></h2>
                            <?php submit_button(__('Save Changes', 'force-login-view'), 'primary', 'flv_save_settings', false); ?>
                        </div>
                        <div class="flv-card-body">
                            <div class="flv-form-group">
                                <label for="flv_login_message"><?php _e('Custom Login Message', 'force-login-view'); ?></label>
                                <textarea id="flv_login_message" name="flv_login_message" rows="3" style="width: 100%; padding: 8px; border: 1px solid var(--google-border); border-radius: 4px; font-family: inherit;"><?php echo esc_textarea($login_message); ?></textarea>
                                <p class="description">
                                    <?php _e('Optional: Add a custom message that will be displayed on the login page. Leave empty to use default WordPress login page.', 'force-login-view'); ?>
                                </p>
                            </div>
                        </div>
                    </div>
                    
                    <!-- Bypass Key Section -->
                    <div class="flv-card">
                        <div class="flv-card-header" style="display: flex; justify-content: space-between; align-items: center;">
                            <h2 style="margin: 0;"><?php _e('Bypass Key', 'force-login-view'); ?></h2>
                            <?php submit_button(__('Save Changes', 'force-login-view'), 'primary', 'flv_save_settings', false); ?>
                        </div>
                        <div class="flv-card-body">
                            <div class="flv-form-group">
                                <label for="flv_bypass_key"><?php _e('Bypass Key', 'force-login-view'); ?></label>
                                <input type="text" id="flv_bypass_key" name="flv_bypass_key" value="<?php echo esc_attr($bypass_key); ?>" placeholder="<?php _e('Enter a secret key', 'force-login-view'); ?>" style="width: 100%; max-width: 500px; padding: 8px; border: 1px solid var(--google-border); border-radius: 4px;">
                                <p class="description">
                                    <?php _e('Set a secret key to allow bypassing login by adding ?flv_bypass=YOUR_KEY to any URL. Leave empty to disable this feature.', 'force-login-view'); ?>
                                    <?php if (!empty($bypass_key)) : ?>
                                        <br><strong><?php _e('Example:', 'force-login-view'); ?></strong> <code><?php echo esc_url(home_url('/?flv_bypass=' . $bypass_key)); ?></code>
                                    <?php endif; ?>
                                </p>
                            </div>
                        </div>
                    </div>
                    
                    <!-- Maintenance Mode Section -->
                    <div class="flv-card">
                        <div class="flv-card-header" style="display: flex; justify-content: space-between; align-items: center;">
                            <h2 style="margin: 0;"><?php _e('Maintenance Mode', 'force-login-view'); ?></h2>
                            <?php submit_button(__('Save Changes', 'force-login-view'), 'primary', 'flv_save_settings', false); ?>
                        </div>
                        <div class="flv-card-body">
                            <div class="flv-form-group">
                                <label>
                                    <input type="checkbox" name="flv_maintenance_mode" value="1" <?php checked($maintenance_mode, '1'); ?>>
                                    <?php _e('Enable Maintenance Mode', 'force-login-view'); ?>
                                </label>
                                <p class="description">
                                    <?php _e('Show a maintenance page instead of redirecting to login. Useful for scheduled maintenance.', 'force-login-view'); ?>
                                </p>
                            </div>
                            <div class="flv-form-group">
                                <label for="flv_maintenance_title"><?php _e('Maintenance Title', 'force-login-view'); ?></label>
                                <input type="text" id="flv_maintenance_title" name="flv_maintenance_title" value="<?php echo esc_attr($maintenance_title); ?>" style="width: 100%; max-width: 500px; padding: 8px; border: 1px solid var(--google-border); border-radius: 4px;">
                            </div>
                            <div class="flv-form-group">
                                <label for="flv_maintenance_message"><?php _e('Maintenance Message', 'force-login-view'); ?></label>
                                <textarea id="flv_maintenance_message" name="flv_maintenance_message" rows="3" style="width: 100%; padding: 8px; border: 1px solid var(--google-border); border-radius: 4px; font-family: inherit;"><?php echo esc_textarea($maintenance_message); ?></textarea>
                            </div>
                        </div>
                    </div>
                        </div>
                    </div>
                    
                    <!-- Submit Section - Full Width -->
                    <div class="flv-submit-section flv-full-width">
                        <p class="description" style="margin: 0;">
                            <?php _e('Changes will take effect immediately after saving.', 'force-login-view'); ?>
                        </p>
                        <?php submit_button(__('Save', 'force-login-view'), 'primary large', 'flv_save_settings', false); ?>
                    </div>
                </form>
                
                <!-- Powered by Absoluto Designs -->
                <div class="flv-powered-by">
                    <p><?php _e('Powered by:', 'force-login-view'); ?> <a href="http://absolutodesigns.com/plugins" target="_blank" rel="noopener noreferrer">Absoluto Designs</a></p>
                </div>
            </div>
        </div>
        <?php
    }
}

// Initialize the plugin
function flv_init() {
    return Force_Login_View::get_instance();
}

// Start the plugin
add_action('plugins_loaded', 'flv_init');

