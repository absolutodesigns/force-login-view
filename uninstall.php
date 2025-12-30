<?php
/**
 * Uninstall script for Force Login to View plugin
 * 
 * This file is executed when the plugin is deleted from WordPress
 */

// Exit if accessed directly
if (!defined('WP_UNINSTALL_PLUGIN')) {
    exit;
}

// Delete all plugin options
delete_option('flv_enabled');
delete_option('flv_excluded_pages');
delete_option('flv_excluded_templates');
delete_option('flv_excluded_post_types');
delete_option('flv_excluded_categories');
delete_option('flv_excluded_tags');
delete_option('flv_exclude_rss');
delete_option('flv_exclude_rest_api');
delete_option('flv_exclude_ajax');
delete_option('flv_exclude_archives');
delete_option('flv_bypass_roles');
delete_option('flv_bypass_users');
delete_option('flv_bypass_key');
delete_option('flv_whitelist_ips');
delete_option('flv_redirect_back');
delete_option('flv_custom_redirect_url');
delete_option('flv_custom_login_url');
delete_option('flv_login_message');
delete_option('flv_maintenance_mode');
delete_option('flv_maintenance_title');
delete_option('flv_maintenance_message');

