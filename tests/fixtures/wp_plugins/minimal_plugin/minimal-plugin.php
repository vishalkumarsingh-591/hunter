<?php
/**
 * Minimal fixture plugin for Hunter tests.
 */
defined('ABSPATH') || exit;

add_action('wp_ajax_nopriv_hunter_test', 'hunter_test_ajax');

function hunter_test_ajax() {
    global $wpdb;
    $id = isset($_GET['id']) ? $_GET['id'] : '';
    $wpdb->query("DELETE FROM wp_posts WHERE ID = " . $id);
    echo $id;
}
