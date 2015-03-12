<?php

if (!defined('MOODLE_INTERNAL')) {
   // Must be included from a Moodle page
    die('Direct access to this script is forbidden.');    
}

require_once($CFG->libdir.'/authlib.php');

/**
 * Dozuki Moodle authentication plugin
 * Must live in moodle/auth/dozuki (via symlink is OK).
 */
class auth_plugin_dozuki extends auth_plugin_base {

    /**
     * Constructor
     */
    function auth_plugin_dozuki() {
        $this->authtype = 'dozuki';
        $this->roleauth = 'auth_dozuki';
        $this->errorlogtag = '[AUTH DOZUKI] ';
        $this->config = get_config('auth/dozuki');
    }

    /**
     * @param string $username The username (with system magic quotes)
     * @param string $password The password (with system magic quotes)
     * @return bool Authentication success or failure.
     */
    function user_login($username, $password) {
       global $DB, $CFG;

       // retrieve the user matching username
       $user = $DB->get_record('user', array('username' => $username,
         'mnethostid' => $CFG->mnet_localhost_id));

       // username must exist and have the right authentication method
       if (!empty($user) && ($user->auth == 'dozuki')) {
         return true;
       }

       return false;
    }

    function prevent_local_passwords() {
       return true;
    }

    function is_internal() {
       return false;
    }

    function can_change_password() {
       return false;
    }


    function process_config($config) {
    }

    function loginpage_hook() {
    }

    function user_update($olduser, $newuser) {
       return $olduser->email == $newuser->email;
    }

}
