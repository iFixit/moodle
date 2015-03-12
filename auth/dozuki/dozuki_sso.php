<?php

if (isset($_GET['userid'])) {
   DozukiAuthentication::validate();
} else {
   DozukiAuthentication::authenticate();
}

/**
 * Implementation of authentication against dozuki server.
 * See docs here: https://github.com/iFixit/dozuki-single-sign-on
 * 
 * See moodle authentication plugin docs here: 
 * https://docs.moodle.org/dev/Authentication_plugins#authenticate_user_login.28.29
 * 
 * @author Kyle Wiens
 */
class DozukiAuthentication {
   // TODO: Switch to live server URL
   protected static $dozukiSite = '';
   protected static $secret = '<SECRET_KEY>';
   // TODO: Move moodle to production dir with symlinks
   protected static $moodleConfigFile = '<MOODLE_CONFIG_FILE>';

   public static function validate() {
      require(self::$moodleConfigFile);

      $fullParams = $_SERVER['QUERY_STRING'];
      self::verifySecureParameters($fullParams, time(), self::$secret);

      $loginurl = '/login/index.php';
      if (!empty($CFG->alternateloginurl)) {
         $loginurl = $CFG->alternateloginurl;
      }
      
      $useremail = $_GET['email'];
      $user = self::get_user($useremail) ?: self::create_user($useremail, $_GET['name']);
      complete_user_login($user);
      
      // Redirect to Moodle url
      
      // We don't want to do this now, but may in the future
      $askUserForFullInfo = false;
      if ($askUserForFullInfo && user_not_fully_set_up($user)) {
         $url = $CFG->wwwroot.'/user/edit.php';
         // We don't delete $SESSION->wantsurl yet, so we get there later                                                                          
         } else if (isset($SESSION->wantsurl) and (strpos($SESSION->wantsurl, $CFG->wwwroot) === 0)) {
         // Because it's an address in this site
         $url = $SESSION->wantsurl;    
         unset($SESSION->wantsurl);
      } else {
         // No wantsurl stored or external - go to homepage                                                                                        
         $url = $CFG->wwwroot . '/';
         unset($SESSION->wantsurl);
      }

      redirect($url);
   }

   private static function get_user($useremail) {
      global $DB;

      return $DB->get_record('user', array('username' => $useremail));
   }

   // create the user if it doesn't exist
   private static function create_user($useremail, $name) {
      global $DB, $CFG;

      // deny login if setting "Prevent account creation when authenticating" is on
      if ($CFG->authpreventaccountcreation) throw new moodle_exception("noaccountyet", "auth_dozuki");
      
      // retrieve more information from the provider
      $newuser = new stdClass();

      $newuser->email = $useremail;
      $newuser->username = $useremail;
      $newuser->firstname = $name;
      $newuser->lastname = '';
      $newuser->country = 'US'; 
      $newuser->city = ''; 
      
      create_user_record($useremail, '', 'dozuki');
      
      $user = authenticate_user_login($useremail, null, false, $str);
      
      if ($user) {
         $newuser->id = $user->id;
         $DB->update_record('user', $newuser);
         $user = (object) array_merge((array) $user, (array) $newuser);
      }
      
      return $user;
   }

   public static function authenticate() {
      require(self::$moodleConfigFile);

      if (!static::isLoggedIn()) {
         static::sendToLogin();
      }
   }

   // Example hash: 
   // userid=758572&email=fred%40ifixit.com&name=Fred&t=1419899081&hash=6193f3c42dc33...
   protected static function verifySecureParameters($fullQuery, $timestamp, $secret) {
      if (!preg_match("#^(.*)&hash=([^&]+)$#", $fullQuery, $matches)) {
         throw new moodle_exception(
          "Invalid query string format. &hash= must be the last parameter.");
      }

      $secureParams = $matches[1];
      $secureHash = $matches[2];
      $calculatedHash = sha1($secureParams . $secret);

      if ($calculatedHash !== $secureHash)
         throw new moodle_exception("Secure hash is incorrect.");

      $MAX_TIMESTAMP_DELTA = 3600;

      if (abs(time() - $timestamp) > $MAX_TIMESTAMP_DELTA) {
         $seconds = time() - $timestamp;
         throw new moodle_exception("Timestamp is off UTC by " .
            " $seconds seconds. It must be a Unix epoch timestamp within " .
          MAX_TIMESTAMP_DELTA . " seconds of UTC.");
      }
   }

   /**
    * Change this function to return true if a user is logged into your site
    * and false if not.
    */
   protected static function isLoggedIn() {
      // This is working correctly now, but if it causes trouble in the future,
      // the reference code does something like:
      // return isset($_SESSION['userid']);
      return false;
   }

   /**
    * This function should redirect the user to your login page, or just render
    * it directly.
    */
   protected static function sendToLogin() {
      $type = 'login';

      // To test in coder dirs, set this to
      // something like kwiens.cominor.com
      $debugURL = '';

      if ($debugURL) {
         static::$dozukiSite = $debugURL;
      } else if (!static::$dozukiSite) {
         static::$dozukiSite = $_SERVER['HTTP_HOST'];
      }
      $destinationURL = 'http://' . static::$dozukiSite .
       "/Guide/User/dozuki_sso?site=moodle";

      redirect($destinationURL);
   }
}

