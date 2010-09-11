<?php
include 'config.inc'; 
include 'payswarmdb.inc'; 

// get the session ID if it exists
$id = 0;
if(array_key_exists("session", $_COOKIE))
{
   $id = $_COOKIE["session"];
}
else if(array_key_exists("session", $_GET))
{
   $id = $_GET["session"];
}
else
{
   error("Session ID does not exist.");
}

// get the payment token if it exists
$ps = new payswarm;
$ptok = $ps->load($id);

if($ptok === false)
{
   error("Failed to retrieve Payment Token associated with ID: $id");
}

// If we are in state == 1 there should be an OAuth_token, if not go back to 0
if($ptok['state'] === "authorizing" && !isset($_GET['oauth_token']))
{
   $ptok['state'] = "initializing";
}

try
{
   $oauth = new OAuth(
      $CONSUMER_KEY, $CONSUMER_SECRET, OAUTH_SIG_METHOD_HMACSHA1, 
      OAUTH_AUTH_TYPE_FORM);

   // enable debug output for OAuth and remove SSL checks
   $oauth->enableDebug();
   $oauth->disableSSLChecks();

   // check the state of the payment token
   if($ptok['state'] === "initializing")
   {
      // State 0 - Generate request token and redirect user to payswarm site 
      // to authorize
      $article = $_GET['article'];
      $callback_url = "$BUY_URL/$article?session=$id";
      $request_token_info = 
         $oauth->getRequestToken("$REQUEST_URL?currency=USD&amount=1.00", $callback_url);

      $tok['id'] = $id;
      $tok['token'] = $request_token_info['oauth_token'];
      $tok['secret'] = $request_token_info['oauth_token_secret'];
      $tok['amount'] = "0.0";
      $tok['state'] = "authorizing";
      if($ps->save($tok))
      {
         // Save the token and the secret, which will be used later
         $oauth_token = $tok['token'];
         header("Location: $AUTHORIZE_URL?oauth_token=$oauth_token");
      }
      else
      {
         // if something went wrong, clear the cookie and attempt the purchase
         // again
         setcookie(
            "session", $id, time() - 3600, "/$DEMO_PATH/", $WEBSITE, true);
         header("Location: $BASE_URL/");
      }
   }
   else if($ptok['state'] === "authorizing")
   {
      // State 1 - Handle callback from payswarm 
      if(array_key_exists("oauth_verifier", $_GET))
      {
         // get and store an access token
         $oauth->setToken($_GET['oauth_token'], $ptok['secret']);
         $access_token_info = $oauth->getAccessToken($ACCESS_URL);
         $tok['id'] = $id;
         $tok['state'] = "valid";
         $tok['token'] = $access_token_info['oauth_token'];
         $tok['secret'] = $access_token_info['oauth_token_secret'];
         $tok['amount'] = '0.0';
         
         // save the access token and secret
         $ps->save($tok);

         $article = $_GET['article'];
         $redir_url = "$BUY_URL/$article?session=$id";
         header("Location: $redir_url");
      }
      else
      {
         $fh = fopen("articles/denied.html", "r");
         print(fread($fh, 32768));
         fclose($fh);
      }
   }
   else if($ptok['state'] === "valid")
   {
      // State 2 - Authorized. We can just use the stored access token
      $oauth->setToken($ptok['token'], $ptok['secret']);
      $article = $_GET['article'];
      $params = array(
         'asset' => "$ARTICLES_URL/$article",
         'license' => 'http://example.org/licenses/personal-use',
         'license_hash' => '866f3f9540e572e8cc4467f470a869242db201ba',
         'currency' => 'USD',
         'amount' => '0.01');

      // catch any token revocations
      try
      {
         $oauth->fetch($CONTRACTS_URL, $params);
         
         // check to see if the purchase was approved and get the remaining
         // balance on the payment token
         $authorized = false;
         $balance = "0.0";
         $items = explode("&", $oauth->getLastResponse());
         foreach($items as $item)
         {
            $kv = explode("=", $item, 2);
            if($kv[0] === "authorized" && $kv[1] === "true")
            {
               $authorized = true;
            }
            else if($kv[0] === "balance")
            {
               $balance = $kv[1];
            }
         }

         if($authorized)
         {
            $ptok['state'] = "valid";
            $tok['id'] = $ptok['id'];
            $tok['state'] = $ptok['state'];
            $tok['token'] = $ptok['token'];
            $tok['secret'] = $ptok['secret'];
            $tok['amount'] = $balance;
            // Save the access token and secret
            $ps->save($tok);
            $article = $_GET['article'];
            $redir_url = "$ARTICLES_URL/$article";
            header("Location: $redir_url");
         }
      }
      catch(OAuthException $E)
      {
         // if there is an error, check to see that the token has been
         // revoked
         $error = $oauth->getLastResponse();
         $invalidToken = strpos($error, "bitmunk.database.NotFound");

         if($invalidToken !== false)
         {
            setcookie(
               "session", $id, time() - 3600, "/$DEMO_PATH/", $WEBSITE, true);
            $fh = fopen("articles/revoked.html", "r");
            print(fread($fh, 32768));
            fclose($fh);
         }
      }
   }
}
catch(OAuthException $E)
{
   $err = json_decode($E->lastResponse);
   print_r('<pre>' . $E . "\nError details: \n" . print_r($err, true) . '</pre>');
}
?>
