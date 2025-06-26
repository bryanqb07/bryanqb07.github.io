---
layout: post
title: "Kanboard CVE-2025-52560"
---

<style>
/* Only affects this post */
pre {
  margin-top: 2em;
  margin-bottom: 2em !important;
  padding: 1em;
  border-radius: 6px;
}
ol {
  margin-bottom: 2em;
}

ol > li {
  margin-bottom: 1em;  /* space between list items */
  line-height: 1;
}
</style>

## Password Reset Poisoning via Host Header Injection

### Identifying the Vulnerability

So on a whim, this past week I decided to check out [Kanboard](https://github.com/kanboard/kanboard/)
 , an open source Kanban-like sprint task management software. It's a medium-sized project, with over 9k Github stars and several published security audits, so I thought it would be a decent challenge for me.

I spent the first few days getting comfortable with the app and looking through the routes.  After going down some major rabbitholes chasing the usual suspects (SQLi, XSS), I decided to take a step back and take a more holistic view of the app itself.

One thing that stood out to me as unusual is that Kanboard uses its own HTTP module to handle incoming requests, rather than relying on a vetted external library.  After poring through the HTTP module, I came across this bit of code in `app/Helper/UrlHelper.php`:

```php
public function server()
{
    if ($this->request->getServerVariable('SERVER_NAME') === '') {
        return 'http://localhost/';
    }

    $url = $this->request->isHTTPS() ? 'https://' : 'http://';
    $url .= $this->request->getServerVariable('SERVER_NAME');
    ...
    return $url;
}
```

As can be seen, it looks as though a URL is being constructed by parsing the `SERVER_NAME` variable from the HTTP request and appending it to the url. A quick google search shows that `SERVER_NAME` is derived from the HTTP `Host` header, which we as attackers control. Furthermore, it doesn't look like there's any validation of the header field, so we could potentially hijack the url in any way we'd like.

From here, I started looking for potential attack vectors. I soon found this password reset email in `/app/Template/password_reset/template.php`

```php
<p><?= t('To reset your password click on this link:') ?></p>

<p><?= $this->url->to('PasswordResetController', 'change', array('token' => $token), '', true) ?></p>

<hr>
Kanboard
```

I decided to look into the `url -> to`, and... BINGO! It relies on the `UrlHelper::server()` method analyzed above.

From here, the attack chain is clear.

1. Create a malicious website that logs all requests (myevilsite.com).
2. Setup Burp Suite or some proxy server where HTTP requests can be intercepted.
3. Click on Kanboard's `Forgot My Password` link on the login page.
4. Type in the user who you want to attack (admin) and intercept the request after sending
5. Change the Host header to the malcious website (myevilsite.com).
6. The user will receive a malicious link. Once he clicks, attacker can use credentials to reset the password and takeover the account. 


### Exploiting

I have Kanboard running in Docker in its default configuration. Rather than setting up email support, I'll just be lazy and add debug logging to `/var/www/app/app/Core/Mail/Client.php` so that we can log the body of the mail being sent.

```php
    public function send($recipientEmail, $recipientName, $subject, $html, $authorName = null, $authorEmail = null)
    {

    error_log("=== Kanboard Email Debug ===");
    error_log("To: " . $recipientEmail);
    error_log("Subject: " . $subject);
    error_log("Body:\n" . $html);
    error_log("============================");
        if (! empty($recipientEmail)) {
            $this->queueManager->push(EmailJob::getInstance($this->container)->withParams(
                $recipientEmail,
                $recipientName,
                $subject,
                $html,
                is_null($authorName) ? $this->getAuthorName() : $authorName,
                is_null($authorEmail) ? $this->getAuthorEmail() : $authorEmail
            ));
        }

        return $this;
    }
```

Once this is complete, I'll go to the login page, click the `Forgot Password` link, then enter in a username and click submit, making sure to proxy the request through Burp Suite so that I can edit the headers.
<figure style="text-align: center; margin: 2em 0;">
  <img src="/assets/img/kanboard/reset_password.png" alt="Password Reset" style="display: block; margin-left: auto; margin-right: auto; max-width: 90%; border-radius: 8px;">
</figure>

In BurpSuite I'll now go ahead and edit the `Host` header to `myevilsite.com`, then pass the request back through to the backend.
<figure style="text-align: center; margin: 2em 0;">
  <img src="/assets/img/kanboard/proxy.png" alt="Proxy" style="display: block; margin-left: auto; margin-right: auto; max-width: 90%; border-radius: 8px;">
</figure>

If we look through the debug logs of the app for the email sent, we should now see the following:
```
PHP message: === Kanboard Email Debug ===; 
PHP message: To: test@mail.com; PHP message: Subject: Password Reset for Kanboard; PHP message: Body:
kanboard  | <p>To reset your password click on this link:</p>
kanboard  |
kanboard  | <p>http://myevilsite.com/forgot-password/change/39ca7935ca63a4720dd3136d038db0b4778eced1a80d9263d1b998a2ae0c</p>
kanboard  |
kanboard  | <hr>
```

As can be seen the email's reset link is to a site that we as attackers control (myevilsite.com) rather than Kanboard. We can now setup a listener on our evil site to listen for the user's request.
<figure style="text-align: center; margin: 2em 0;">
  <img src="/assets/img/kanboard/listener.png" alt="Listener" style="display: block; margin-left: auto; margin-right: auto; max-width: 90%; border-radius: 8px;">
</figure>

Once we have the reset password token, we can then go to `http://<kanboard_url>/change/<token>` and use the token to change the user's password and subsequently login to the account.
<figure style="text-align: center; margin: 2em 0;">
  <img src="/assets/img/kanboard/reset_success.png" alt="Success" style="display: block; margin-left: auto; margin-right: auto; max-width: 90%; border-radius: 8px;">
</figure>

### Final Thoughts

If you're going to roll out your own HTTP library, better be careful about which headers you trust. Overall, it was a fun discovery that many others missed during their security audits of the app.  Just goes to show that the more "boring" aspects of development (HTTP header parsing) should not be overlooked.


Note that this has been patched and a security advisory has been published here: [GHSA-2ch5-gqjm-8p92 advisory](https://github.com/kanboard/kanboard/security/advisories/GHSA-2ch5-gqjm-8p92)
 
