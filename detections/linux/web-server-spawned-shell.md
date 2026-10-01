# Shell or downloader spawned by a web server process

| | |
|---|---|
| ID | LNX-001 |
| ATT&CK | [T1505.003](https://attack.mitre.org/techniques/T1505/003/) Server Software Component: Web Shell |
| Data needed | Linux process creation with parent process (auditd, Sysmon for Linux or EDR) |
| Severity | High |
| Status | Experimental. Logic reviewed; not yet validated against production data. |

## Why

A web server worker has no ordinary reason to start a shell, an interpreter or a download tool. When it does, an application flaw or a web shell is usually executing commands.

## Splunk

```spl
| tstats summariesonly=true count min(_time) as first_seen
    from datamodel=Endpoint.Processes
    where Processes.parent_process_name IN ("apache2", "httpd", "nginx", "php-fpm*", "java", "node", "gunicorn", "uwsgi")
          Processes.process_name IN ("sh", "bash", "dash", "python*", "perl", "nc", "ncat", "curl", "wget")
    by Processes.dest, Processes.user, Processes.parent_process_name, Processes.process_name, Processes.process
| `drop_dm_object_name(Processes)`
| convert ctime(first_seen)
```

## Elastic

```eql
process where host.os.type == "linux" and event.type == "start" and
  process.parent.name : ("apache2", "httpd", "nginx", "php-fpm*", "java", "node", "gunicorn", "uwsgi") and
  process.name : ("sh", "bash", "dash", "python*", "perl", "nc", "ncat", "curl", "wget")
```

## False positives

Applications that legitimately shell out, such as image conversion, PDF generation and CGI scripts. `java` and `node` as parents are the noisiest. Allowlist by application host and command line.

## Validate

On a lab web server, request a test script that runs `id` through the web server user.

## Respond

Capture the command line and the web access log entry at the same time; together they show the request that triggered execution. Look for new files in the web root.
