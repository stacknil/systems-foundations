# Linux Process Observe Diff

- Host: `lab-host`
- Observed at: `2026-07-05T00:05:00Z`
- Processes: +1 / -1 / 1 modified
- Process/socket links: +2 / -2

## Processes

### Added

- `lab-host:330:3300 name=python3 uid=1001 gid=1001 exe=/usr/bin/python3.11`

### Removed

- `lab-host:220:2200 name=app-worker uid=1001 gid=1001 exe=/opt/example/bin/app-worker`

### Modified

- `lab-host:230:2300 argv: ['/opt/example/bin/task-runner', '--once'] -> ['/usr/bin/dash', '-c', 'sleep 30'], executable: /opt/example/bin/task-runner -> /usr/bin/dash, name: task-runner -> sh`

## Process/socket links

### Added

- `lab-host:120:1200 tcp ESTAB 192.0.2.10:22 -> 198.51.100.21:51000 exposure=specific`
- `lab-host:330:3300 tcp LISTEN 0.0.0.0:8080 -> 0.0.0.0:* exposure=wildcard`

### Removed

- `lab-host:120:1200 tcp ESTAB 192.0.2.10:22 -> 198.51.100.20:50000 exposure=specific`
- `lab-host:220:2200 tcp LISTEN 127.0.0.1:9000 -> 0.0.0.0:* exposure=loopback`
