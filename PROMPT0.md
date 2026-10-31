* write a network fileserver daemon.
## design
* it should require the fewest configuration options.
## protocols
* the fileserver should implement SMB 3.0.
## platforms
* the fileserver runs on recent version of Linux and macOS hosts.
* the fileserver will serve recent versions of Linux, Windows, and macOS clients.
## embedded admin webserver
* manage a configuration options.
* manage share share names and hosted directory paths.
* may manage user credentials.
* live monitor activity.
## implementation
* all tool code must be entirely in Zig 0.17.0 (or later version); this is non-negotiatable.
* it may use SQLite to store data (e.g., hashed passwords, configuration state).
## self improvement
* update PROMPT.md
