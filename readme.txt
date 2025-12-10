CS4254: FTP SERVER

Rearranged file structure:
./client_directory/ is the client's local files
./server_directory/ are the files on the server.

running the client and server from within these files makes it easier to see the correct transferring
( or at least it was hard to understand what was going on with the .c and executable files in the directories 
for me)

Compiling instructions (from ./Networking-Final-Project):
    cd ..;
    gcc server.c -o server -lcrypto -lssl;
    cd ./server_directory/;
    ../server;

    cd ..;
    gcc client.c -o client -lcrypto -lssl;
    cd ./client_directory/;
    ../client 127.0.0.1;


AUTHENTICATION SYSTEM

Users must authenticate to perform write operations.
- Without login: Can only use GET, LIST, PWD, PING, HELP, QUIT
- With login: Full access to all commands including PUT, DELE, MKDIR, RMDIR, CWD

Default credentials: admin / password


COMMANDS

--- Public Commands (no login required) ---

PING:
    Responds PONG - test if server is alive

GET <file>:
    Downloads a file from the server

LIST [dir]:
    Shows the directory's content (defaults to current directory)

PWD:
    Print working directory

HELP:
    Shows list of available commands

WHOAMI:
    Shows current login status

QUIT:
    Closes the client connection


--- Authenticated Commands (login required) ---

AUTH <user> <pass>:
    Login to gain write access
    Example: AUTH admin password

LOGOUT:
    Logout and return to read-only access

PUT <file> [dest]:
    Takes a file from the client and uploads it to the server
    Example: PUT test.txt
    Example: PUT test.txt ./dironserver   (uploads to directory)

CWD <dir>:
    Modify current working directory

DELE <file>:
    Delete a file from the server

MKDIR <dir>:
    Makes a directory

RMDIR <dir>:
    Removes a directory


Possible additions:
- user database (instead of hardcoded credentials)
- per-user home directories