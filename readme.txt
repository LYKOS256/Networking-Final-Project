CS4254: FTP SERVER

Rearranged file structure:
./client_directory/ is the client's local files
./server_directory/ are the files on the server.

running the client and server from within these files makes it easier to see the correct transferring
( or at least it was hard to understand what was going on with the .c and executable files in the directories 
for me)

Compiling instructions (from ./Networking-Final-Project):
    cd ..
    gcc server.c -o server -lcrypto -lssl
    cd ./server_directory/
    ../server

    cd ..
    gcc client.c -o client -lcrypto -lssl
    cd ./client_directory/
    ../client 127.0.0.1


Commands currently implemented:

AUTH <user> <pass>:
    currently just "admin" "password", doesn't actually enforce permissions.

PUT <file> <dest>:              example: PUT test.txt ./dironserver
    takes a file from the client and uploads it to the server

GET <file>:
    downloads a file from the server

PING:
    Responds PONG

LIST <dir>:
    shows the directory's content

PWD:
    print working directory

CWD:
    modify current working directory

DELE:
    Delete a file from the server.

MKDIR <dir>:
    Makes a directory.
RMDIR <dir>:
    Removes a dir.

QUIT:
    closes the client connection.


TODO:
[ ] - enforcing AUTH permissions (admin/user/not logged in)
