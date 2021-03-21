# simple-dict-server
database["key"]="value"

# Compile
You should first clone this project into a system with cmake & libpthread installed.
If you plan to compile it on Windows, you should edit the source code and transform socket/thread/file libraries into Windows version.
```bash
git clone https://github.com/fumiama/simple-dict-server.git
```
Create a `build` folder.
```bash
cd simple-dict-server
mkdir build
```
Use `cmake` command to generate files for `make` automatically.
```bash
cd build
cmake ../
```
Use `make` to generate executable binary files named `simple-dict-server` and `simple-dict-client` in `./build` directory.
```bash
make
```

# Execute
Start server on localhost using the commands below.
```bash
chmod +x simple-dict-server simple-dict-client
./simple-dict-server -d 7777 1 ./dict.bin    # use -d to start as daemon
```
Open another shell to connect to it.
```bash
./simple-dict-client 127.0.0.1 7777
```
Now you have connected to the server. Type `fumiama` and press enter in `10` seconds to get the read/write access. You can modify the password in source code as you like. Please note that the server will only wait `10` seconds for a response after the last communication. The box below shows how to control the server to accompilsh basic add/del/find/edit operations.
```c
break!
Get sockfd
Connected to server
Welcome to simple dict server.
Thread create succeeded
Enter command:fumiama
Enter command:set     #set a key-value pair
Recv 3 bytes: set
Enter command:test    #key
Recv 4 bytes: data
Enter command:测试    #value
Recv 4 bytes: succ
Enter command:get     #get a value using key
Recv 3 bytes: get
Enter command:test
Recv 6 bytes: 测试
Enter command:del     #delete a key
Recv 3 bytes: del
Enter command:test
Recv 4 bytes: succ
Enter command:get
Recv 3 bytes: get
Enter command:test
Recv 4 bytes: null
Enter command:set
Recv 3 bytes: set
Enter command:test
Recv 4 bytes: data
Enter command:测试
Recv 4 bytes: succ
Enter command:lst   #list all keys that match the pattern
Recv 3 bytes: lst
Enter command:t     #pattern
Recv 5 bytes: test

Enter command:quit
Enter command:^C
```
You can also use `cat` command to get the raw data directly.
```c
break!
Get sockfd
Connected to server
Welcome to simple dict server.
Thread create succeeded
Enter command:fumiama
Enter command:cat
Recv 131 bytes: 128test测试
Enter command:quit
Enter command:^C
```
The raw data starts with an integer showing its size, following all binary data in `./dict.bin`.

# Android Client for simple-dict-server
There is also an [Android Client](https://github.com/fumiama/simple-dict-android) for simple-dict-server. Just install the apk file downloaded from release page and click `config` icon to set your server address using the format
```
127.0.0.1:7777_password
```
Note that this APP is designed for a new language called `Tenenja`, so the font inside is abnormal. What's more, there is no English translation for this APP because its users are Chinese. If you want to get an APP in your language, just edit the source code for free.