# simple-dict-server
database["key"]="value"

# Compile
You should first clone this project into a system with cmake & libpthread installed.
If you plan to compile it on Windows, you should edit the source code to transform the socket/thread/file libraries into Windows version.
```bash
git clone https://github.com/fumiama/simple-dict-server.git
```
Now we will create a `build` folder.
```bash
cd simple-dict-server
mkdir build
```
Then use `cmake` command to generate files for `make` automatically.
```bash
cd build
cmake ../
```
Now you can use `make` to generate executable binary files named `simple-dict-server` and `simple-dict-client` in `./build` directory.
```bash
make
```

# Use
Now we will show you how to start the server on localhost. You can try the command below.
```bash
chmod +x simple-dict-server simple-dict-client
./simple-dict-server -d 7777 1 ./dict.bin    # use -d to start as daemon
Bind server success!
Listening....
Ready for accept, waitting...
Run on thread No.0

```
Then you can open another shell to connect to it.
```bash
./simple-dict-client 127.0.0.1 7777
```
Now you have connected to the server. Type `fumiama` and press enter in `10` seconds to get the read/write access. You can modify the password in the source code as you like. Please note that the server will only wait `10` seconds for a response after the last communication. The communication below shows how to control the server to accompilsh basic add/del/find/edit operations.
```bash
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
Enter command:lst   #list all keys match pattern
Recv 3 bytes: lst
Enter command:t     #pattern
Recv 5 bytes: test

Enter command:quit
Enter command:^C
```
You can also use `cat` command to get the raw data directly.
```bash
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
The raw data starts with a integer showing the size of data, then send all data in `./dict.bin` to the client.
