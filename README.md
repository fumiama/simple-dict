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
./simple-dict-server -d 7777 1 ./dict.sp ./cfg.sp    # use -d to start as daemon
```
Open another shell to connect to it.
```bash
./simple-dict-client 127.0.0.1 7777
```
Now you have connected to the server. Type `fumiama` and press enter in `10` seconds to get the read/write access. You can modify the password in source code as you like. Please note that the server will only wait `10` seconds for a response after the last communication. The box below shows how to control the server to accompilsh basic add/del/find/edit operations.

The raw data starts with an integer showing its size, then a char `$` follows, finally following all binary data in `./dict.sp`.

# Android Client for simple-dict-server
There is also an [Android Client](https://github.com/fumiama/simple-dict-android) for simple-dict-server. Just install the apk file downloaded from release page and click `config` icon to set your server address using the format
```
127.0.0.1:7777_password
```
Note that this APP is designed for a new language called `Tenenja`, so the font inside is abnormal. What's more, there is no English translation for this APP because its users are Chinese. If you want to get an APP in your language, just edit the source code for free.