# simple-dict-server
database["key"]="value" with tea encryption.

## Prepare
Install [simple-crypto](https://github.com/fumiama/simple-crypto) and [simple-protobuf](https://github.com/fumiama/simple-protobuf) into `/usr/local` according to their README.

## Compile
Clone this project into a system with cmake & libpthread installed.
If you plan to compile it on Windows, you ought to edit the source code and transform socket/thread/file libraries into a Windows version.
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
cmake ..
```
Use `make` to generate executable binary files named `simple-dict-server` and `simple-dict-client` in `./build` directory.
```bash
make
```
Optional: Use `make install` to install `simple-dict-server` into `/usr/local/bin`.

## Execute
Start server on localhost using the commands below.
```bash
chmod +x simple-dict-server simple-dict-client
Usage:
./simple-dict-server [-d] listen_port dict_file [config_file | -]
        -d: As daemon
        - : Read config from env SDS_PWD & SDS_SPS
```
`cfg.sp`is generated by `cfgwriter`, otherwise you can pass config by setting env `SDS_PWD` and `SDS_SPS`.

Open another shell to connect to it.
```bash
./simple-dict-client 127.0.0.1 7777
```
Now you have connected to the server. The default access passwords is in `client.c` and you can modify the password in source code as you like. Please note that the server will only wait `4` seconds for a response after the last communication. The box below shows how to control the server to accompilsh basic add/del/find/edit operations.

|  cmd  |  data  |  description  |  reply  |
|  ----  | ----  | ----  | ----- |
| get:  | key | get key value | the value or "null" |
| cat:  | filename | save raw dict.sp into filename | the raw data |
| md5:  | md5 str | compare whether md5 of dict.sp is what given in data | "nequ" or "null" |
| end   | no data  | end conversation | no reply |
| set:  | key | set key | "data" |
| dat:  | value to set | give value to the key | "succ" |
| del:  | key | del key | "succ" or "null |

- The raw data starts with an integer showing its size, then a char `$` follows, finally following all binary data in `./dict.sp` encoded by `TEA`.
- Whenever the reply is "erro", it indicates that the server has some troubles, which means that you shuold end the conversation and retry later.

A cmd sequence example is as below

https://user-images.githubusercontent.com/41315874/167127391-1798f7ec-f917-4246-b31f-258db9dc771e.mp4

## Android Client for simple-dict-server
There is also an [Android Client](https://github.com/fumiama/simple-dict-android) for simple-dict-server. Just install the apk file downloaded from release page and click `config` icon to set your server address using the format
```
127.0.0.1:7777_password
```
Note that this APP is designed for a new language called `Tenenja`, so the font inside is abnormal. What's more, there is no English translation for this APP because its users are Chinese. If you want to get an APP in your language, just edit the source code for free.