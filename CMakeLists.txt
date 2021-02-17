project(simple-dict-server)
add_executable(simple-dict-server server.c) # 生成可执行文件
add_executable(simple-dict-client client.c) # 生成可执行文件
target_link_libraries(  # 目标库
                        simple-dict-server
 
                        # 目标库需要链接的库
                        pthread)
target_link_libraries(  # 目标库
                        simple-dict-client
 
                        # 目标库需要链接的库
                        pthread)
