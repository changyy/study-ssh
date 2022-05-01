cmake_minimum_required (VERSION 2.8)
project (simpleSSHClient)

include_directories (include)

set (CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -I/opt/local/include -I/usr/include -g -std=c++11 -DUSE_OPENSSL")
set (CXXFLAGS "${CXXFLAGS} -I/opt/local/include  -I/usr/include -std=c++11 -g -stdlib=libc++ -DUSE_OPENSSL")
set (LDFLAGS "${LDFLAGS} -L/opt/local/lib")
link_directories(/opt/local/lib)

FIND_PATH(LIBSSH_INCLUDE_DIR NAMES libssh.h)
FIND_LIBRARY(LIBSSH_LIBRARY NAMES ssh)

# ssh crawler for hot board article list
add_executable(ptt-ssh-client
	src/main.cpp
)
target_link_libraries (ptt-ssh-client
	ssl
	ssh
)
