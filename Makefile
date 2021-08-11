all: ip-list

ip-list:
	g++ --std=c++17 -I/opt/halon/include/ -I/usr/local/include/ -fPIC -shared ip-list.cpp -llpm -o ip-list.so