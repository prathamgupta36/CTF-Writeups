chall: chall.cpp crypto.hpp
	g++ -std=c++20 -O2 -I./intx/include/ chall.cpp -o chall -Wl,-z,relro,-z,now -lcrypto
crypto_test: crypto_test.cpp crypto.hpp
	g++ -std=c++20 -O2 -I./intx/include/ crypto_test.cpp -o crypto_test -Wl,-z,relro,-z,now -lcrypto