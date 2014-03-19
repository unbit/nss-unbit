all:
	gcc -g -fPIC -shared -o /lib/libnss_unbit.so.2 nss_unbit.c -lm
