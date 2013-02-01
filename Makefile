all : sTelNet.exe

sTelNet.exe: sTelNet.c
	gcc -o sTelNet.exe -fexec-charset=CP932 sTelNet.c -lws2_32
