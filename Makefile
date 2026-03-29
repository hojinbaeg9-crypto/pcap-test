#Makefile

all: pcap-test

pcap-test: main.o
	gcc -o pcap-test main.o -lpcap		#pcap 라이브러리 링크

main.o: pcap-test.c
	gcc -c -o main.o pcap-test.c

clean:
	rm -f pcap-test
	rm -f *.o
