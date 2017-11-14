all : unblock

unblock: clean nfqnl_test.o
	g++ -o site_unblock nfqnl_test.o -lnetfilter_queue

nfqnl_test.o:
	g++ -c -o nfqnl_test.o nfqnl_test.cpp

clean:
	rm -f site_unblock
	rm -f *.o

