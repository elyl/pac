.PHONY: clean

CFLAGS=	-L lib -l coll

coll_finder: md5.o main.o
	g++ $^ -o $@ $(CFLAGS)

lib/libcoll.a:
	cd lib && $(MAKE)

clean:
	rm -f coll_finder
	rm -f *.o
	cd lib && $(MAKE) clean
