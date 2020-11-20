CFLAGS = -Wall -O2

ota_tools: ota_tools.o quicklz.o tiny_aes.o
	gcc $(CFLAGS) $^ -o $@

ota_tools.o: ota_tools.c quicklz.h tiny_aes.h
	gcc $(CFLAGS) -c $< 

quicklz.o: quicklz.c quicklz.h
	gcc $(CFLAGS) -c $< 

tiny_aes.o: tiny_aes.c tiny_aes.h
	gcc $(CFLAGS) -c $< 

.PHONY: clean
clean:
	-rm -f *.o
