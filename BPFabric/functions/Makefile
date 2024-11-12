SRC = $(wildcard *.c) 

TAR = $(SRC:.c=.o) 

.PHONY: all clean 

all: $(TAR) 

%.o: %.c 
	clang -O2 -target bpf -I ../includes -c $< -o $@ 

clean: 
	rm -f $(TAR) 