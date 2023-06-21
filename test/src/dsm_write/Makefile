CC = gcc
CFLAGS = -Wall -Wextra -Wno-implicit-function-declaration -Wno-unused-but-set-variable
LDFLAGS = -lpthread

SRCS = dsm_write.c radix.c time.c 
OBJS = $(SRCS:.c=.o)
EXEC = dsm_write

all: $(EXEC)

$(EXEC): $(OBJS)
	$(CC) $(CFLAGS) $(OBJS) -o $(EXEC) $(LDFLAGS)

%.o: %.c
	$(CC) $(CFLAGS) -c $< -o $@

clean:
	rm -f $(OBJS) $(EXEC)
