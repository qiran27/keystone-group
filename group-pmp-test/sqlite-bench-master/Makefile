CFLAGS=-Wall -I. -O2 -DNDEBUG -std=c99 -DSQLITE_ENABLE_MEMSYS5 -DSQLITE_DEFAULT_MEMSTATUS=0 -DSQLITE_THREADSAFE=0
SRCS=$(wildcard *.c)
EXTRA_SRCS=
OBJS=$(SRCS:.c=.o)
EXTRA_OBJS=
HDRS=$(wildcard *.h)
TARGET=sqlite-bench

UNAME_S := $(shell uname -s)
ifeq ($(UNAME_S),Darwin)
	LDFLAGS=-lpthread -ldl -lm
else
	LDFLAGS=-lpthread -ldl -lm -static
endif

ifeq ($(SEC),1)
	CFLAGS += -DSQLITE_BENCH_HAVE_SEC=1 -I../sec-aesgcm-bench -I../common/enclave
	EXTRA_SRCS += ../sec-aesgcm-bench/jh7110_aes_gcm_user.c
	EXTRA_OBJS += jh7110_aes_gcm_user.o
else
	CFLAGS += -DSQLITE_BENCH_HAVE_SEC=0
endif


$(TARGET): $(OBJS) $(EXTRA_OBJS)
	$(CC) $(OBJS) $(EXTRA_OBJS) -o $(TARGET) $(LDFLAGS)

%.o : %.c 
	$(CC) $(CFLAGS) -c $<

jh7110_aes_gcm_user.o: ../sec-aesgcm-bench/jh7110_aes_gcm_user.c
	$(CC) $(CFLAGS) -c $< -o $@

$(OBJS): $(HDRS)

bench: $(TARGET) clean-db
	./$(TARGET)

clean:
	rm -f $(TARGET) *.o

clean-db:
	rm -f dbbench_sqlite3*

.PHONY: bench clean clean-db
