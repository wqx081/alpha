CC = gcc
CPP = g++

CFLAG = -O2 -c -D_XOPEN_SOURCE=600 -D_BSD_SOURCE
CFLAGS = $(CFLAG) -I.

CPPFLAGS += -Wall
CPPFLAGS += -Wpointer-arith
CPPFLAGS += -Wno-cast-qual
CPPFLAGS += -Wno-deprecated
CXXFLAGS += -Wno-write-strings
CPPFLAGS += -g -c
CPPFLAGS += -I.

OBJS =  bigint.o	\
		curvep.o	\
		dbg_print.o	\
		eicl_mul.o	\
		mpzlib.o	\
		NNMLib.o	\
		sm2s.o		\
		sm3.o		\
		srand.o		\
		native_sm2.o
		

TARGET = libsm2.a

%.o:%.c
	$(CC) $(CFLAGS) $< -o $@

%.o:%.cpp
	@$(CPP) $(CPPFLAGS) $< -o $@
	@echo "  [CXX]  $@"

all:$(OBJS)
	@ar rc $(TARGET) $(OBJS);
	@ranlib $(TARGET)
	@echo "  [AR]   $(TARGET)"


clean:
	rm -f $(OBJS)
	rm -f $(TARGET)
	rm -f main.o
