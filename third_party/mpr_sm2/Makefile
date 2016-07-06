CC = gcc
CPP = g++

CFLAG = -O2 -c  -D_BSD_SOURCE
CFLAGS = $(CFLAG) -I.

CPPFLAGS += -Wall
CPPFLAGS += -Wpointer-arith
CPPFLAGS += -Wno-cast-qual
CPPFLAGS += -Wno-deprecated
CXXFLAGS += -Wno-write-strings
CPPFLAGS += -g -c
CPPFLAGS += -I.


C_SRC := ./mrbuild.c	\
	./mrlucas.c	\
	./mrflsh1.c	\
	./mrfrnd.c	\
	./mrzzn3.c	\
	./hail.c	\
	./mr87v.c	\
	./mrflsh3.c	\
	./mrround.c	\
	./mrxgcd.c	\
	./mralloc.c	\
	./mrzzn2.c	\
	./mrgcd.c	\
	./mrcomba.c	\
	./mrarth3.c	\
	./mrscrt.c	\
	./mrpi.c	\
	./mrio1.c	\
	./mrio2.c	\
	./mrcrt.c	\
	./mrarth1.c	\
	./p1363.c	\
	./mrflsh4.c	\
	./mrecn2.c	\
	./mrmonty.c	\
	./mrcurve.c	\
	./mrdouble.c	\
	./mrgf2m.c	\
	./mpr_sm2.c	\
	./mrflash.c	\
	./mrarth2.c	\
	./mrzzn4.c	\
	./ecn2_opt.c	\
	./mrjack.c	\
	./mrcomba2.c	\
	./mrsmall.c	\
	./mrzzn2b.c	\
	./mrec2m.c	\
	./mrsroot.c	\
	./mrmuldv.c	\
	./mr87f.c	\
	./mrbits.c	\
	./mrfast.c	\
	./mrcore.c	\
	./mrarth0.c	\
	./mrebrick.c	\
	./mrpower.c	\
	./mrprime.c	\
	./mrrand.c	\
	./mrbrick.c	\
	./mrflsh2.c	\
	./mrkcm.c	

C_OBJECTS := $(C_SRC:.c=.o)

TARGET = libmpr_sm2.a

%.o:%.c
	$(CC) $(CFLAGS) $< -o $@

%.o:%.cc
	@$(CPP) $(CPPFLAGS) $< -o $@
	@echo "  [CXX]  $@"

all:$(C_OBJECTS)
	@ar rc $(TARGET) $(OBJS);
	@ranlib $(TARGET)
	@echo "  [AR]   $(TARGET)"


clean:
	rm -f $(OBJS)
	rm -f $(TARGET)
	rm -f main.o
