CXXFLAGS += -I.
CXXFLAGS += -I./base
CXXFLAGS += -std=c++11 -Wall -g -c -o

LIB_FILES := -lglog -L/usr/local/lib -lgtest -lgtest_main -lpthread


CPP_SOURCES := ./base/once.cc 

CPP_OBJECTS := $(CPP_SOURCES:.cc=.o)


TESTS := ./base/once_unittest

all: $(CPP_OBJECTS) $(TESTS)
.cc.o:
	$(CXX) $(CXXFLAGS) $@ $<

./base/once_unittest: ./base/once_unittest.o
	$(CXX) -o $@ $< $(CPP_OBJECTS) $(LIB_FILES)
./base/once_unittest.o: ./base/once_unittest.cc
	$(CXX) $(CXXFLAGS) $@ $<

clean:
	rm -fr base/*.o
	rm -fr $(TESTS)
