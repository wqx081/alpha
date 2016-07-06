CXXFLAGS += -I./
CXXFLAGS += -I./third_party/mpr_sm2/
CXXFLAGS += -std=c++11 -Wall -g -c -o

LIB_FILES := -lglog -L/usr/local/lib -lgtest -lgtest_main -lpthread
CRYPTO_LIB_FILES := -L./third_party/sm2 -lsm2 -L./third_party/mpr_sm2 -lmiracl

CPP_SOURCES := ./base/once.cc \
	./base/mutex.cc \
	./base/condition_variable.cc \
	./base/semaphore.cc \
	./base/time.cc \
	./base/thread.cc \
	./base/task_queue.cc \
	./base/worker_thread.cc \

CPP_OBJECTS := $(CPP_SOURCES:.cc=.o)


TESTS := ./base/once_unittest \
	./base/thread_unittest \
	./base/worker_thread_unittest \
    \
	./crypto/crypto_unittest \


all: $(CPP_OBJECTS) $(TESTS)
.cc.o:
	$(CXX) $(CXXFLAGS) $@ $<

./base/once_unittest: ./base/once_unittest.o
	$(CXX) -o $@ $< $(CPP_OBJECTS) $(LIB_FILES)
./base/once_unittest.o: ./base/once_unittest.cc
	$(CXX) $(CXXFLAGS) $@ $<

./base/thread_unittest: ./base/thread_unittest.o
	$(CXX) -o $@ $< $(CPP_OBJECTS) $(LIB_FILES)
./base/thread_unittest.o: ./base/thread_unittest.cc
	$(CXX) $(CXXFLAGS) $@ $<

./base/worker_thread_unittest: ./base/worker_thread_unittest.o
	$(CXX) -o $@ $< $(CPP_OBJECTS) $(LIB_FILES)
./base/worker_thread_unittest.o: ./base/worker_thread_unittest.cc
	$(CXX) $(CXXFLAGS) $@ $<

./crypto/crypto_unittest: ./crypto/crypto_unittest.o
	$(CXX) -o $@ $< $(CPP_OBJECTS) $(LIB_FILES) $(CRYPTO_LIB_FILES)
./crypto/crypto_unittest.o: ./crypto/crypto_unittest.cc
	$(CXX) $(CXXFLAGS) $@ $<

clean:
	rm -fr base/*.o
	rm -fr crypto/*.o
	rm -fr $(TESTS)
