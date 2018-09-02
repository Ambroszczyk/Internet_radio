TARGETS = sikradio-receiver sikradio-sender

CXX = g++
CXXFLAGS = -pthread -Wall -O2 -std=c++17
LDFLAGS = -Wall -pthread

all: $(TARGETS)

sikradio-receiver.o sikradio-sender.o err.o: err.h

sikradio-define.o: sikradio-define.h

sikradio-receiver: sikradio-receiver.o err.o sikradio-define.o
	$(CXX) $(LDFLAGS) $^ -o $@

sikradio-sender: sikradio-sender.o err.o sikradio-define.o
	$(CXX) $(LDFLAGS) $^ -o $@
	
.PHONY: clean

clean:
	rm -f $(TARGETS) *.o *~ *.bak
