CC = gcc

TARGET = src/packet_sniffer

SRC = src/main.c

LIBS = -lpcap

#  What dis doing?
all: $(TARGET) 

$(TARGET): $(SRC)
	$(CC) $(SRC) -o $(TARGET) $(LIBS)

clean || clear:
	rm -f $(TARGET)
