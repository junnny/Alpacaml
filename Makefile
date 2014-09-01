CC = corebuild
PKG = async,cryptokit,sodium
LFLAGS = -lflags -cclib,-lsodium

all: client server

client:
	$(CC) -pkg $(PKG) $(LFLAGS) client.native

server:
	$(CC) -pkg $(PKG) $(LFLAGS) server.native

clean:
	$(CC) -clean

.PHONY: client server all clean

