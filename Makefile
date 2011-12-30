OUT = keytool
OBJ = keytool.o generate.o text.o pem.o openssh.o ssh.o pgp.o der.o turtle.o rdfxml.o dnssec.o cert-ipgp.o pka.o

CFLAGS = -W -Wall -O0 -g

CCLD = $(CC)
CCLDFLAGS = -g
LIBS = -lcrypto

all: $(OUT)

$(OUT): $(OBJ)
	$(CCLD) $(CCLDFLAGS) $(LDFLAGS) -o $(OUT) $(OBJ) $(LIBS)

clean:
	-rm $(OUT) $(OBJ)
