OPENSSLDIR = C:\OpenSSL-Win32

CC = cl /nologo
DEFS = /DHAVE_TIME_H /DHAVE_SYS_STAT_H /DHAVE_STDINT_H -DHAVE_IO_H -D_SECURE_CRT_NO_WARNINGS=1
INCLUDES = /I$(OPENSSLDIR)\include
CPPFLAGS = /TC $(INCLUDES) $(DEFS) $(EXTRA_CPPFLAGS)
CFLAGS = /Od /GA /Zi /MDd $(CPPFLAGS) $(EXTRA_CFLAGS)
CCLD = $(CC)
LDFLAGS = /LIBPATH:$(OPENSSLDIR)\lib\VC /SUBSYSTEM:CONSOLE $(EXTRA_LDFLAGS)
LIBS = libeay32MDd.lib $(EXTRA_LIBS)

OUT = locksmith.exe
OUT_EXP = locksmith.exp
OUT_LIB = locksmith.lib
OBJ = keytool.obj args.obj getopt.obj generate.obj handlers.obj \
	cert-ipgp.obj der.obj dnssec.obj openssh.obj pem.obj pgp.obj \
	pka.obj pkcs8.obj rdfxml.obj ssh.obj sshfp.obj text.obj \
	turtle.obj

all: $(OUT) libeay32.dll

libeay32.dll: $(OPENSSLDIR)\libeay32.dll
	COPY $(OPENSSLDIR)\libeay32.dll

$(OUT): $(OBJ)
	$(CCLD) /Fe$(OUT) $(OBJ) /link $(LDFLAGS) $(LIBS)

.c.obj:
	$(CC) /c $(CFLAGS) /Fo$@ $<

clean:
	DEL /f $(OUT) $(OBJ) $(OUT_EXP) $(OUT_LIB)
