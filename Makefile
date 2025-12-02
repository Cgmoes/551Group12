#
# Makefile for TLS-enabled chat client, server, and directory server
#
CC	= gcc
EXECUTABLES=chatClient5 chatServer5 directoryServer5
INCLUDES	= $(wildcard *.h)
SOURCES	= $(wildcard *.c)
DEPS		= $(INCLUDES)
OBJECTS	= $(SOURCES:.c=.o)
OBJECTS	+= $(SOURCES:.c=.dSYM*)
EXTRAS	= $(SOURCES:.c=.exe*)
LIBS		=
LDFLAGS	=
CFLAGS	= -g -ggdb -std=c99 \
				-Wuninitialized -Wunused -Wunused-macros -Wunused-variable \
				-Wunused-function -Wunused-but-set-parameter \
				-Wignored-qualifiers -Wshift-negative-value \
				-Wmain -Wreturn-type \
				-Winit-self -Wimplicit-int -Wimplicit-fallthrough \
				-Wparentheses -Wdangling-else -Wfatal-errors \
				-Wreturn-type -Wredundant-decls -Wswitch-default -Wshadow \
				-Wformat=2 -Wformat-nonliteral -Wformat-y2k -Wformat-security
CFLAGS	+= -ggdb3
#CFLAGS	+= -Wconversion
#CFLAGS	+= -Wc99-c11-compat -Wmaybe-uninitialized \
					-Wformat-truncation=2 -Wstringop-truncation \
					-Wformat-overflow=2 -Wformat-signedness

# Uncomment the LIBS line below containing the library that you're using
#LIBS	= -lcrypto -lgnutls
LIBS	= -lcrypto -lssl

all:	tls

tls:	$(EXECUTABLES)


chatClient5: chatClient5.c $(DEPS)
	$(CC) $(LDFLAGS) $(CFLAGS) $(INCLUDES) $(LDFLAGS) -o $@ $< $(LIBS)

chatServer5: chatServer5.c $(DEPS)
	$(CC) $(LDFLAGS) $(CFLAGS) $(INCLUDES) $(LDFLAGS) -o $@ $< $(LIBS)

directoryServer5: directoryServer5.c $(DEPS)
	$(CC) $(LDFLAGS) $(CFLAGS) $(INCLUDES) $(LDFLAGS) -o $@ $< $(LIBS)


# Clean up the mess we made
.PHONY: clean
clean:
	@-rm -rf $(OBJECTS) $(EXECUTABLES) $(EXTRAS)
