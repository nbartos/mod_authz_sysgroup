LIBS=
APXS=apxs

SOURCES=mod_authz_sysgroup.c
# Apache 2.0 uses GNU libtool, hence the libtool suffix
TARGETS=$(SOURCES:.c=.la)

all: $(TARGETS)

# general rule to build
%.la: %.c
	$(APXS) -Wc,-Wall -Wl,-Wall -c $< $(LIBS)

install: $(TARGETS)
	$(APXS) -Wc,-Wall -Wl,-Wall -i $(TARGETS)

clean:
	-rm -f $(TARGETS) *~ $(SOURCES:.c=.slo) $(SOURCES:.c=.lo) $(SOURCES:.c=.so) $(SOURCES:.c=.o) 
	-rm -rf .libs 
