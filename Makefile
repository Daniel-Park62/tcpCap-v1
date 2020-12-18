debug = NONE
TP_INC = $(TUXDIR)/include
TP_LIB = $(TUXDIR)/lib
CC = gcc
RM = rm -f
CFLAGS = -std=gnu99 -m64 -W -Wall -g -lpthread -D$(debug)
CCINC = -I$(TP_INC) -I/mtzsw/mariadb/include/mysql
LDFLAGS = -L. -L$(TP_LIB) -L/mtzsw/mariadb/lib -lmysqlclient -lwsc -lgpnet -ltux -lfml -lfml32 -lengine

TARGETS = aqt_send aqt_send2 aqt_rnsend

all: $(TARGETS)

aqt_send: aqt_send.c tr_rec.h
		$(CC) $(CFLAGS) $(CCINC) $(LDFLAGS) -o $@ $<

aqt_send2: aqt_send2.c tr_rec.h
		$(CC) $(CFLAGS) $(CCINC) $(LDFLAGS) -o $@ $<
aqt_rnsend: aqt_rnsend.c tr_rec.h
		$(CC) $(CFLAGS) $(CCINC) $(LDFLAGS) -o $@ $<

clean:
	$(RM) *.o $(TARGETS)
