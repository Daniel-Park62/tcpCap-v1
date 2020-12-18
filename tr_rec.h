/*
* 전문 LAYOUT
*/

#ifndef _TR_REC_H
#define _TR_REC_H

#define L_PACKET_LENGTH     8
#define L_REPLY_NEEDED      1
#define L_UUID              32
#define L_TR_CODE           15
#define L_MSG_CODE          4

typedef struct {
  char packet_length [L_PACKET_LENGTH] ;
  char reply_needed   [L_REPLY_NEEDED];
  char uuid           [L_UUID];
  char tr_code        [L_TR_CODE];
  char msg_code       [L_MSG_CODE];
} TR_REC ;

#define TUX_ENV_FILE "bla bla"
#define LOG_PATH "bla bla"

#define VNAME_SZ  128
#define FNAME_SZ  256

#define DBHOST  "localhost"
#define DBUSER  "aqtdb"
#define DBNAME  "aqtdb"
#define DBPASS  "Dadsjhdshj"


#endif
