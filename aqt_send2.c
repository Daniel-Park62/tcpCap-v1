/*
AQT TUXEDO TUXEDO SEND
*/

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <pthread.h>
#include <signal.h>
#include <libgen.h>
#include <atmi.h>
#include <error.h>
#include <mysql.h>
#include <stdarg.h>
#include <ctype.h>

#include "tr_rec.h"

#define MAXLN2M 2098152

int LOGprint(char ltype, const char *src_name, const char *func, int , const char*, ...) ;

#define LOGERROR(...) \
  do {\
    LOGprint('E', __FILE__, __func__, __LINE__, ## __VA_ARGS__ ); \
  } while(0)
#define LOGINFO(...) \
	do { \
		LOGprint('I' , __FILE__ , __func__ , __LINE__ , ## __VA_ARGS__ ) ; \
  } while(0)

#define PRINTF(fmt, ...) \
	do { \
		printf("%-30s:%d " fmt "\n" , __func__ , __LINE__ , ## __VA_ARGS__ ) ; \
  } while(0)

#define EPRINTF(fmt, ...) \
	do { \
		fprintf(stderr,"(E) %s:%d " fmt "\n" , __func__ , __LINE__ , ## __VA_ARGS__ ) ; \
  } while(0)

static TPINIT *_tpinfo ;
static TPCONTEXT_T ctx1, ctx2 ;

static struct sigaction act ;

static FILE *rcvfp = NULL ;
static FILE *fp_log = NULL ;
static pid_t fpid = -1;
static pthread_mutex_t _mutx;
static pthread_attr_t p_attr;

static int _iDB = 1;
static int _conn2_OK = 0;
static int _iTimeChk = 0;

static unsigned int _iTotCnt = 0 ;
static unsigned int _iFailCnt = 0 ;
static unsigned int _iFailCnt2 = 0 ;
static unsigned int _iUpdCnt = 0 ;
static unsigned int _iUpdCnt2 = 0 ;

static char* tux_sndbuf = NULL;
static char* tux_rcvbuf = NULL;
static char* tux_rcvbuf2 = NULL;
static char oltp_name[L_TR_CODE +1];

static char _test_code[VNAME_SZ];
static char _conn_label[VNAME_SZ];
static char _test_code2[VNAME_SZ];
static char _conn_label2[VNAME_SZ];
static char _test_date[VNAME_SZ];
static char _test_oltp[VNAME_SZ];
static char _test_oltp[VNAME_SZ];
static char cond_svcid[VNAME_SZ];
static char cond_limit[VNAME_SZ];
static char cond_etc[1024];

static char _tux_env[FNAME_SZ];
static char _tux_info[VNAME_SZ];

static void Usage(void);
static void Closed(void);
static void _Signal_Handler(int sig);
static struct timespec *getStrdate(char *, const int);
static int atoi00(char *, int len);
static int connectDB();
static void closeDB();
static int _Init(int, char **) ;
static int get_target(char * );
static int update_db(unsigned int, char *, long rlen, char *stime, char *rtime, double gap);
static int update_db_fail(nsigned int,  char *stime, char *rtime, char *, double gap);

static void mysql_with_err(MYSQL *) ;
static void time_wait(char *otime) ;

static int init_context(char *conn_label, TPCONTEXT_T * );

static void *second_call(void *);

void Usage(void)
{
  printf(
    "\n Usage : -j 테스트코드 -m 대상서버 [-u 처리건수][-d][-k][-o 서비스] [-e "기타조건"]\n"
    "\t -u : 입력건수만큼 처리\n"
    "\t -d : DB 기록안함\n"
    "\t -k : 기존과 같은시간에 송신\n"
    "\t -n : r서비스 제외\n"
  );
}

void _Signal_Handler(int sig)
{
  sigfillset(&act.sa_mask);
  LOGINFO("SIGNAL(%d) -> [%s][%s] Read:(%d) Fail:(%d)(%d) DB:(%d)(%d)",
          sig, _test_code, _test_code2, _iTotCnt,  _iFailCnt, _iFailCnt2, _iUpdCnt, _iUpdCnt2);
  PRINTF ("SIGNAL(%d) -> [%s][%s] Read:(%d) Fail:(%d)(%d) DB:(%d)(%d)",
          sig, _test_code, _test_code2, _iTotCnt,  _iFailCnt, _iFailCnt2, _iUpdCnt, _iUpdCnt2);
  Closed();
  exit(1) ;
}

int _Init(int argc, char *argv[])
{
  int opt;
  memset(_test_code, 0, sizeof(_test_code)) ;
  memset(_conn_label, 0, sizeof(_conn_label)) ;
  memset(_test_code2, 0, sizeof(_test_code2)) ;
  memset(_conn_label2, 0, sizeof(_conn_label2)) ;
  memset(_test_oltp, 0, sizeof(_test_oltp)) ;
  memset(cond_svcid, 0, sizeof(cond_svcid)) ;
  memset(cond_limit, 0, sizeof(cond_limit)) ;
  memset(cond_etc, 0, sizeof(cond_etc)) ;

  while((opt = getopt(argc, argv, "dhke:j:m:o:u:")) != -1) {
    switch (opt) {
      case 'o':
        strcpy(_test_oltp, optarg) ;
        snprintf(cond_svcid,VNAME_SZ,"and a.svcid like '%s'", _test_oltp) ;
        break;
      case 'e':
        snprintf(cond_etc,VNAME_SZ, "and %s", optarg);
        break;
      case 'u':
        snprintf(cond_limit,VNAME_SZ, "LIMIT %s", optarg);
        break;
      case 'j':
        strcpy(_test_code,optarg);
        break;
      case 'm':
        strcpy(_conn_label,optarg);
        break;
      case 'd':
        _iDB = 0;
        break;
      case 'k':
        _iTimeChk = 1;
        break;
      default:
        return(-1);
    }
  }

  if (_test_code[0] == 0 ) return(1);
  if (_conn_label[0] == 0) {
    if (get_target(_test_code) )  retuen (1) ;
  }

  act.sa_handler = _Signal_Handler ;
  sigemptyset(&act.sa_mask);
  act.sa_flags = 0;
  sigaction(SIGINT, &act, 0);
  sigaction(SIGBUS, &act, 0);
  sigaction(SIGQUIT, &act, 0);
  sigaction(SIGTERM, &act, 0);
  sigaction(SIGABRT, &act, 0);
  sigaction(SIGKILL, &act, 0);
  sigaction(SIGCHLD, &act, 0);

  getStrdate(_test_date, 8);

  if ( (pthread_mutex_init(&_mutx, NULL)) !=0 ){
    EPRINTF("(%s)",strerror(errno));
    return(-1);
  }

  LOGINFO("********************<<  START READ TEST >>*****************");
  LOGINFO("** TEST CODE  [%s][%s]", _test_code, _test_code2);
  LOGINFO("** TARGET     [%s][%s]", _conn_label, _conn_label2);
  LOGINFO("***********************************************************");

  return(0) ;
}


struct timespec *getStrdate(char *str, const int len)
{
  static struct timespec tv;
  struct tm tm1;
  char cTmp[21] = {0,};
  clock_gettime(CLOCK_REALTIME, &tv);
  localtime_r(&tv.tv_sec, &tm1);
  snprintf(cTmp, 21, "%04d%02d%02d%02d%02d%02d%06ld",
          1900+tm1.tm_year, tm1.tm_mon+1, tm1.tm_mday,
          tm1.tm_hour, tm1.tm_min, tm1.tm_sec, tv.tv_nsec / 1000  );
  memcpy(str,cTmp, len > 21 ? 21 : len) ;
  return(&tv) ;
}

void time_wait(char *otime)
{
  struct timespec tv;
  struct tm tm1;
  char ctime[7] ;
  clock_gettime(CLOCK_REALTIME, &tv);
  localtime_r(&tv.tv_sec, &tm1);
  sprintf(ctime,"%02d%02d%02d", tm1.tm_hour, tm1.tm_min, tm1.tm_sec);
  if(memcmp(otime,ctime,6)> 0){
    int hh,mm,ss,tsec=0 ;
    sscanf(otime,"%02d%02d%02d",&hh,&mm,&ss);
    if (ss < tm1.tm_sec ){
      ss += 60;
      mm -= 1;
    }
    tsec = ss - tm1.tm_sec ;
    if (mm < tm1.tm_min){
      mm += 60;
      hh -= 1;
    }
    tsec += (mm - tm1.tm_min)*60;
    tsec += (hh - tm1.tm_hour)*60*60;
    usleep(tsec * 1000000) ;
  }
}
int LOGprint(char ltype, const char *src_name, const char *func, int line_no, const char *fmt, ...)
{
    va_list ap;
    int sz = 0, rc ;
    struct timespec tv;
    struct tm tm1;
    char date_info[256];
    char src_info[256];
    char prt_info[1024];
    char fname[128];

    if (fp_log == NULL) {
      snprintf(fname,sizeof(fname)-1, LOG_PATH "%s_%s_%d.wlog", _test_date, fpid);
      if ((fp_log = fopen(fname,"ab")) == NULL )  return (-1);
    }
    if (_conn2_OK)
      while( (rc = pthread_mutex_trylock(&_mutx)) ) {
        if( rc == EDEADLK ) {
          pthread_mutex_unlock(&_mutx);
          return (-1);
        }
      }

    clock_gettime(CLOCK_REALTIME, &tv);
    localtime_r(&tv.tv_sec, &tm1);

    va_start(ap, fmt);

    snprintf(data_info, sizeof(prt_info)-1, "[%c] %04d%02d%02d:%02d%02d%02d%06ld:%d",
            ltype, 1900+tm1.tm_year, tm1.tm_mon+1, tm1.tm_mday,
            tm1.tm_hour, tm1.tm_min, tm1.tm_sec, tv.tv_nsec / 1000, fpid);

    snprintf(src_info, sizeof(src_info)-1, "%s (%d)", func, line_no);
    vsprintf(prt_info, fmt, ap);
    sz += fprintf(fp_log, "%s:%-25.25s: %s\n", data_info, src_info, prt_info);
    va_end(ap);
    fflush(fp_log);
    if (_conn2_OK) pthread_mutex_unlock(&_mutx);
    return sz;
}

int rcvFileOpen()
{
  char fname[FNAME_SZ] ;
  snprintf(fname, FNAME_SZ-1,LOG_PATH "%s_%s_%d.slog",_test_date, _test_code, fpid) ;
  if ((rcvfp = fopen(fname,"ab")) == NULL) return(-1) ;
  return 1;
}

int connectDB()
{
  conn = mysql_init(NULL) ;
  if ( conn == NULL) {
    EPRINTF("mysql init error");
    return(-1);
  }

  if ( (mysql_real_connect(conn, DBHOST, DBUSER, DBPASS, DBNAME, 13306,"/mtzsw/mariadb/tmp/mysql.sock",0)) == NULL){
    EPRINTF("DB connect error : %s", mysql_error(conn));
    return(-1);
  }

  mysql_autocommit(conn,0);
  return(0);
}

void closeDB()
{
  if(conn) mysql_close(conn);
  conn = NULL;
}

int atoi00(char *str, int len)
{
    char data[21];
    memset(data, 0x00, sizeof(data));
    memcpy(data, str, len);
    return(atoi(data));
}

int get_target(char *test_code )
{
  char cquery[1000];
  memset(cquery,0,sizeof(cquery));
  snprintf(cquery, sizeof(cquery),
          "SELECT a.thost, a.cmpcode, a.lvl, b.thost FROM tmaster a left join tmaster b on (a.cmpcode = b.code) WHERE a.code = '%s'", test_code) ;

  if (mysql_query(conn, cquery)) {
    mysql_with_err(conn) ;
    return(1) ;
  }

  MYSQL_RES *result = mysql_store_result(conn);
  if ( result == NULL) return -1;
  MYSQL_ROW row = mysql_fetch_row(result);
  if (row == NULL){
    EPRINTF("** 테스트코드를 확인하세요.(%s)", test_code);
    return(-1) ;
  }
  unsigned long *len = mysql_fetch_lengths(result);
  memmove(_conn_label, row[0], len[0]);
  memmove(_test_code2, row[1], len[1]);
  memmove(_conn_label2, row[3], len[3]);

  if (len[1] && len[2] && row[2][0] == '2' ) _conn2_OK = 1;

  mysql_free_result(result) ;

  return(0);

}

void mysql_with_err(MYSQL *conn)
{
  LOGERROR("mysql error : %s", mysql_error(conn)) ;
  mysql_close(conn) ;
}


int main(int argc, char *argv[])
{
  char hostname[128];
  char errinfo[121];
  char c_sttime[18];
  char c_ettime[18];
  int slen, tret ;
  long rlen;

  struct timespec stv, etv;

  fpid = getpid();

  strncpy(_tux_env, TUX_ENV_FILE, sizeof(_tux_env));

  if (connectDB()){
    return(1);
  }

  if ( _Init(argc, argv) != 0) {
    Usage();
    Closed();
    return(-1);
  }

  _tpinfo = (TPINIT *)tpalloc("TPINIT",NULL, sizeof(TPINIT));
  if (_tpinfo == NULL){
    EPRINTF("TUX ALLOC : (%d)-[%s]", tperrno, tpstrerror(tperrno));
    Closed();
    return(1);
  }

  memset(hostname,0, sizeof(hostname));
  gethostname(hostname, sizeof(hostname));
  memcpy(_tpinfo->usrname, hostname, strlen(hostname));
  memcpy(_tpinfo->cltname, hostname, strlen(hostname));
  _tpinfo->flags = TPMULTICONTEXTS | TPU_IGN ;

  if (_conn2_OK)
    if( (init_context(_conn_label2, &ctx2)) != 0 ) _conn2_OK = 0;

  if( (init_context(_conn_label, &ctx1)) != 0 ) {
    Closed();
    return(-1);
  }
  tux_sndbuf = tpalloc("CARRAY",NULL,MAXLN2M);
  if (tux_sndbuf == NULL){
    LOGERROR("sendbuf alloc failed[%s]", tpstrerror(tperrno));
    Closed();
    return(-1);
  }
  tux_rcvbuf = tpalloc("CARRAY",NULL,MAXLN2M);
  if (tux_rcvbuf == NULL){
    LOGERROR("sendbuf alloc failed[%s]", tpstrerror(tperrno));
    Closed();
    return(-1);
  }
  if (_conn2_OK) {
    tux_rcvbuf2 = tpalloc("CARRAY",NULL,MAXLN2M);
    if (tux_rcvbuf2 == NULL){
      LOGERROR("sendbuf alloc failed[%s]", tpstrerror(tperrno));
      Closed();
      return(-1);
    }
  }

  TR_REC *srec = (TR_REC *)tux_sndbuf ;
  char query[2048] = {0,};
  if (_conn2_OK)
    snprintf(query,2000, "SELECT a.pkey, a.sdata, DATE_FORMAT(ifnull(a.o_stime,now()) ,'%%H%%i%%s'), b.pkey FROM ttransaction a join ttransaction b "
            " ON (a.svcid = b.svcid and a.uuid = b.uuid) WHERE a.tcode = '%s' AND b.tocde = '%s' %s %s ORDERBY a.o_stime, a.svcid %s ",
            _testcode, _test_code2, cond_svcid, cond_etc, cond_limit
    );
  else
    snprintf(query,2000, "SELECT a.pkey, a.sdata, DATE_FORMAT(ifnull(a.o_stime,now()) ,'%%H%%i%%s') FROM ttransaction a  "
            " WHERE a.tcode = '%s'  %s %s ORDERBY a.o_stime, a.svcid %s ",
            _testcode, cond_svcid, cond_etc, cond_limit
    );
  LOGINFO("%s",query) ;

  if (mysql_real_query(conn, query, strlen(query))){
    mysql_with_err(conn) ;
    Closed();
    return(1);
  }
  MYSQL_RES *result = mysql_store_result(conn) ;
  if (result == NULL){
    mysql_with_err(conn) ;
    Closed();
    return(1);
  }

  MYSQL_ROW row ;
  double dgap;
  pthread_t second_id ;

  while( (row = mysql_fetch_row(result)) ) {
    _iTotCnt++ ;
    unsigned int pkey2 = 0, pkey = atoi(row[0]) ;
    memset(c_sttime, 0 , sizeof(c_sttime));
    memset(c_ettime, 0 , sizeof(c_ettime));
    slen =  atoi00(row[1],8);

    memset(tux_sndbuf, 0 , MAXLN2M);
    memcpy(tux_sndbuf, row[1], slen+8);
    memset(oltp_name,0,sizeof(oltp_name)) ;
    memcpy(oltp_name, srec->tr_code, L_TR_CODE);

    memset(tux_rcvbuf,0, MAXLN2M );
    rlen = 0 ;

    if (_iTimeChk){
      memcpy(c_sttime,row[2],6);
      time_wait(c_sttime) ;
    }

    stv = *getStrdate(c_sttime, 17) ;
    memcpy(srec->mca_req_time, c_sttime+8,9);

    if (( tret = tpsetctxt(ctx1,0)) < 0) {
      LOGERROR("tpsetctxt Error : (%d)-[%s]", tperrno, tpstrerror(tperrno));
      break ;
    }

    if (_conn2_OK) {
      pkey2 = atoi(row[3]) ;
      pthread_create(&second_id, NULL, second_call, (void *)&pkey2);
    }
    if (srec->reply_needed[0] == '1')
      tret = tpcall(oltp_name, tux_sndbuf, slen+8, (char **)&tux_rcvbuf, (long *)&rlen,TPNOFLAGS);
    else
      tret = tpacall(oltp_name, tux_sndbuf, slen+8, TPNOFLAGS);

    etv = *getStrdate(c_ettime,17);
    dgap = (double)( etv.tv_nsec - stv.tv_nsec) / 1000000000 + (etv.tv_sec - stv.tv_sec) ;
    if (tret == -1) {
      memset(errinfo, 0 , sizeof(errinfo))snprintf(errinfo,sizeof(errinfo)-1, "(%d)%s", tperrno,tpstrerror(tperrno));
      LOGERROR("tpcall error %d (id:%d) %s %s", _iTotCnt, pkey, oltp_name, errinfo) ;
      _iFailCnt++ ;
      if (_iDB) update_db_fail(pkey, c_sttime, c_ettime, errinfo, dgap) ;
    } else {
      PRINTF("tpcall %d,%s time(%.6f)",pkey, oltp_name, dgap);
      if (_iDB) update_db(pkey, tux_rcvbuf, rlen, c_sttime, c_ettime,  dgap) ;
    }
    if (_conn2_OK) pthread_join(second_id,NULL);

  } // while loop end

  mysql_free_result(result);
  PRINTF("LOOP END");
  LOGINFO("[%s][%s] Read:(%d) Fail:(%d)(%d) DB:(%d)(%d)",
           _test_code, _test_code2, _iTotCnt,  _iFailCnt, _iFailCnt2, _iUpdCnt, _iUpdCnt2);
  PRINTF ("[%s][%s] Read:(%d) Fail:(%d)(%d) DB:(%d)(%d)",
           _test_code, _test_code2, _iTotCnt,  _iFailCnt, _iFailCnt2, _iUpdCnt, _iUpdCnt2);
  Closed();
  exit(0);
}

void *second_call(void *data)
{
  int slen, tret ;
  long rlen ;
  unsigned int pkey = *(unsigned int*)data ;
  char errinfo[121];
  char c_sttime[18];
  char c_ettime[18];
  struct timespec stv, etv ;

  TR_REC *srec = (TR_REC *)tux_sndbuf ;
  slen = atoi00(tux_sndbuf,8) ;

  memset(c_sttime, 0 , sizeof( c_sttime ) ) ;
  memset(c_ettime, 0 , sizeof( c_ettime ) ) ;
  memset(tux_rcvbuf2, 0 , MAXLN2M ) ;

  stv = *getStrdate(sr_arr[tix].c_sttime,17);

  memcpy(srec->mca_req_time , c_sttime+8, 9) ;

  if (( tret = tpsetctxt(ctx2,0)) < 0) {
    LOGERROR("tpsetctxt Error : (%d)-[%s]", tperrno, tpstrerror(tperrno));
    pthread_exit(NULL) ; ;
  }

  if (srec->reply_needed[0] == '1')
    tret = tpcall(oltp_name, tux_sndbuf, slen+8, (char **)&tux_rcvbuf2, (long *)&rlen,TPNOFLAGS);
  else
    tret = tpacall(oltp_name, tux_sndbuf, slen+8, TPNOFLAGS);

  etv = *getStrdate(c_ettime,17);
  dgap = (double)( etv.tv_nsec - stv.tv_nsec) / 1000000000 + (etv.tv_sec - stv.tv_sec) ;
  if (tret == -1) {
    memset(errinfo, 0 , sizeof(errinfo))snprintf(errinfo,sizeof(errinfo)-1, "(%d)%s", tperrno,tpstrerror(tperrno));
    LOGERROR("tpcall error %d (id:%d) %s %s", _iTotCnt, pkey, oltp_name, errinfo) ;
    _iFailCnt2++ ;
    if (_iDB) update_db_fail2(pkey, c_sttime, c_ettime, errinfo, dgap) ;
  } else {
    PRINTF("tpcall %d,%s time(%.6f)",pkey, oltp_name, dgap);
    if (_iDB) update_db2(pkey, tux_rcvbuf2, rlen, c_sttime, c_ettime,  dgap) ;
  }

  pthread_exit(NULL) ;
}

int init_context(char *conn_label, TPCONTEXT_T *ctx)
{
  if(tuxreadenv(_tux_env, conn_label) < 0 ){
    EPRINTF("tuxreadenv Error : (%s:%s) (%d)-(%s)", _tux_env, conn_label, tperrno, tpstrerror(tperrno)) ;
    return(1) ;
  }

  if ( tpinit(_tpinfo) < 0){
    LOGERROR("tux init Error : (%s) (%d)-(%s)", conn_label, tperrno, tpstrerror(tperrno)) ;
    return(1);
  }
  if ( tpgetctxt(ctx,0) < 0){
    LOGERROR("tux getctxt Error : (%s) (%d)-(%s)", conn_label, tperrno, tpstrerror(tperrno)) ;
    return(1);
  }
  return 0;
}

void Closed()
{
  if ( tux_rcvbuf ) tpfree((char*)tux_rcvbuf) ;
  if ( tux_rcvbuf2 ) tpfree((char*)tux_rcvbuf2) ;
  if ( tux_sndbuf ) tpfree((char*)tux_sndbuf) ;
  pthread_mutex_destroy(&_mutx);

  tpsetctxt(ctx1,0);
  tpterm();
  tpsetctxt(ctx2,0);
  tpterm();

  if (rcvfp) fclose(rcvfp);
  if (fp_log) fclose(fp_log);
  closeDB();
}

inline int update_db(unsigned int pkey, char *rcvdata, long rlen, char *stime, char*rtime, double gap)
{

  char cbuf[MAXLN2M+2048] ;
  char cquery[MAXLN2M+2048] ;
  char msgcode[L_MSG_CODE+1] ;
  char msg[L_MAIN_MSG+100] ;
  int ilen ;
  TR_REC *rrec = (TP_REC *)rcvdata ;

  memset(cquery,0, sizeof(cquery));
  memset(cbuf,0, sizeof(cbuf));
  memset(msg,0, sizeof(msg));
  memset(msgcode,0, sizeof(msgcode));

  memcpy(msgcode, rrec->msg_code, L_MSG_CODE);
  mysql_real_escape_string(conn, cbuf, rcvdata, rlen) ;
  mysql_real_escape_string(conn, msg, rrec->main_msg, L_MAIN_MSG) ;

  ilen = snprintf(cquery,MAXLN2M,
    "UPDATE ttransaction SET rdata = '%.*s' "
    ", stime = STR_TO_DATE('%s', '%%Y%%m%%d%%H%%i%%S%%f')"
    ", rtime = STR_TO_DATE('%s', '%%Y%%m%%d%%H%%i%%S%%f')"
    ", elapsed=%.6f, svctime=%.6f, rlen=%ld"
    ", msgcd='%s', rcvmsg='',sflag='1' "
    " WHERE pkey=%d LIMIT 1" ,
    rlen, cbuf,stime,rtime, gap,gap, rlen, msgcode, pkey) ;

  if( mysql_real_query(conn, cquery,ilen)) {
    LOGERROR("DB error (id:%d)[%d]%s", pkey, mysql_errno(conn), mysql_error(conn));
    if (mysql_errno(conn) == 2006 || mysql_errno(conn) == 1156 || mysql_errno(conn) == 1064 ) mariadb_reconnect(conn) ;
    if (rcvfp == NULL ) rcvFileOpen() ;
    fprintf(rcvfp, "%d^^%s^^%s^^%.6f^^%s^^%ld^^%s@@\n",pkey,stime,rtime,gap,msgcode,rlen,cbuf);
    fflush(rcvfp);
    return(1);
  }

  _iUpdCnt++;
  return(0);
}

inline int update_db_fail(unsigned int pkey,  char *stime, char*rtime, char *errinfo, double gap)
{
  char cquery[MAXLN2M+2048] ;
  int ilen ;

  memset(cquery,0, sizeof(cquery));
  ilen = snprintf(cquery,MAXLN2M,
    "UPDATE ttransaction SET "
    "  stime = STR_TO_DATE('%s', '%%Y%%m%%d%%H%%i%%S%%f')"
    ", rtime = STR_TO_DATE('%s', '%%Y%%m%%d%%H%%i%%S%%f')"
    ", elapsed=%.6f, svctime=%.6f, rlen=0"
    ", errinfo='%s', sflag='2' "
    " WHERE pkey=%d LIMIT 1" ,
     stime,rtime, gap,gap, errinfo, pkey) ;

  if( mysql_real_query(conn, cquery,ilen)) {
    LOGERROR("DB error (id:%d)[%d]%s", pkey, mysql_errno(conn), mysql_error(conn));
    return(1);
  }
  return(0);
}
