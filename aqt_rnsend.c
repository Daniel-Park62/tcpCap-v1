/*
AQT TUXEDO TCP RCV & SEND
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
#include <sys/wait.h>
#include <linux/fcntl.h>

#include "tr_rec.h"

#define MAXLN2M 2098152
#define MAXDATA 100000

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

#define MAX_POOL 1000

static MYSQL *connP[MAX_POOL+1] = {NULL,};
static int pos_dbp = 0;

#define MAX_CTX1 550
#define MAX_CTX2 50

static TPINIT *_tpinfo ;
static TPCONTEXT_T ctx1[MAX_CTX1], ctx2[MAX_CTX2];
static int pos_ctx_1 = 0, pos_ctx_2 = 0;

static struct sigaction act ;

static FILE *fp_log = NULL ;
static pid_t fpid = -1;
static pthread_mutex_t _mutx;
static pthread_attr_t p_attr;

static int _iDB = 1;
static int _iCall = 1;
static int pfd[2] = {0,0};
static char _iRsvc[3] = {0,} ;  // -r 값이들어오면 r서비스 제외
static unsigned int _Thread_c = 0;

static unsigned int _iTotCnt = 0 ;
static unsigned int _iOkCnt = 0 ;
static unsigned int _iOkCnt2 = 0 ;
static unsigned int _iFailCnt = 0 ;
static unsigned int _iFailCnt2 = 0 ;
static unsigned int _iUpdCnt = 0 ;
static unsigned int _iUpdCnt2 = 0 ;

static unsigned int _test_count = 0 ;

static int pid ;

static char _test_code[VNAME_SZ];
static char _conn_label[VNAME_SZ];
static char _test_code2[VNAME_SZ];
static char _conn_label2[VNAME_SZ];
static char _test_date[VNAME_SZ];
static char _test_oltp[VNAME_SZ];

static char _tux_env[FNAME_SZ];
static char _tux_info[VNAME_SZ];

#define SR_ARR_SZ 550
typedef struct {
  int use;
  pthread_t pid;
  char* tux_sndbuf ;
  char* tux_rcvbuf;
  long slen;
  long rlen;
  char oltp_name[L_TR_CODE + 1];
  char otime[18];
  char errinfo[121];
  char c_sttime[18];
  char c_ettime[18];
  double dgap;
} SR_ARR ;
static SR_ARR sr_arr[SR_ARR_SZ];
static int curr_sr_idx = 0;

static void Usage(void);
static void Closed(void);
static void _Signal_Handler(int sig);
static struct timespec *getStrdate(char *, const int);
static int atoi00(char *, int len);
static int connectDB(MYSQL**);
static int _Init(int, char **) ;
static int get_target(char * , char *);
static int update_db(int, char);
static int update_db_fail(int);
static int update_db2(int, char);
static int update_db_fail2(int);
static int init_context(char *conn_label, TPCONTEXT_T **, int);

static void *thread_f1(void *);
static void *thread_f2(void *);
static void th_free() ;

void Usage(void)
{
  printf(
    "\n Usage : aqt_rnsend [-n 건수] [-d | -s] [-r] 기간계코드 정보계코드\n\n"
    "\t -n : 처리건수\n"
    "\t -s : 송신안함\n"
    "\t -d : DB 기록안함\n"
    "\t -n : r서비스 제외\n"
  );
}

int _Init(int argc, char *argv[])
{
  int opt;
  memset(_test_code, 0, sizeof(_test_code)) ;
  memset(_conn_label, 0, sizeof(_conn_label)) ;
  memset(_test_code2, 0, sizeof(_test_code2)) ;
  memset(_conn_label2, 0, sizeof(_conn_label2)) ;
  memset(_test_oltp, 0, sizeof(_test_oltp)) ;

  while((opt = getopt(argc, argv, "dhrsn:")) != -1) {
    switch (opt) {
      case 'n':
        _test_count = atoi(optarg) ;
        break;
      case 'r':
        strcpy(_iRsvc,"-r");
        break;
      case 'd':
        _iDB = 0;
        break;
      case 's':
        _iCall = 0;
        break;
      default:
        return(-1);
    }
  }

  if( !(_iDB || _iCall)) {
    EPRINTF("-d , -s 는 동시에 사용불가합니다.");
    return(-1);
  }

  if(argc <= optind+1)  {
    return (-1);
  }
  strncpy(_test_code, argv[optind++], sizeof(_test_code)-1) ;
  strncpy(_test_code2, argv[optind], sizeof(_test_code2)-1) ;

  if (_iCall) {
    if ( get_target(_test_code, _conn_label)) return(1) ;
    if ( get_target(_test_code2, _conn_label2)) return(1) ;
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
  if(_iCall)  LOGINFO("** TARGET     [%s][%s]", _conn_label, _conn_label2);
  LOGINFO("***********************************************************");

  return(0) ;
}

void _Signal_Handler(int sig)
{
  sigfillset(&act.sa_mask);
  kill(pid, SIGINT);
  close(pfd[0]) ;

  th_free() ;
  LOGINFO("SIGNAL(%d) -> [%s][%s] Read:(%d) Ok:(%d)(%d) Fail:(%d)(%d) DB:(%d)(%d)",
          sig, _test_code, _test_code2, _iTotCnt, _iOkCnt, _iOkCnt2, _iFailCnt, _iFailCnt2, _iUpdCnt, _iUpdCnt2);
  PRINTF ("SIGNAL(%d) -> [%s][%s] Read:(%d) Ok:(%d)(%d) Fail:(%d)(%d) DB:(%d)(%d)",
          sig, _test_code, _test_code2, _iTotCnt, _iOkCnt, _iOkCnt2, _iFailCnt, _iFailCnt2, _iUpdCnt, _iUpdCnt2);
  Closed();
  exit(1) ;
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
      snprintf(fname,sizeof(fname)-1, LOG_PATH "%s_REAL_%d.wlog", _test_date, fpid);
      if ((fp_log = fopen(fname,"ab")) == NULL )  return (-1);
    }
    while( (rc = pthread_mutex_trylock(&_mutx)) ) {
      if( rc == EDEADLK ) {
        pthread_mutex_unlock(&_mutx);
        RETURN -1;
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
    pthread_mutex_unlock(&_mutx);
    return sz;
}

int connectDB(MYSQL **conn)
{
  *conn = mysql_init(NULL) ;
  if ( *conn == NULL) {
    EPRINTF("mysql init error");
    return(-1);
  }

  if ( (mysql_real_connect(*conn, DBHOST, DBUSER, DBPASS, DBNAME, 13306,"/mtzsw/mariadb/tmp/mysql.sock",0)) == NULL){
    EPRINTF("DB connect error : %s", mysql_error(*conn));
    return(-1);
  }

  mysql_autocommit(*conn,0);
  return(0);
}

void initDBPool() {
  for (int i=0; i <= MAX_POOL ; i++){
    connP[i] = mysql_init(NULL);
    if ( connP[i] == NULL) {
      EPRINTF("mysql init error");
      continue ;
    }
    if ( (mysql_real_connect(connP[i], DBHOST, DBUSER, DBPASS, DBNAME, 13306,"/mtzsw/mariadb/tmp/mysql.sock",0)) == NULL){
      EPRINTF("DB connect error : %s", mysql_error(connP[i]));
      continue ;
    }
    mysql_autocommit(*conn,0);
  }
}

MYSQL* getDBconn() {
  pos_dbp++ ;
  if (pos_dbp >= MAX_POOL)  pos_dbp = 0;
  return (connP[pos_dbp]) ;
}

void closeDBPool() {
  for (int i=0; i <= MAX_POOL ; i++){
    if (connP[i]) mysql_close(connP[i]) ;
    connP[i] = NULL;
  }
}

void closeCTXpool() {
  for (int i=0; i <= MAX_CTX1 ; i++){
    tpsetctxt(ctx1[i],0);
    tpterm() ;
  }
  for (int i=0; i <= MAX_CTX2 ; i++){
    tpsetctxt(ctx2[i],0);
    tpterm() ;
  }

}

TPCONTEXT_T getContext1() {
  pos_ctx_1++ ;
  if (pos_ctx_1 >= MAX_CTX1) pos_ctx_1 = 0;
  return (ctx1[pos_ctx_1]);
}
TPCONTEXT_T getContext2() {
  pos_ctx_2++ ;
  if (pos_ctx_2 >= MAX_CTX2) pos_ctx_2 = 0;
  return (ctx2[pos_ctx_2]);
}

int atoi00(char *str, int len)
{
    char data[21];
    memset(data, 0x00, sizeof(data));
    memcpy(data, str, len);
    return(atoi(data));
}

int get_target(char *test_code, char *conn_label)
{
  char cquery[1000];
  memset(cquery,0,sizeof(cquery));
  snprintf(cquery, sizeof(cquery),
          "SELECT a.thost FROM tmaster a WHERE a.code = '%s'", test_code) ;

  MYSQL *conn = NULL;
  connectDB(&conn) ;

  if (mysql_query(conn, cquery)) {
    LOGERROR("%s", mysql_error(conn));
    mysql_close(conn);
    return(1) ;
  }

  MYSQL_RES *result = mysql_store_result(conn);
  if ( result == NULL) return -1;
  MYSQL_ROW row = mysql_fetch_row(result);
  if (row == NULL){
    EPRINTF("** 테스트코드를 확인하세요.(%s)", test_code);
    mysql_close(conn);
    return(-1) ;
  }
  unsigned long *len = mysql_fetch_lengths(result);
  memmove(conn_label, row[0], len[0]);

  mysql_free_result(result) ;
  mysql_close(conn);
  return(0);

}

int get_free()
{
  int rc;
  for (int ix=0; ix < SR_ARR_SZ; ix++){
    curr_sr_idx++ ;
    if(curr_sr_idx >= SR_ARR_SZ) curr_sr_idx = 0;
    if(sr_arr[curr_sr_idx].use == 0){
      sr_arr[curr_sr_idx].use = 1;
      _Thread_c++;
      return curr_sr_idx ;
    }
  }
  return -1;
}

void set_free(int ix)
{
  int rc;
  while( (rc = pthread_mutex_trylock(&_mutx))){
    if (rc == EDEADLK) return ;
    usleep(50000) ;
  }
  sr_arr[ix].use = 0;
  pthread_mutex_unlock(&_mutx) ;
}

void th_free()
{
  PRINTF("th free start");
  for (int chk=0,i=0; i<50; i++){
      for (int ix=0; ix < SR_ARR_SZ; ix++){
        if (sr_arr[ix].use != 2) chk = 1;
        if (sr_arr[ix].use > 0 && i<49) continue ;
        if (sr_arr[ix].tux_sndbuf) tpfree(sr_arr[ix].tux_sndbuf) ;
        if (sr_arr[ix].tux_rcvbuf) tpfree(sr_arr[ix].tux_rcvbuf) ;
        sr_arr[ix].use = 2;
      }
      if(!chk) break ;
      sleep(1);
  }
  PRINTF("th free end");

}

int th_alloc()
{
    for(int ix=0; ix < SR_ARR_SZ; ix++){
      sr_arr[ix].tux_sndbuf = tpalloc("CARRAY",NULL,MAXLN2M);
      if (sr_arr[ix].tux_sndbuf == NULL){
        LOGERROR("sendbuf alloc failed[%s]", tpstrerror(tperrno));
        return(-1);
      }
      sr_arr[ix].tux_rcvbuf = tpalloc("CARRAY",NULL,MAXLN2M);
      if (sr_arr[ix].tux_rcvbuf == NULL){
        LOGERROR("rcvbuf alloc failed[%s]", tpstrerror(tperrno));
        return(-1);
      }
    }
    return 0;
}

int main(int argc, char *argv[])
{
  char hostname[128];
  fpid = getpid();
  int ret ;

  if ( pthread_attr_setdetachstate(&p_attr. PTHREAD_CREATE_DETACHED) != 0){
    perror("pthread detach set error");
    return(1);
  }

  strncpy(_tux_env, TUX_ENV_FILE, sizeof(_tux_env));

  if ( _Init(argc, argv) != 0) {
    Usage();
    Closed();
    return(-1);
  }

  if( pipe(pfd) == -1){
    perror("create pipe error");
    Closed();
    exit(1);
  }

  if (( pid = fork()) == -1){
    perror("fork error");
    Closed();
    exit(1);
  }

  if ( pid == 0) {
    Closed();
    dup2(pfd[1],1);
    close(pfd[0]);
    close(pfd[1]);
    ret = execl("/jjjdsjk/aqtRealrcv.pl","aqtRealrcv.pl",_iRsvc, NULL);
    if(ret == -1)
      perror("execl error");
    else
      wait(NULL) ;
    exit(0);
  }

  close(pfd[1]);

  initDBPool();

  if (_iCall ){
    _tpinfo = (TPINIT *)tpalloc("TPINIT",NULL, sizeof(TPINIT));
    if (_tpinfo == NULL){
      EPRINTF("TUX ALLOC : (%d)-[%s]", tperrno, tpstrerror(tperrno));
      Closed();
      return(1);
    }
  }

  memset(hostname,0, sizeof(hostname));
  gethostname(hostname, sizeof(hostname));
  memcpy(_tpinfo->usrname, hostname, strlen(hostname));
  memcpy(_tpinfo->cltname, hostname, strlen(hostname));
  _tpinfo->flags = TPMULTICONTEXTS | TPU_IGN ;

  if( (init_context(_conn_label, &ctx1, MAX_CTX1)) != 0 ) return(-1);
  if( (init_context(_conn_label2, &ctx2, MAX_CTX2)) != 0 ) return(-1);

  if( th_alloc() == -1){
    Closed();
    return(1);
  }

  if( fcntl(pfd[0], F_SETPIPE_SZ, 1024 * 1024 * 2) < 0) {
    perror("set pipe buffer size failed.");
  }

  char buf1[11];
  int tind;
  ssize_t rsz, d_rsz ;
  int *inp ;

  while(1) {
    memset(buf1,0,11);
    for(int i=0;i<10;i++){
      rsz= read(pfd[0],buf1+i, 1);
      if (rsz < 1) break;
      if(i<9 && ( !isdigit(buf1[i]) || !strchr("12", buf1[0]) ) ){
        i= -1;
        continue ;
      }
      if(i>0 && buf1[1] != '0' || i>1 && buf1[2] != '0'){
        i = -1;
        continue;
      }
      if(i == 9 && buf1[9] != 'R'){
        i = -1;
        continue;
      }
    }
    if (rsz < 1) break ;
    d_rsz = atoi00(buf1+1,8);
    if (d_rsz < 250 || d_rsz >= MAXLN2M){
      continue ;
    }

    do {
      pthread_mutex_lock(&_mutx);
      tind = get_free() ;
      pthread_mutex_unlock(&_mutx);
    } while ( tind == -1 ) ;

    memset(sr_arr[tind].tux_sndbuf,0, d_rsz+10) ;
    memcpy(sr_arr[tind].tux_sndbuf, buf1+1,9) ;
    rsz = read(pfd[0], sr_arr[tind].tux_sndbuf+9, d_rsz-1 );
    if (rsz < 1) break ;
    TR_REC *srec = (TR_REC *)sr_arr[tind].tux_sndbuf ;
    memset(sr_arr[tind].oltp_name,0 , L_TR_CODE+1);
    memcpy(sr_arr[tind].oltp_name, srec->tr_code, L_TR_CODE) ;
    memset(sr_arr[tind].uuid,0 , L_UUID+1);
    memcpy(sr_arr[tind].uuid, srec->uuid, L_UUID) ;

    if( strlen(sr_arr[tind].oltp_name) != 15 || strchr( sr_arr[tind].oltp_name,' ') != NULL || strchr( sr_arr[tind].oltp_name,'_') == NULL) {
      sr_arr[tind].use = 0 ;
      _Thread_c-- ;
      continue ;
    }

    inp = (int *)malloc(sizeof(int));
    *inp = tind ;
    _iTotCnt++ ;

    if (buf1[0] == '1')
      pthread_create(&sr_arr[tind].pid, &p_attr, thread_f1, (void *)inp) ;
    else
      pthread_create(&sr_arr[tind].pid, &p_attr, thread_f2, (void *)inp) ;

    if ( _iTotCnt / 1000 * 1000 == _iTotCnt )
      LOGINFO("*** read count:(%d) Fail:(%d)(%d) DBUpdate:(%d)(%d)", _iTotCnt, _iFailCnt, _iFailCnt2, _iUpdCnt, _iUpdCnt2) ;
  } // while loop end

  PRINTF("LOOP END");
  wait(NULL) ;
  close(pfd[0]);
  th_free() ;
  LOGINFO("[%s][%s] Read:(%d) Ok:(%d)(%d) Fail:(%d)(%d) DB:(%d)(%d)",
           _test_code, _test_code2, _iTotCnt, _iOkCnt, _iOkCnt2, _iFailCnt, _iFailCnt2, _iUpdCnt, _iUpdCnt2);
  PRINTF ("[%s][%s] Read:(%d) Ok:(%d)(%d) Fail:(%d)(%d) DB:(%d)(%d)",
           _test_code, _test_code2, _iTotCnt, _iOkCnt, _iOkCnt2, _iFailCnt, _iFailCnt2, _iUpdCnt, _iUpdCnt2);
  Closed();
  exit(0);
}

void *thread_f1(void *data)
{
  int slen, tret, tix = *(int*)data ;
  free(data);

  char tmpc[128] = {0,};
  struct timespec stv, etv ;

  TR_REC *srec = (TR_REC *)sr_arr[tix].tux_sndbuf ;
  memset(sr_arr[tix].c_sttime, 0 , sizeof( sr_arr[tix].c_sttime ) ) ;
  memset(sr_arr[tix].c_ettime, 0 , sizeof( sr_arr[tix].c_ettime ) ) ;
  memset(tmpc, 0 sizeof(tmpc)) ;
  memcpy(tmpc,srec,8);
  slen = atoi(tmpc) ;
  sr_arr[tix].slen = slen ;
  sr_arr[tix].rlen = 0 ;

  stv = *getStrdate(sr_arr[tix].c_sttime,17);
  memcpy(sr_arr[tix].otime , sr_arr[tix].c_sttime, 8) ;
  memcpy(sr_arr[tix].otime+8 , srec->mca_req_time, 9) ;
  memcpy(srec->mca_req_time , sr_arr[tix].c_sttime+8, 9) ;

  if (_iCall){
    tret = tpsetctxt(ctx1[tix]),0);
    if (tret < 0){
      LOGERROR("tpsetctxt eRROR : (%s)(%d)-[%s]",_conn_label, tperrno, tpstrerror(tperrno)) ;
    }  else{
      if (srec->reply_needed[0] == '1')
        tret = tpcall(sr_arr[tix].oltp_name, sr_arr[tix].tux_sndbuf, slen+8, (char **)&sr_arr[tix].tux_rcvbuf, (long *)&sr_arr[tix].rlen,TPNOFLAGS);
      else
        tret = tpacall(sr_arr[tix].oltp_name, sr_arr[tix].tux_sndbuf, slen+8, TPNOREPLY|TPNOFLAGS);

      etv = *getStrdate(sr_arr[tix].c_ettime,17);
      sr_arr[tix].dgap = (double)( etv.tv_nsec - stv.tv_nsec) / 1000000000 + (etv.tv_sec - stv.tv_sec) ;
      memset( sr_arr[tix].errinfo, 0 , sizeof(sr_arr[tix].errinfo)) ;

      if (tret == -1 ){
        snprintf(sr_arr[tix].errinfo, sizeof(sr_arr[tix].errinfo)-1, "(%d)%s no:%d",tperrno, tpstrerror(tperrno),_iTotCnt);
        _iFailCnt++ ;
        update_db_fail(tix) ;
      } else {
        PRINTF("tpcall success %s time(%.6f)[%d]", sr_arr[tix].oltp_name,sr_arr[tix].dgap,_Thread_c ) ;
        _iOkCnt++ ;
        if (_iDB){
          update_db(tix,'1') ;
        }
      }
    }
  } else {  // if (_iCall)
    memcpy(sr_arr[tix].c_ettime , sr_arr[tix].c_sttime, 17);
    update_db(tix,'0');
    PRINTF("update db []%s](%d)", sr_arr[tix].oltp_name, tix);
  }

  sr_arr[tix].pid = 0;
  sr_arr[tix].use = 0;
  _Thread_c-- ;

  pthread_exit(NULL) ;
}

void *thread_f2(void *data)
{
  int slen, tret, tix = *(int*)data ;
  free(data);

  char tmpc[128] = {0,};
  struct timespec stv, etv ;

  TR_REC *srec = (TR_REC *)sr_arr[tix].tux_sndbuf ;
  memset(sr_arr[tix].c_sttime, 0 , sizeof( sr_arr[tix].c_sttime ) ) ;
  memset(sr_arr[tix].c_ettime, 0 , sizeof( sr_arr[tix].c_ettime ) ) ;
  memset(tmpc, 0 sizeof(tmpc)) ;
  memcpy(tmpc,srec,8);
  slen = atoi(tmpc) ;
  sr_arr[tix].slen = slen ;
  sr_arr[tix].rlen = 0 ;

  stv = *getStrdate(sr_arr[tix].c_sttime,17);
  memcpy(sr_arr[tix].otime , sr_arr[tix].c_sttime, 8) ;
  memcpy(sr_arr[tix].otime+8 , srec->mca_req_time, 9) ;
  memcpy(srec->mca_req_time , sr_arr[tix].c_sttime+8, 9) ;

  if (_iCall){
    tret = tpsetctxt(ctx2[tix]),0);
    if (tret < 0){
      LOGERROR("tpsetctxt eRROR : (%s)(%d)-[%s]",_conn_label2, tperrno, tpstrerror(tperrno)) ;
    }  else{
      if (srec->reply_needed[0] == '1')
        tret = tpcall(sr_arr[tix].oltp_name, sr_arr[tix].tux_sndbuf, slen+8, (char **)&sr_arr[tix].tux_rcvbuf, (long *)&sr_arr[tix].rlen,TPNOFLAGS);
      else
        tret = tpacall(sr_arr[tix].oltp_name, sr_arr[tix].tux_sndbuf, slen+8, TPNOREPLY|TPNOFLAGS);

      etv = *getStrdate(sr_arr[tix].c_ettime,17);
      sr_arr[tix].dgap = (double)( etv.tv_nsec - stv.tv_nsec) / 1000000000 + (etv.tv_sec - stv.tv_sec) ;
      memset( sr_arr[tix].errinfo, 0 , sizeof(sr_arr[tix].errinfo)) ;

      if (tret == -1 ){
        snprintf(sr_arr[tix].errinfo, sizeof(sr_arr[tix].errinfo)-1, "(%d)%s no:%d",tperrno, tpstrerror(tperrno),_iTotCnt);
        _iFailCnt2++ ;
        update_db_fail2(tix) ;
      } else {
        PRINTF("tpcall success %s time(%.6f)[%d]", sr_arr[tix].oltp_name,sr_arr[tix].dgap,_Thread_c ) ;
        _iOkCnt2++ ;
        if (_iDB){
          update_db2(tix,'1') ;
        }
      }
    }
  } else {  // if (_iCall)
    memcpy(sr_arr[tix].c_ettime , sr_arr[tix].c_sttime, 17);
    update_db2(tix,'0');
    PRINTF("update db []%s](%d)", sr_arr[tix].oltp_name, tix);
  }

  sr_arr[tix].pid = 0;
  sr_arr[tix].use = 0;
  _Thread_c-- ;

  pthread_exit(NULL) ;
}

int init_context(char *conn_label, TPCONTEXT_T **ctx, int sz)
{
  if(tuxreadenv(_tux_env, conn_label) < 0 ){
    EPRINTF("tuxreadenv Error : (%s:%s) (%d)-(%s)", _tux_env, conn_label, tperrno, tpstrerror(tperrno)) ;
    return(1) ;
  }

  for (int i=0; i < sz ; i++){
    if ( tpinit(_tpinfo) < 0){
      LOGERROR("tux init Error : (%s) (%d)-(%s)", conn_label, tperrno, tpstrerror(tperrno)) ;
      return(1);
    }
    if ( tpgetctxt(&ctx[i],0) < 0){
      LOGERROR("tux getctxt Error : (%s) (%d)-(%s)", conn_label, tperrno, tpstrerror(tperrno)) ;
      return(1);
    }
  }
  return 0;
}

void Closed()
{
  if (_iCall) closeCTXpool() ;
  pthread_mutex_destroy(&_mutx);
  pthread_attr_destroy(&p_attr);
  if (fp_log) fclose(fp_log);
  closeDBPool();
}

inline int update_db(int tix, chaar sflag)
{
  char sdata[MAXLN2M+2048] ;
  char rdata[MAXLN2M+2048] ;
  char cquery[MAXLN2M+2048] ;
  char msgcode[L_MSG_CODE+1] ;
  int ilen ;
  TR_REC *srec = (TP_REC *)sr_arr[tix].tux_sndbuf ;
  TR_REC *rrec = (TP_REC *)sr_arr[tix].tux_rcvbuf ;
  pos_dbp++ ;
  if (pos_dbp >= MAX_POOL) pos_dbp = 0 ;
  MYSQL *conn = connP[pos_dbp];

  memset(cquery,0, sizeof(cquery));
  memset(msgcode,0, sizeof(msgcode));
  for (int i=L_UUID-1;i>=0;i--)  if(*(sr_arr[tix].uuid+i) == ' ') *(sr_arr[tix].uuid+i) = 0; else break ;
  if(strlen(sr_arr[tix].uuid) == 0) strcpy(sr_arr[tix].uuid,"ABCD1234");

  ilen = (sr_arr[tix].slen+8 > MAXLN2M ? MAXLN2M : sr_arr[tix].slen+8);
  mysql_real_escape_string(conn, sdata, sr_arr[tix].tux_sndbuf, ilen) ;

  if (sr_arr[tix].rlen > 0){
    ilen = (sr_arr[tix].rlen > MAXLN2M ? MAXLN2M : sr_arr[tix].rlen );
    mysql_real_escape_string(conn, rdata, sr_arr[tix].tux_rcvbuf, ilen) ;
    memmove(msgcode, rrec->msg_code, L_MSG_CODE);
  }
  ilen = snprintf(cquery,MAXLN2M,
    "INSERT INTO ttransaction (uuid, tcode, svrnm,svcid,o_stime,stime,rtime,userid,clientip,"
    " scrno,msgcd, rcvmsg, errinfo, sflag, elapsed, svctime, slen, rlen,cdate, sdata,rdata) "
    " VALUES('%s','%s','','%s',STR_TO_DATE('%s','%%Y%%m%%d%%H%%i%%S%%f'),STR_TO_DATE('%s','%%Y%%m%%d%%H%%i%%S%%f'),STR_TO_DATE('%s','%%Y%%m%%d%%H%%i%%S%%f')"
    ", '%.20s','%.39s','%s','%s','%s','%s','%c',%.6f,%.6f,%ld,%ld,NOW(),'%s','%s') "
    , sr_arr[tix].uuid,_test_code, sr_arr[tix].oltp_name, sr_arr[tix].otime, sr_arr[tix].c_sttime, sr_arr[tix].c_ettime
    , srec->userid, srec->clientip, srec->scrno, msgcode, srec->msg, '', sflag, sr_arr[tix].dgap, sr_arr[tix].dgap, sr_arr[tix].slen, sr_arr[tix].rlen
    , sdata, rdata ) ;

  if (mysql_real_query(conn, cquery, ilen)) {
    LOGERROR("Insert error (%s)[%d]%s [%d]", sr_arr[tix].uuid, mysql_errno(conn), mysql_error(conn), ilen);
    if (mysql_errno(conn) == 2006 || mysql_errno(conn) == 1156 || mysql_errno(conn) == 1064 ) mariadb_reconnect(conn) ;
  } else {
    _iUpdCnt++;
  }

  return(0);
}
