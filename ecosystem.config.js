module.exports = {
  apps : [{
    script: './aqt_execjob.js',
    log_date_format : 'MM/DD HH:mm:ss' ,
    watch: true
  }, {
    script: './aqt_resend.js',
    log_date_format : 'MM/DD HH:mm:ss' ,
    watch: true
  }],

};
