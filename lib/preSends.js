const https = require('https') ;

module.exports = {
  '*' : { index : 0 , proto : https } ,
  opts : [ 
    new URL('https://abc:xyz@example.com')
  ],

}