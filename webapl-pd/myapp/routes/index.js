var express = require('express');
var router = express.Router();
var os = require('os');
var https = require('https');
var jwt = require('jsonwebtoken');
var jwksClient = require('jwks-rsa');
var getPem = require('rsa-pem-from-mod-exp');

/* GET home page. */
router.get('/', function(req, res, next) {
    var networkInterfaces = os.networkInterfaces();
    var wk1 = req.headers['cookie'];
    var wk2 = wk1.split(';');
    var cookie = {};
    for (i = 0; i < wk2.length; i++) {
	var [k, v] = wk2[i].split('=');
	cookie[k] = v
    }

    var rh    = req.headers['authorization'];
    var jwtx  = rh.split(" ")[1];
    var token = jwt.decode(jwtx, {complete: true});
    var kid   = token.header['kid'];

    
    var options = {
        hostname: 'dex.labo.local',
        port: 32000,
        path: '/keys',
        method: 'GET',
        rejectUnauthorized: false,
        requestCert: true
    };
    var data = [];
    // JWKSの取得
    https.get(options, function (res2) {
	res2.on('data', function(chunk) {
          data.push(chunk);
      }).on('end', function() {
          var json = JSON.parse(Buffer.concat(data));
	  for(var key of json.keys) {
	      // kid が一致した鍵で検証
	      if (kid == key['kid']) {
		  var pem = getPem(key['n'], key['e']);
		  jwt.verify(jwtx, pem, function(err, decoded) {
		      if (err) {
			  // 検証失敗
			  console.log("verfiy err = ", err);
			  res.render('error', {
			      message: "JWT検証失敗",
			      error: ""
			  });			  
			  
		      } else {
			  // 検証成功
			  console.log("jwt.verify = ",decoded);
			  res.render('index', {
			      title: "POD問題判別用コンテナ",
			      message: "JWT検証成功",
			      hostname: process.env.HOSTNAME,
			      ip: networkInterfaces.eth0[0].cidr,	
			      host: req.headers.host,
			      agent: req.headers['user-agent'],
			      userid: token.payload['email'],
			      env: process.env,
			      headers: req.headers,
			      cookies: cookie
			  });
		      }
		  });
	      }
	  }
      });
    });
    /*
    res.render('index', {
	title: "POD問題判別用コンテナ",
	hostname: process.env.HOSTNAME,
	ip: networkInterfaces.eth0[0].cidr,	
	host: req.headers.host,
	agent: req.headers['user-agent'],
	userid: token.payload['email'],
	env: process.env,
	headers: req.headers,
	cookies: cookie
    });
    */
    

});

module.exports = router;
