// Module dependencies.
require('newrelic');
var app = require('express')();
var server = require('http').Server(app);
var io = require('socket.io')(server);
var session = require('express-session')
var bodyParser = require('body-parser') 
var cookieParser = require('cookie-parser')
var forge = require('node-forge')
var mongoskin = require('mongoskin')

// default to a 'localhost' configuration:
var connection_string = '@localhost:27017/chitchat';
// if OPENSHIFT env variables are present, use the available connection info:
if(process.env.OPENSHIFT_MONGODB_DB_PASSWORD){
  connection_string = process.env.OPENSHIFT_MONGODB_DB_USERNAME + ":" +
  process.env.OPENSHIFT_MONGODB_DB_PASSWORD + "@" +
  process.env.OPENSHIFT_MONGODB_DB_HOST + ':' +
  process.env.OPENSHIFT_MONGODB_DB_PORT + '/' +
  process.env.OPENSHIFT_APP_NAME;
}

var db = mongoskin.db('mongodb://'+connection_string, {safe:true})
var collections = ["accounts"];


var keyManageJS = require('./crypto/key-management.js')
var aes = require('./crypto/aes-encryption.js')
var rsa = require('./crypto/rsa-encryption.js')


//generate an rsa keypair
var keyManager = new KeyManagement();
keyManager.generateRSAKeyPair();




//storing currently logged user information
var users = [];
var openSockets = [];
var pendingLogins = [];
var onlineUserList = [];
var userCount = 0;


//configuring app settings
app.set('port', process.env.PORT || 3000);
app.use(bodyParser.json()); 
app.use(bodyParser.urlencoded({ extended: true }));
app.use(cookieParser())
app.use(session({secret: 'test'}));

//ejs views
 
// Using the .html extension instead of
// having to name the views as *.ejs
app.engine('.html', require('ejs').__express);

 
// Set the folder where the pages are kept
app.set('views', __dirname + '/views');
 
// This avoids having to provide the 
// extension to res.render()
app.set('view engine', 'html');


//defining routes

app.get('/\/|\/index.html/' , function(req , res , next){
    cookieHandler.storePubCookie(keyManager.getServerPublicKey() , req , res);
    //if(req.cookies.user==req.session.uid){
    //  res.render('chat' , {
    //      userId:forge.util.decode64(req.cookies.user) , 
    //      onlineUserList : onlineUserList
    //    });
    //}else{
            res.render('index');

    //}
})

app.get('/*.*' , function(req , res , next){
    var fileName = req.path;
    //console.log(req.path);
    //console.log(process.env.OPENSHIFT_REPO_DIR+'/'+req.path);
    res.sendfile(__dirname +'/'+ fileName);
})

app.get('/' , function(req , res , next){
	cookieHandler.storePubCookie(keyManager.getServerPublicKey() , req , res);
	res.render('index');
})


app.get('/chat' , function(req , res , next){
	
	if(onlineUserList.indexOf(req.cookies.user)>=0 || pendingLogins.indexOf(req.cookies.user)>=0)
		console.log("logged in")
    if(req.cookies.user==req.session.uid && req.cookies.auth == req.session.uniqueId){
        res.render('chat', {
            userId:forge.util.decode64(req.session.uid) 
          });
        //next();
    }else{
        console.log("You must be logged in")
        res.render('login')
        //next();
    }
    
})

app.get('/logout' , function(req , res , next){
	var user = req.session.uid;

})

app.post('/*' , function(req , res , next){
    if(req.cookies.user==req.session.uid && req.cookies.auth == req.session.uniqueId){
        next();
    }else{
        next();
    }
})

//registration router
app.post('/register', function (req, res, next) {
    var reg = new Register();
    reg.post(req, res);
});

//login router
app.post('/login', function(req , res , next){
    var login = new Login();
    login.post(req , res);
})

app.post('/login/:id', function(req , res , next){
    var client = null;
    for (var i = pendingLogins.length - 1; i >= 0; i--) {
        if(pendingLogins[i].id == req.param("id") && pendingLogins[i].secret == JSON.parse(req.body.data).secret_key){
            client = pendingLogins[i];
            break;
        }
    };
    if(client==null){
        res.status(401);
        res.end();
    }
    else{
        var log = new Login();
        log.verify(client , req , res);
    }
    
})

var server_port = process.env.OPENSHIFT_NODEJS_PORT || 80
var server_ip_address = process.env.OPENSHIFT_NODEJS_IP || '127.0.0.1'

server.listen(server_port, server_ip_address, function () {
  console.log( "Listening on " + server_ip_address + ", server_port " + server_port )
});



function createHash(data , key){
    var md = forge.md.sha1.create();
    md.update(data);
    return keyManager.getServerPrivateKey().sign(md);
}

//verifies the hash of the incoming message
function verifyHash(hash , message , pubKey){
    
    //pubKey = forge.pki.setRsaPublicKey(new forge.jsbn.BigInteger(pubKey.n) , new forge.jsbn.BigInteger(pubKey.e));
    try{
        var md = forge.md.sha1.create();
        md.update((message));
        var success = pubKey.verify(md.digest().getBytes() , hash);
        return success;
    }
    catch(err){
        return false;
    }

}

//verify that the client is actually authenticated
function verifyClient(client){

}

//get clients by id
function getClientById(id){
    var count = users.length;
    var client = null;
    for(var i=0;i<count;i++){
        
        if(users[i].userId==id){
            client = users[i];
            break;
        }
    }
    return client;
}


//get sockets by id
function getSocketById(id){
    var count = openSockets.length;
    var socket = null;
    for(var i=0;i<count;i++){
        
        if(openSockets[i].id==id){
            socket = openSockets[i];
            break;
        }
    }
    return socket;
}

function getSocket(socket){
    var count = openSockets.length;
    var s = null;
    for(var i=0;i<count;i++){
        if(openSockets[i].socket==socket){
            s = openSockets[i];
            break;
        }
    }
    return s;
}

/*
    -The actual chat send/receive management
    -Uses socket.io for all types of chats
    -The public chat
    -The group chat
    -Instant message
*/
io.use(function(socket, next) {
  var handshakeData = socket.request;
    var user_cookie = socket.request.headers.cookie['user'];
    var auth_cookie = socket.request.headers.cookie['auth'];

  next();
});


io.on('connection', function (socket) {
  /*
    This block deals with the public chat only.
    All the functions are applicable for public chat module
  */
    socket.emit('welcome', {online : onlineUserList});  //send welcome handshake message
    onlineUserList.push({id:socket.request._query['user']});

    io.emit('new user' , forge.util.encode64(socket.request._query['user']));   

    socket.on('chat key send' , function(data){
        try{
            var client = getClientById(data.id);
            if(client == null)      {
                console.log("no user found")
                return;
            }
            openSockets.push({id:data.id , socket:socket});
            var sessionKey = client.sessKey;
            var key = keyManager.getPublicChatKey().key;
            var iv = keyManager.getPublicChatKey().iv;
            var resp = "{\"key\":\""+forge.util.encode64(key)+"\",\"iv\":\""+forge.util.encode64(iv)+"\"}";
            resp = AESEncryption.encrypt(resp , sessionKey)
                
            socket.emit('chat key receive' , {response : resp})
        }catch(err){
            console.log("Chat key send failed");
            console.log(err);
        }
        

    })

    socket.on('new message', function (data) {
    	console.log(data.hash);
    	//var user = data.user;
    	//var client = getClientById(user);
    	//var pubKey = 
        io.emit('receive message' , data);
    });


    socket.on('disconnect',function(){
    	//io.emit('user disconnect' , {id:id});
        try{
            var s = getSocket(socket);
            var i = openSockets.indexOf(s);
            var id = openSockets[i].id;
            var user = getClientById(id);
            users.splice(users.indexOf(user),1);
            openSockets.splice(i, 1)
            onlineUserList.splice(onlineUserList.indexOf(id) , 1);
            io.emit('user disconnect' , {id:id});
        }catch(err){
            console.log(err);
        }
        
    })

    /*
        This block deals with the private chat only.
        All the functions are applicable for private chat module
    */

    socket.on('instant message handshake send' , function(data){
        try{
            var recipient = data.recipient_id;
            var sender = data.sender_id;
            var recipientClient = getClientById(recipient);
            if(recipientClient!=null){
                socket.emit('instant message handshake receive' , {id:recipient , pk:recipientClient.publicKey , hash:createHash(recipientClient.publicKey,keyManager.getServerPrivateKey())})
            }

        }catch(err){
            console.log(err);
        }
        
    })

    socket.on('instant message chat key send' , function(data){
        try{
            var s = getSocketById(data.id);
            s.socket.emit('instant message chat key receive' , data);

        }catch(err){
            console.log(err);

        }
        
    })

    socket.on('send instant message' , function(data){
        try{
            var recipient = data.receiver_id;
            var sender = data.sender_id;
            var recipientClient = getClientById(recipient);
            if(recipientClient!=null){
                var s = getSocketById(recipient);
                s.socket.emit('receive instant message' , data);
            }

        }catch(err){
             console.log(err);

        }
        
    })


    /*
        This block deals with the group chat only.
        All the functions are applicable for group chat module
    */

    socket.on('group message handshake send' , function(data){
        try{
                var recipient = data.recipient_id;
                var sender = data.sender_id;
                var response = [];
                for (var i = recipient.length - 1; i >= 0; i--) {
                    var client = getClientById(recipient[i]);
                    if(client!=null){
                        response.push({rid:recipient[i] , pk:client.publicKey});
                    }
                };
                socket.emit('group message handshake receive' , {resp:response , chat_id:data.chat_id , name:data.name})


        }catch(err){
                        console.log(err);

        }
        
        
    })

    socket.on('group message chat key send' , function(data){
        try{
            var recipients = data.resp;
            for (var i = recipients.length - 1; i >= 0; i--) {
                var s = getSocketById(recipients[i].id);
                s.socket.emit('group message chat key receive' , data);
            };

        }catch(err){
            console.log(err);

        }
        
    })

    socket.on('send group message' , function(data){
        try{

            var recipient = data.receiver_id;
            var sender = data.sender_id;
            for (var i = recipient.length- 1; i >= 0; i--) {
                var s = getSocketById(recipient[i]);
                if(s!=null){
                    s.socket.emit('receive group message' , data);
                }
             };

        }catch(err){
            console.log(err);

        }
        
    })
    
});



/*
    The register module-used to manage new user sign up
*/

Register = function (){
    var self = this;
    self.post = function(req , res) {
        var valid = self.verify(req.body);
        //user successfully validated
        //console.log(req.data);
        if(valid){
            var user = self.storeUserSession(req.body.data);
            self.writeUserDetailsToDB(req.body.data);
            self.createResponse(user, req , res);
            return;
        }else{
            res.status(400).end();
        }
        
    }

    self.verify = function(data){
        try{
        	
            var parsedJSON = data;
           // console.log(parsedJSON.data);
            var sign = parsedJSON.data.sign;
            var digest = parsedJSON.data.digest;
            var user_id = parsedJSON.data.user_id;
            var email = parsedJSON.data.email;
            var public_key = parsedJSON.data.public_key;
            var private_key = parsedJSON.data.private_key;
            var hash = forge.util.decode64(parsedJSON.hash);
            //data = delete hash;
            public_key = forge.pki.setRsaPublicKey(new forge.jsbn.BigInteger(public_key.n) , new forge.jsbn.BigInteger(public_key.e));
            return verifyHash(hash , parsedJSON.data , public_key) && RSAencryption.verify(digest , sign , public_key);
        }catch(err){
            return false;
        }
        
    }

    self.createResponse = function(user , req , res){
        try{
            cookieHandler.storeAuthCookie(user.userId , req , res);
            cookieHandler.storePubCookie(keyManager.getServerPublicKey() , req , res)

            var publicChatKey = keyManager.getPublicChatKey();

            var response = "{\"session_key\":\""+forge.util.encode64(user.sessKey.key)+"\" , \"session_iv\":\""+forge.util.encode64(user.sessKey.iv)+"\"}";//, session_key:user.sessKey}"
            var clientPublicKey = forge.pki.setRsaPublicKey(new forge.jsbn.BigInteger(user.publicKey.n) , new forge.jsbn.BigInteger(user.publicKey.e));
            var encryptedResponse = RSAencryption.encrypt(response , clientPublicKey ,user.userId);

            res.json({resp:encryptedResponse})
            res.end();
        }catch(err){
            res.status(500);
        }
        
    }

    self.storeUserSession=function(data){
        var count = userCount;
        var user = new client();

        user.setUserId(data.user_id);
        user.setEmail(data.email);
        user.setPublicKey(data.public_key);
        user.setPrivateKey(data.private_key);
        var uniqueId = 'xxxxxxxx-xxxx-4xxx-yxxx-xxxxxxxxxxxx'.replace(/[xy]/g, function(c) {
                var r = Math.random()*16|0, v = c == 'x' ? r : (r&0x3|0x8);
                return v.toString(16);
                    //alert(unique_url);
             });

        user.setRandomKey(uniqueId);
        var sessKey = keyManager.generateAESKey();
        user.setSessionKey(sessKey);

        users.push(user);
        userCount += 1;
        //onlineUserList.push({id:forge.util.decode64(data.user_id)});
        
        return user;
    }

    self.writeUserDetailsToDB=function(data){
        var success = databaseHandler.save('accounts' , data)
        if(success==true){
            
        }
        else{
            
        }
    }
}


Login = function(){
    var self = this;

    self.post = function(req , res){
        try{
            var collection = db.collection('accounts');
            collection.find({"user_id":req.body.id},{"private_key":1,"public_key":1,_id:0}).limit(1).toArray(function(err,data){
            	if(err)
            	{
            		res.status(404 , "No such user exists");
                    res.end();
                    return;
               	}
               
            var secretKey = 'xxxxxxxx-xxxx-4xxx-yxxx-xxxxxxxxxxxx'.replace(/[xy]/g, function(c) {
                var r = Math.random()*16|0, v = c == 'x' ? r : (r&0x3|0x8);
                return v.toString(16);
                //alert(unique_url);
            });
            var resp = "{\"secret_key\":\""+secretKey+"\"}";
            resp = RSAencryption.encrypt(resp , forge.pki.setRsaPublicKey(new forge.jsbn.BigInteger(data[0].public_key.n) , new forge.jsbn.BigInteger(data[0].public_key.e)));
            var response = JSON.parse("{\"response\":\""+forge.util.encode64(resp)+"\",\"public_key_e\":\""+data[0].public_key.e+"\",\"public_key_n\":\""+data[0].public_key.n+  "\",\"private_key\":\""+data[0].private_key+"\"}");
            var hash = createHash(response , keyManager.getServerPrivateKey());
            pendingLogins.push({id:req.body.id , secret:secretKey , data:data});
            res.json({data:response , hash:hash});
            res.end();
            });
        }catch(err){
            res.status(500 );
            res.end();
        }
        
            
    }

    self.verify = function(client , req , res){

        try{
            var pubKey = forge.pki.setRsaPublicKey(new forge.jsbn.BigInteger(client.data[0].public_key.n) , new forge.jsbn.BigInteger(client.data[0].public_key.e))
            
            if(verifyHash(req.body.hash , req.body.data , pubKey )){
                self.createResponse(client , req , res);
            }else{
                res.status(400 , "Bad Request");
                res.end();
            }
        }catch(err){
            res.status(404,"No such user exists")
        }
        
    }   

    self.createResponse = function(client , req , res){
        cookieHandler.storeAuthCookie(client.id , req , res);
        try{
            var user = self.storeUserSession(client);
            var response = "{\"session_key\":\""+forge.util.encode64(user.sessKey.key)+"\" , \"session_iv\":\""+forge.util.encode64(user.sessKey.iv)+"\"}";//, session_key:user.sessKey}"
            var pubKey = forge.pki.setRsaPublicKey(new forge.jsbn.BigInteger(user.publicKey.n) , new forge.jsbn.BigInteger(user.publicKey.e))
            var encryptedResponse = RSAencryption.encrypt(response , pubKey ,client.id);
            var hash = createHash(encryptedResponse , keyManager.getServerPrivateKey())
            res.status(200);
            res.json({resp:encryptedResponse , hash:hash})
            res.end();
        }catch(err){
            res.status(500,"An internal server error occured. Please try again")
            res.end();
        }
    }

    self.storeUserSession=function(data){
        var count = userCount;
        var user = new client();

        user.setUserId(data.id);
        user.setEmail(data.email);
        user.setPublicKey(data.data[0].public_key);
        user.setPrivateKey(data.private_key);
        var uniqueId = 'xxxxxxxx-xxxx-4xxx-yxxx-xxxxxxxxxxxx'.replace(/[xy]/g, function(c) {
                var r = Math.random()*16|0, v = c == 'x' ? r : (r&0x3|0x8);
                return v.toString(16);
                    //alert(unique_url);
             });

        user.setRandomKey(uniqueId);
        var sessKey = keyManager.generateAESKey();
        user.setSessionKey(sessKey);

        users.push(user);
        userCount += 1;
        pendingLogins = pendingLogins.filter(function (el) {
                        return el.id !== data.id;
                       });
        //onlineUserList.push({id:forge.util.decode64(data.id)});

        return user;
    }

}

/*
    CookieHandler module-used to manage cookies
*/




cookieHandler = function(){
}

//Verify cookies sent by user request
cookieHandler.verifyCookies = function(req , res){
    res.cookie('user' , "" , {expires: new Date(Date.now()) });
    res.cookie('auth' , "" , {expires: new Date(Date.now()) });
}

//Send server public key as cookie
cookieHandler.storePubCookie = function(serverPublicKey , req , res){
    //the user is not new
        var cookie = "{\"n\":\""+serverPublicKey.n+"\" , \"e\":\""+serverPublicKey.e+"\"}";
        res.cookie('pub_key',cookie, {httpOnly: false });
        return;
        if(req.cookies.pub_key){
            return;
        }else{
            res.cookie('pub_key', forge.util.encode64({n:serverPublicKey.n , e:serverPublicKey.e}), { expires: new Date(Date.now() + 900000), httpOnly: false });
            return;
        }


}

//Store authentication cookies
cookieHandler.storeAuthCookie = function(id , req , res){
    var uniqueId = 'xxxxxxxx-xxxx-4xxx-yxxx-xxxxxxxxxxxx'.replace(/[xy]/g, function(c) {
            var r = Math.random()*16|0, v = c == 'x' ? r : (r&0x3|0x8);
            return v.toString(16);
            //alert(unique_url);
        });
    res.cookie('user' , id , {httpOnly: false });
    res.cookie('auth' , uniqueId , {httpOnly: true });

    var sess = req.session;
    sess.uid = id;
    sess.uniqueId = uniqueId;
}

//remove cookies
cookieHandler.removeAuthCookie = function(req , res){
    res.clearCookie('userId');
    res.clearCookie('auth');
    return;
}



/*
    The client bean- used to store the client info and maintain session
*/

client = function()
{
    var self = this;
    self.userId;
    self.email;
    self.privateKey;
    self.publicKey;
    self.randomKey;
    self.sessKey = {key:"" , iv:""}

    self.setUserId = function(id){
        self.userId = id;
    }
    self.setEmail = function(email){
        self.email = email;
    }
    self.setPublicKey = function(puKey){
        self.publicKey = puKey;
    }
    self.setPrivateKey = function(prKey){
        self.privateKey = prKey;
    }
    self.setRandomKey = function(key){
        self.randomKey = key;
    }
    self.setSessionKey = function(sessKey){
        self.sessKey = sessKey;
    }
}


/*

*/


databaseHandler = function(){
}

databaseHandler.save = function(col , data){
    var collection = db.collection('accounts');
    var self = this;
    self.success = true;
    switch(col){
        case 'accounts':
            collection.insert(data, function(err, doc){
                if(!err)
                {
                    self.success = true;
                    return self.success;
                }
                else{
                    console.log("Error writing...")
                    console.log(err);
                }
            });
            break;
            case 'public_key':

            break;
        default:
            console.log("No collection found");
    }
    return self.success;
    

}

databaseHandler.get = function(coll , id , res){
    //get all the elements
    var collection = db.collection('accounts');
    if(coll=='accounts')
        collection = db.collection('accounts');
    else
        console.log(coll)

    if(id==null){
        return collection.find();
    }
    else{
        var self =this;
        self.result = null;
        
        var cursor = collection.find({"user_id":id},{"private_key":1,"public_key":1,"email":1,_id:0}).toArray(function(data){
            
        });
        return cursor;
    }

}   
