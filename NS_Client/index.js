var keyManager= null;
var user = [];
$(function(){
	keyManager = $.jStorage.get("key_manager");
	if(!keyManager){
	    // if not - load the data from the server
	    console.log("creating key pair")
	    keyManager = new KeyManagement();
	    
	    var allcookies = document.cookie;
	       // Get all the cookies pairs in an array
	       cookiearray  = allcookies.split(';');
	       // Now take key value pair out of this array
	       for(var i=0; i<cookiearray.length; i++){
	          name = cookiearray[i].split('=')[0];
	          value = cookiearray[i].split('=')[1];
	          if(name=='pub_key' || name==' pub_key')
	          {
	          		var cr = (decodeURI(value)).replace(/%3A/g,':').replace(/%2C/,',')
	          		var key = JSON.parse(cr);
	          		keyManager.serverPublicKey = forge.pki.setRsaPublicKey(new forge.jsbn.BigInteger(key.n) , new forge.jsbn.BigInteger(key.e));
	          		break;
	          }
	          
	       }

	    $.jStorage.set("key_manager",keyManager);
	}
	else{
		var k = new KeyManagement();
		k.setPublicChatKey((keyManager.publicChatKey).key , (keyManager.publicChatKey).iv);
		k.setClientPrivateKey(keyManager.clientPrivateKey);
		k.setClientPublicKey(keyManager.clientPublicKey);
		var allcookies = document.cookie;
		   // Get all the cookies pairs in an array
		   cookiearray  = allcookies.split(';');
		   // Now take key value pair out of this array
		   for(var i=0; i<cookiearray.length; i++){
		      name = cookiearray[i].split('=')[0];
		      value = cookiearray[i].split('=')[1];
		      console.log(name)
		      if(name=='pub_key' || name==' pub_key')
		      {
		      		var cr = (decodeURI(value)).replace(/%3A/g,':').replace(/%2C/,',')
		      		var key = JSON.parse(cr);
		      		k.serverPublicKey = forge.pki.setRsaPublicKey(new forge.jsbn.BigInteger(key.n) , new forge.jsbn.BigInteger(key.e));
		      		break;
		      }
		      
		   }
		//k.setServerPublicKey(keyManager.serverPublicKey);
		k.groupKeys = keyManager.groupKeys;
		k.sessionKey = keyManager.sessionKey;
		keyManager = k;
		console.log(keyManager);
		$.jStorage.set("key_manager",keyManager);

	}

	
})

