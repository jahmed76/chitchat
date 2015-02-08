KeyManagement =  function(){
	var self=this;
	self.clientPublicKey = null ;
	self.clientPrivateKey = null;
	self.serverPublicKey = null;
	self.publicChatKey = {key:"" , iv:""};
	self.groupKeys = {id:"" , key:"" , iv:""}
	self.sessionKey = {key:"" , iv:""}

	self.generateRSAKeyPair=function(password){
		if(self.clientPrivateKey!=null){
			return;
		}
		var rsa = forge.pki.rsa;

		var keypair = rsa.generateKeyPair({bits: 1024, e: 0x10001});
		console.log(keypair)
		self.saveRSAKeys(keypair , password);

		self.setClientPublicKey(localStorage.getItem("public_key"));

		self.setClientPrivateKey(localStorage.getItem("private_key"));

	}

	self.generateAESKey=function(){
		var uniqueId = 'xxxxxxxx-xxxx-4xxx-yxxx-xxxxxxxxxxxx'.replace(/[xy]/g, function(c) {
		            var r = Math.random()*16|0, v = c == 'x' ? r : (r&0x3|0x8);
		            return v.toString(16);
		            //alert(unique_url);
		        });
		var generatedKey = forge.random.getBytesSync(16);
		var iv = forge.random.getBytesSync(16);
		var newKey = {id:uniqueId , key:generatedKey , iv:iv}
		self.groupKeys[self.groupKeys.length] =newKey;
		return newKey;

	}

	self.receiveAESKey=function(rid,rkey,iv){
		var newKey = {id:rid , key:rkey , iv:iv};
		self.groupKeys[self.groupKeys.length] = newKey;

	}
	self.saveRSAKeys=function(keypair , password){
		//console.log(keypair);
		var publicKey = "{\"e\":\""+keypair.publicKey.e+"\" , \"n\":\""+keypair.publicKey.n+"\"}";
		var privateKey = "{\"e\":\""+keypair.publicKey.e+"\" , \"n\":\""+keypair.publicKey.n+"\"}";
		localStorage.setItem("private_key" , forge.pki.encryptRsaPrivateKey(keypair.privateKey , password));
		localStorage.setItem("public_key" , publicKey);

	}
	

	self.setClientPublicKey = function(publicKey){
		self.clientPublicKey = publicKey;
	}

	self.setClientPrivateKey = function(privateKey){
		self.clientPrivateKey = privateKey;
	}

	self.setServerPublicKey=function(serverKey){
		var allcookies = document.cookie;
		   // Get all the cookies pairs in an array
		   cookiearray  = allcookies.split(';');

		   // Now take key value pair out of this array
		   for(var i=0; i<cookiearray.length; i++){
		      name = cookiearray[i].split('=')[0];
		      value = cookiearray[i].split('=')[1];
		      if(name==' pub_key')
		      {
		      		console.log("Setting server public_key")
		      		var key = JSON.parse(forge.util.decode64(value));
		      		key = JSON.parse(key)
		      		self.serverPublicKey = forge.pki.setRsaPublicKey(new forge.jsbn.BigInteger(key.n) , new forge.jsbn.BigInteger(key.e));
		      		break;
		      }
		      
		   }
		   
	}

	self.setPublicChatKey = function(key , iv){
		self.publicChatKey = {key:key , iv:iv};
	}

	self.getClientPublicKey = function(){
		return self.clientPublicKey;
	}

	self.getClientPrivateKey = function(){
		return self.clientPrivateKey;
	}

	self.getServerPublicKey=function(){
		return self.serverPublicKey;
	}

	self.getPublicChatKey=function(){
		return self.publicChatKey;
	}
}