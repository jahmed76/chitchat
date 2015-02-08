var fs = require('fs');
var forge = require('node-forge')
var dbh = require('../database-management/database-handler.js')

KeyManagement = function(){
	var self = this;
	self.serverPublicKey = null;
	self.serverPrivateKey = null;
	self.publicChatKey = {key:"" , iv:""};
	self.groupChatKeys = [];
	self.sessionKey = {key:"" , iv:""}
	self.generateRSAKeyPair = function(){

		if(self.getServerPrivateKey()!=null){//Key pair already exists
			return;
		}

		var rsa = forge.pki.rsa;
		var keypair = rsa.generateKeyPair({bits: 1024, e: 0x10001});
		self.serverPublicKey = keypair.publicKey;
		self.serverPrivateKey = keypair.privateKey;
		self.saveRSAKeys(keypair);

		self.generatePublicChatKey();


	}
	self.saveRSAKeys = function(keypair){
		var publicKey = forge.pki.publicKeyToPem(keypair.publicKey)
		var privateKey = forge.pki.publicKeyToPem(keypair.privateKey)
		//Writing public key to public.key
		fs.writeFile("./keys/public.key", publicKey, function(err) {
		    if(err) {
		        console.log(err);
		    } else {
		    }
		}); 

		//Writing private key to private.key
		fs.writeFile("./keys/private.key", privateKey, function(err) {
		    if(err) {
		        console.log(err);
		    } else {
		    }
		}); 


	}

	self.generateAESKey = function(){
		var key = forge.random.getBytesSync(16);
		var iv = forge.random.getBytesSync(16);
		return {key:key , iv:iv}
	}

	self.generatePublicChatKey = function(){
		var key = forge.random.getBytesSync(16);
		var iv = forge.random.getBytesSync(16);
		self.publicChatKey = {key:key , iv:iv}
		//console.log(self.getPublicChatKey())
	}

	self.getServerPublicKey = function(){
		return self.serverPublicKey;
	}

	self.getServerPrivateKey = function(){
		return self.serverPrivateKey;
	}

	self.getPublicChatKey = function(){
		return self.publicChatKey;
	}

	self.getClientPublicKey=function(id){
		var publicKey = databaseHandler.get('accounts',id);
		var k = forge.pki.setRsaPublicKey(new forge.jsbn.BigInteger(publicKey.n) , new forge.jsbn.BigInteger(publicKey.e));
		return k;
	}

	self.getGroupChatKey = function(id){
		for(var i=0; i<groupChatKeys.length; i++){
			if(groupChatKeys[i].id == id)
				return groupChatKeys[i].key;
		}
		return null;
	}

}
