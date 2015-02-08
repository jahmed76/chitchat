function RSAEncryption(){
}
String.prototype.getBytes = function () {
  var bytes = [];
  for (var i = 0; i < this.length; ++i) {
    bytes.push(this.charCodeAt(i));
  }
  return bytes;
};
RSAEncryption.getKeyManager = function(){
	return keyManager;
}


RSAEncryption.sign = function(message , password) {
	var key = RSAEncryption.getKeyManager();
	
	var encryptionKey;
	encryptionKey = keyManager.getClientPrivateKey();
	
	encryptionKey = forge.pki.decryptRsaPrivateKey(encryptionKey,password);
	if(encryptionKey==null)
		encryptionKey = forge.pki.decryptRsaPrivateKey(keyManager.getClientPrivateKey(),password);
	var md = forge.md.sha1.create();
	md.update(message);
	var sign=encryptionKey.sign(md);

	var result = JSON.parse("{\"sign\":\""+forge.util.encode64(sign)+"\" , \"digest\":\""+message+"\"}"); 
	return result;
}

RSAEncryption.verify = function(sign , message , publicKey){
	//Verify using client's public key
	if(publicKey==null){
		//console.log(RSAEncryption.keyManager.getClientPublicKey());
		var publicKey = JSON.parse(RSAEncryption.keyManager.getClientPublicKey());

		publicKey = forge.pki.setRsaPublicKey(new forge.jsbn.BigInteger(publicKey.n) , new forge.jsbn.BigInteger(publicKey.e));

		var md = forge.md.sha1.create();
		md.update(message);
		console.log("-------------Verifying message-----------------")
		//console.log(message)
		var s = md.digest().getBytes()
		//console.log(s.getBytes())
		//console.log(sign.getBytes())
		console.log(publicKey)
		console.log("-------------End verifying-----------------")
		
		var verified =  publicKey.verify(md.digest().getBytes(), sign);
		return publicKey;

	}
	else{//verify using server/other client's key
		var publicKey = JSON.parse(publicKey);
		publicKey = forge.pki.setRsaPublicKey(new forge.jsbn.BigInteger(publicKey.n) , new forge.jsbn.BigInteger(publicKey.e));

		var md = forge.md.sha1.create();
		md.update(message);

		console.log("-------------Verifying message-----------------")
		console.log("Test")
		var s = md.digest().getBytes()
		//console.log(s.getBytes())
		//console.log(sign.getBytes())
		console.log(publicKey)
		console.log("-------------End verifying-----------------")

		var verified =  publicKey.verify(md.digest().getBytes(), sign);
		console.log(verified);
	}

}

RSAEncryption.encrypt=function(message , key){
		var encryptionKey="";
		var encrypted="";
		if(key==null)	{
			var publicKey = JSON.parse(keyManager.getClientPublicKey());
			encryptionKey = forge.pki.setRsaPublicKey(new forge.jsbn.BigInteger(publicKey.n) , new forge.jsbn.BigInteger(publicKey.e));
			encrypted = encryptionKey.encrypt(message);
			console.log(publicKey)
		}
		
		else if(key!=null){
			encryptionKey = key;
			var len = message.length;
			encrypted = encryptionKey.encrypt(message);
					
		}
		else
		{
			return;
		}
		return (encrypted);

}

RSAEncryption.decrypt=function(cipher , key, password){
		var decryptionKey="";
		var decrypted="";
		if(key==null){
			decryptionKey = RSAEncryption.getKeyManager().getClientPrivateKey();
			decryptionKey = forge.pki.decryptRsaPrivateKey(decryptionKey,password);
			console.log(decryptionKey)
		}
		
		else{
			return;
		}

		decrypted = decryptionKey.decrypt(cipher);

		return decrypted;

}