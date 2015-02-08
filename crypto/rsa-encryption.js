var forge = require('node-forge');

RSAencryption = function(){
}

RSAencryption.sign = function(message , privateKey){
	var encryptionKey = privateKey;//get private key stored in server directory

	var md = forge.md.sha1.create();
	md.update(message);
	var sign=encryptionKey.sign(md);

	var result = JSON.parse("{\"sign\":\""+forge.util.encode64(sign)+"\" , \"digest\":\""+message+"\"}"); 
	return result;
}

RSAencryption.verify = function(message, sign , publicKey){
		message = forge.util.decode64(message);
		sign = forge.util.decode64(sign);

		var md = forge.md.sha1.create();
		md.update((message));

		var verified =  publicKey.verify( md.digest().getBytes(), sign);
		return verified;
}

RSAencryption.encrypt = function(message , publicKey , id){
		var key = publicKey;
		return key.encrypt(message);
}

RSAencryption.decrypt = function(cipher,privateKey){
	return privateKey.decrypt(cipher);
}