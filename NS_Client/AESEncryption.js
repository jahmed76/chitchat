AESEncryption = function(){}

AESEncryption.encrypt = function (message , key){
	
	var cipher = forge.cipher.createCipher('AES-CBC', key.key);
	cipher.start({iv:key.iv});
	cipher.update(forge.util.createBuffer(message));
	cipher.finish();
	var encrypted = cipher.output;
	return encrypted;
}

AESEncryption.decrypt = function (cipher , key){
	var decipher = forge.cipher.createDecipher('AES-CBC', key.key);
	decipher.start({iv: key.iv});
	decipher.update(cipher);
	decipher.finish();

	//var t = AESEncryption.encrypt("test" , chatKey);
	//var j = AESEncryption.decrypt(t , chatKey)
	return decipher.output.data;
}