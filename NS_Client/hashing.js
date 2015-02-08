hash = function(){}

hash.createHash = function(data , key){
	var md = forge.md.sha1.create();
	md.update(data);
	return key.sign(md);
}

hash.verifyHash = function(hash , message , pubKey){
	var md = forge.md.sha1.create();
		md.update((message));
		try{
			var success = pubKey.verify(md.digest().getBytes() , hash);
			return success;
		}
		catch(err){
			return false;
		}
}