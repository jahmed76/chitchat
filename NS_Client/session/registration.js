String.prototype.getBytes = function () {
  var bytes = [];
  for (var i = 0; i < this.length; ++i) {
    bytes.push(this.charCodeAt(i));
  }
  return bytes;
};
function Registration(){
		var self = this;
		self.keyManager  = new KeyManagement();
		self.password = null;
		self.performRegistration=function(Id , email , password)	{
			self.password = password;
		self.keyManager.generateRSAKeyPair(self.password);

		keyManager = self.keyManager;
		self.password = password;
		var jsonObject="test";
		var publicKey = self.keyManager.getClientPublicKey();
		//console.log(publicKey)
		var encodedPublicKey = forge.util.encode64(publicKey);

		var encodedPrivateKey = forge.util.encode64(self.keyManager.getClientPrivateKey());

		jsonObject = "{\"public_key\":\""+encodedPublicKey+"\"}";

     	var singleEncryption = self.signWithClientKey(encodedPublicKey,password);
	    
	    var p = JSON.parse(keyManager.getClientPublicKey());
	    //var newKey2 = RSAEncryption.verify(forge.util.decode64(singleEncryption.sign) , encodedPublicKey , null)
	    var newKey2 = forge.pki.setRsaPublicKey(new forge.jsbn.BigInteger(p.n) , new forge.jsbn.BigInteger(p.e));
	    var data = "{\"sign\":\""+singleEncryption.sign+"\", \"digest\":\""+forge.util.encode64(encodedPublicKey)+"\", \"user_id\":\""+forge.util.encode64(Id)+"\", \"email\":\""+forge.util.encode64(email)+"\", \"private_key\":\""+encodedPrivateKey
						+"\",\"public_key\":{\"n\":\""+newKey2.n+"\" , \"e\":\""+newKey2.e+"\"}}"
	    
		var h = hash.createHash(JSON.parse(data),forge.pki.decryptRsaPrivateKey(self.keyManager.getClientPrivateKey(),password));
		var finalJSON ="{\"data\":"+data+" , \"hash\":\""+forge.util.encode64(h)+"\"}";
		var success = self.sendToServer(finalJSON);
		return success;
	}

	self.signWithClientKey=function(data,password){
		var encryptedData = RSAEncryption.sign(data , self.password);
		return encryptedData;
	}

	self.encryptWithServerKey=function(data){
		var serverPublicKey  = self.keyManager.getServerPublicKey();
		var encryptedData = RSAEncryption.encrypt(data , serverPublicKey , "public");
		return encryptedData;
	}

	self.sendToServer=function(data){
		data = JSON.parse(data);
		var user_id = data.data.user_id;
		//console.log(data.data.sign)
		//data = JSON.parse(data);
		//console.log(data.getBytes());
		$.ajax({url:"./register" , method:"POST" , data:data , dataType:"json" , success:function(data , status , jqXHR)	{
				
				if(self.processServerOutput(data.resp,jqXHR)){
					
			
					localStorage.setItem("user" , user_id)
					window.location.href = "./chat";
				}
				else{
					console.log("Error occurred");
				}

			} , 
			error:function(jqXHR , status , error){
				console.log(error);
			}
		});

	}

	self.processServerOutput = function(data,jqXHR){

		try{
			var decrypted = RSAEncryption.decrypt(data,null,self.password);
			self.keyManager.sessionKey = {key:forge.util.decode64(JSON.parse(decrypted).session_key), iv:forge.util.decode64(JSON.parse(decrypted).session_iv)};
			
			keyManager = self.keyManager;
			localStorage.setItem("password" , self.password);

			$.jStorage.set("key_manager",keyManager);
			return true;
		}catch(err){
			return false;
		}
		

	}
}
