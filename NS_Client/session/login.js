function Login(){
	var self = this;

	self.performLogin=function(userId , password)	{
		$.ajax({url:"./login" , method:"POST" , data:{id:forge.util.encode64(userId)} , dataType:"json" , success:function(data , status , jqXHR){
			var success = hash.verifyHash(data.hash , data.data , keyManager.getServerPublicKey());
			console.log(data);
			if(success){
				try{
					keyManager.setClientPrivateKey(forge.util.decode64(data.data.private_key));
					var privateKey = forge.pki.decryptRsaPrivateKey(forge.util.decode64(data.data.private_key) , password)
					var decryptedResp = privateKey.decrypt(forge.util.decode64(data.data.response));
					var requestData = "{\"secret_key\":\""+JSON.parse(decryptedResp).secret_key+"\"}";
					keyManager.setClientPublicKey("{\"e\":\""+data.data.public_key_e+"\" , \"n\":\""+data.data.public_key_n+"\"}");
					var h = hash.createHash(requestData , privateKey);
					
					$.ajax({url:"./login/"+forge.util.encode64(userId) , method:"POST" , data:{data:requestData , hash:h} , dataType:"json", success:function(data,status,jqXHR){
						console.log(data)
						if(self.processServerOutput(data.resp,privateKey,password)){
											
							localStorage.setItem("user" , forge.util.encode64(userId))
							window.location.href = "./chat";
						}
						else{
							$.gritter.add({
								title: "Login credentials not verified",
								text: "Your login credentials cannot be verified. Check your username and password and try again",
								fade: true,
								class_name: 'gritter-light',
								speed: "fast"
							});
						}
					},error:function(jqXHR , status , error){
						$.gritter.add({
								title: "Error occurred",
								text: error,
								fade: true,
								class_name: 'gritter-light',
								speed: "fast"
						});
					}})
				}catch(err){
					$.gritter.add({
						title: "Login credentials not verified",
						text: error,
						fade: true,
						class_name: 'gritter-light',
						speed: "fast"
					});
				}
			}else{
				$.gritter.add({
					title: "Identity not verified",
					text: "Server identity cannot be verified. Please refresh this page and try again",
					fade: true,
					class_name: 'gritter-light',
					speed: "fast"
				});
			}

		} , error:function(jqXHR , status , error){
				$.gritter.add({
				    title: "Error",
				    text: error,
				    fade: true,
				    class_name: 'gritter-light',
				    speed: "fast"
				});
		}})


	}

	self.processServerOutput = function(data,privateKey,password){

		try{
			
			var decrypted = privateKey.decrypt(data);
			keyManager.sessionKey = {key:forge.util.decode64(JSON.parse(decrypted).session_key), iv:forge.util.decode64(JSON.parse(decrypted).session_iv)};
			localStorage.setItem("password" , password);
			$.jStorage.set("key_manager",keyManager);
			return true;
		}catch(err){
			console.log(err);
			return false;
		}
			

	}

}
