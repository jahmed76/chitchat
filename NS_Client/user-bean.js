function user()
{
	var self=this;
	self.email;
	self.userId;
	self.publicKey;
	
	self.setEmail=function(email){
		self.email = email;
	}
	self.getEmail=function(){
		return self.email;
	}

	self.setUserId=function(id){
		self.userId = id;
	}
	self.getUserId=function(){
		return self.userId;
	}

	self.setPublicKey=function(pk){
		self.publicKey = pk;
	}
	self.getPublicKey=function(){
		return self.publicKey;
	}

}