var mongoskin = require('mongoskin')
var db = mongoskin.db('mongodb://@localhost:27017/chatty', {safe:true})
var collections = ["accounts"];


databaseHandler = function(){
}

databaseHandler.save = function(col , data){
	var collection = db.get('accounts');
	var self = this;
	self.success = true;
	switch(col){
		case 'accounts':
			collection.insert(data, function(err, doc){
				if(!err)
				{
					self.success = true;
					//console.log(doc)
					return self.success;
				}
				else{
					console.log("Error writing...")
				}
			});
			break;
			case 'public_key':

			break;
		default:
			console.log("No collection found");
	}
	return self.success;
	

}

databaseHandler.get = function(coll , id){
	//get all the elements
	var collection = db.collection('accounts');
	if(coll=='accounts')
		collection = db.collection('accounts');
	else
		console.log(coll)

	if(id==null){
		return collection.find();
	}
	else{
		var self =this;
		self.result = null;
		
		var cursor = collection.find({"user_id":id}).toArray(function(data){
			console.log(data);
		});
		//return cursor;
		
		return cursor;
	}

}	
