$(function(){

		var chatKey;
		var keyManage = new KeyManagement();
		var user_id = localStorage.getItem("user");
		var socket = io.connect('/' , {query:'user='+forge.util.decode64(user_id)});
		var count = 0;
		var onlineUsers = [];
		var imPublicKeys = [];
		var imChatKeys = [];
		var password;
		var groupChats=[];
		var currentGroupChat;
		var recentInstantMessages = [];
		var recentGroupMessages = [];
		/*
			This code deals with public chat
		*/
		socket.on('welcome', function (data) {
			//var k = 
			console.log(data);
			keyManage = keyManager;
			user_id = localStorage.getItem("user");
			password = localStorage.getItem('password');
			var key = keyManage.sessionKey;
			var iv = key.iv;
			key = key.key
			onlineUsers = data.online;
			for (var i = onlineUsers.length - 1; i >= 0; i--) {
				var p = "<li class=\"\" id=\""+onlineUsers[i].id+"\">  <a href=\"#\">	<i class=\"icon-user\"></i>    <span class=\"title\">"+onlineUsers[i].id+"</span></a></li>";
				$("#online-users").append(p);
				document.getElementById(onlineUsers[i].id).firstChild.nextSibling.addEventListener("click", function(event){
					socket.emit('instant message handshake send' , {recipient_id:forge.util.encode64(event.srcElement.innerText) , sender_id:user_id});
				
				})
			};
			//request the current chat key
			socket.emit('chat key send' , {id:user_id})
			
 		});

 		//when a message is received, decrypt it and display it
		socket.on('receive message', function (data) {
			var encrypted = data.msg;
			var test = new forge.util.ByteStringBuffer();
			test.data = encrypted.data;
			test._constructedStringLength = encrypted._constructedStringLength;
			var decrypted = AESEncryption.decrypt(test , chatKey)
			var resp = "<p><u>"+forge.util.decode64(data.user)+
					   "</u> : "+decrypted+"</p>"
			$(".chat-box").append(resp);
			
		});

		//receive the key and store it
		socket.on('chat key receive',function(data){
			//var resp = RSAEncryption.decrypt(data.response,null,"t")
			
			var encrypted = data.response;
			var test = new forge.util.ByteStringBuffer();
			test.data = encrypted.data;
			test._constructedStringLength = encrypted._constructedStringLength;
			var resp = JSON.parse(AESEncryption.decrypt(test , keyManage.sessionKey));
			chatKey = {key:forge.util.decode64(resp.key) , iv:forge.util.decode64(resp.iv)}
		})

		//when a new user is added
		socket.on('new user',function(data){
			var id = forge.util.decode64(data);
			
			if(data==user_id)
				return;

			onlineUsers.push({id:id});
			
			var p = "<li class=\"\" id=\""+id+"\">  <a href=\"#\">	<i class=\"icon-user\"></i>    <span class=\"title\">"+id+"</span></a></li>";
	//		console.log(document.getElementById(id).firstChild);

			$("#online-users").append(p);

			document.getElementById(id).firstChild.nextSibling.addEventListener("click", function(){
				if(getChatKeyById(data)==null)
					socket.emit('instant message handshake send' , {recipient_id:data , sender_id:user_id});
				else{
					if($("#msg-"+forge.util.decode64(data)).length==0)
						createIMHtmlView(forge.util.decode64(data));
				}

			})
				
			
			
		})

		socket.on('user disconnect',function(data){
			var id = forge.util.decode64(data.id);
			
			for(var i=0;i<imChatKeys.length;i++){
				if(imChatKeys[i].id == data.id){
					imChatKeys[i].id== 0;
				}
			}
			$("#"+id).remove();
			$("#msg-"+id).remove();
			$("#chat-"+id).remove();
			$("#shout").addClass("active");
			$("#shout-box").addClass("active");
			for(var i=0;i<imChatKeys.length;i++){
				$("#msg-"+forge.util.decode64(imChatKeys[i].id)).removeClass("active");
				$("#chat-"+forge.util.decode64(imChatKeys[i].id)).removeClass("active");
			}
			for(var i=0;i<groupChats.length;i++){
				$("#msg-"+groupChats[i].id).removeClass("active");
				$("#chat-"+groupChats[i].id).removeClass("active");
			}
			console.log(data);

		})

		//send a message by first encrypting it
		$("#shout-box-send-message").click(function(data){
			var message = $("#shout-box-text").val();
			$("#shout-box-text"). val("");
			var encrypted = AESEncryption.encrypt(message , chatKey)
			var h = hash.createHash(forge.util.encode64(encrypted) , forge.pki.decryptRsaPrivateKey(keyManage.getClientPrivateKey() , password));			
			socket.emit('new message' , {user:user_id,msg: encrypted , hash:h})
			
		})



		/*
			This code deals with private chat
			
		*/
		socket.on('instant message handshake receive', function(data){
			imPublicKeys.push(data);
			var imKey = keyManage.generateAESKey();
			imChatKeys.push({id:data.id , key:imKey});

			//imKey = JSON.stringify(imKey);
			var recipient_public_key = forge.pki.setRsaPublicKey(new forge.jsbn.BigInteger(data.pk.n) , new forge.jsbn.BigInteger(data.pk.e));
			var session_key = recipient_public_key.encrypt(imKey.key);
			var session_iv = recipient_public_key.encrypt(imKey.iv);
			socket.emit('instant message chat key send' , {id:data.id , sender:user_id , key:{key:session_key , iv:session_iv}});

			if($("#msg-"+forge.util.decode64(data.id)).length==0)
				createIMHtmlView(forge.util.decode64(data.id));
		})

		socket.on('instant message chat key receive' , function(data){
			var key = data.key;
			var privateKey = forge.pki.decryptRsaPrivateKey(keyManage.getClientPrivateKey() , password);
			var s_iv = privateKey.decrypt(key.iv);
			key = privateKey.decrypt(key.key);
			imChatKeys.push({id:data.sender,key:{key:key , iv:s_iv}});

		})

		socket.on('receive instant message', function(data){
			var key = getChatKeyById(data.sender_id);
			var id = forge.util.decode64(data.sender_id);
			if(key!=null){
				var test = new forge.util.ByteStringBuffer();
				test.data = data.data.data;
				test._constructedStringLength = data._constructedStringLength;
				var d = AESEncryption.decrypt(test , key);
				if($("#msg-"+id).length==0)
					createIMHtmlView(id);
				var resp = "<p><u>"+forge.util.decode64(data.sender_id)+
											   "</u> : "+d+"</p>"
				$("#msg-box-"+id).append(resp)	
				recentInstantMessages.push({sender:id , msg:d})
			}else{
				console.log("Key not found!")
				return;
			}
		})


		//start group chat
		initGroupChat = function(event){
			$("#group-chat-user-list").empty();
			var uniqueId = 'xxxxxxxx-xxxx-4xxx-yxxx-xxxxxxxxxxxx'.replace(/[xy]/g, function(c) {
			            var r = Math.random()*16|0, v = c == 'x' ? r : (r&0x3|0x8);
			            return v.toString(16);
			            //alert(unique_url);
			        });
			currentGroupChat = uniqueId;
			var groupChat = {id:uniqueId , name:"" , key:"" , members:[]};
			groupChats.push(groupChat);
			count++;
			for (var i = onlineUsers.length - 1; i >= 0; i--) {
				var c = groupChats.length;

				var group_user = "<div class=\"row\"><div class=\"span12\"><li class=\"span6\" id=\"group-"+c+"-"+onlineUsers[i].id+"\">  <a href=\"#\">	<i class=\"icon-user\"></i>    <span class=\"title\">"+onlineUsers[i].id+"</span></a></li>"+
				"<a href=\"#\" class=\"btn green\" id=\"add-user-"+c+"-"+onlineUsers[i].id+"\">Add</a>"+
				"<a href=\"#\" class=\"btn red disabled\" id=\"remove-user-"+c+"-"+onlineUsers[i].id+"\">Remove</a></div></div>";
	
				$("#group-chat-user-list").append(group_user);
				document.getElementById("add-user-"+c+"-"+onlineUsers[i].id).addEventListener("click", function(event){
					groupChats[c-1].members.push(forge.util.encode64(event.srcElement.id.split('-')[3]));
					$("#add-user-"+c+"-"+event.srcElement.id.split('-')[3]).addClass('disabled');
					$("#remove-user-"+c+"-"+event.srcElement.id.split('-')[3]).removeClass('disabled');
				});
				document.getElementById("remove-user-"+c+"-"+onlineUsers[i].id).addEventListener("click", function(event){
					for(var i=0;i<groupChats[c-1].members.length;i++){
						var index = groupChats[c-1].members.indexOf(event.srcElement.id.split('-')[3]);
						groupChats[c-1].members.splice(index , 1);
					}
					$("#add-user-"+c+"-"+event.srcElement.id.split('-')[3]).removeClass('disabled');
					$("#remove-user-"+c+"-"+event.srcElement.id.split('-')[3]).addClass('disabled');
				});
			};
			
		}

		startGroupChat = function(event){
			var name = $("#group-chat-name").val();
			if(name=="")
				name="Group Chat - "+count;
			socket.emit('group message handshake send' , {chat_id:groupChats[groupChats.length-1].id , name:name , recipient_id:groupChats[groupChats.length-1].members , sender_id:user_id});
			$("#group-chat-name").val("");
		}


		socket.on('group message handshake receive', function(data){
			var imKey = keyManage.generateAESKey();
			var response=[];
			var members=[];
			for(var i=0; i<data.resp.length;i++){
				var public_key = forge.pki.setRsaPublicKey(new forge.jsbn.BigInteger(data.resp[i].pk.n) , new forge.jsbn.BigInteger(data.resp[i].pk.e));
				var session_key = public_key.encrypt(imKey.key);
				var session_iv = public_key.encrypt(imKey.iv);
				response.push({id:data.resp[i].rid , gc_key:{key:session_key , iv:session_iv}});
				members.push(data.resp[i].rid);
			}
			for (var i = groupChats.length - 1; i >= 0; i--) {
				if(groupChats[i].id==data.chat_id){
					groupChats[i].key = {key:imKey.key , iv:imKey.iv};
					break;
				}
			};	
			socket.emit('group message chat key send' , {sender:user_id , resp: response , chat_id:data.chat_id , name:data.name});
			if($("#msg-"+groupChats[groupChats.length-1].id).length==0)
				createGCHtmlView(data.chat_id , data.name , imKey , members);
			
		})

		socket.on('group message chat key receive' , function(data){
			var my_data=null;
			var members = [];
			for (var i = data.resp.length - 1; i >= 0; i--) {
				if(data.resp[i].id==user_id){
					my_data = data.resp[i];
				}
				members.push(data.resp[i].id);
			};
			var privateKey = forge.pki.decryptRsaPrivateKey(keyManage.getClientPrivateKey() , password);
			var s_iv = privateKey.decrypt(my_data.gc_key.iv);
			key = privateKey.decrypt(my_data.gc_key.key);
			groupChats.push({id:data.chat_id, name:data.name , key:{key:key , iv:s_iv} , members:members })
		})

		socket.on('receive group message', function(data){
			var current_chat=null;
			var members=[];
			for (var i = groupChats.length - 1; i >= 0; i--) {
				if(groupChats[i].id==data.id){
					current_chat = groupChats[i];
					break;
				}
			};	
			for(var i=0;i<data.receiver_id.length;i++){
				if(data.receiver_id[i]!=user_id){
					members.push(data.receiver_id[i]);
				}
			}
			members.push(data.sender_id);
			if(current_chat!=null){
				var key = current_chat.key;
				var test = new forge.util.ByteStringBuffer();
				test.data = data.data.data;
				test._constructedStringLength = data._constructedStringLength;
				var d = AESEncryption.decrypt(test , key);
				if($("#msg-"+data.id).length==0)
					createGCHtmlView(current_chat.id , current_chat.name , key , members);
				var resp = "<p><u>"+forge.util.decode64(data.sender_id)+
											   "</u> : "+d+"</p>"
				$("#msg-box-"+current_chat.id).append(resp)
			}	
			else{
				console.log("No group id found!");
				return;
			}
		})


		cancelGroupChat = function(event){
			groupChats.pop();
		}


		createGCHtmlView= function(id , name , k , members){
			//remove current active elements
			$("#shout").removeClass("active");
			$("#shout-box").removeClass("active");
			for(var i=0;i<imChatKeys.length;i++){
				$("#msg-"+forge.util.decode64(imChatKeys[i].id)).removeClass("active");
				$("#chat-"+forge.util.decode64(imChatKeys[i].id)).removeClass("active");
			}
			for(var i=0;i<groupChats.length;i++){
				$("#msg-"+groupChats[i].id).removeClass("active");
				$("#chat-"+groupChats[i].id).removeClass("active");
			}

			//create element
			var tab = "<li class=\"active\" id=\"msg-"+id+"\"><a href=\"#chat-"+id+"\" data-toggle=\"tab\"><u>"+name+"</u> <span ><i class=\"close\" id=\"close-"+id+"\"></i></span></a></li>";
			$(".nav-tabs").append(tab);

			var chatbox = "<div class=\"tab-pane active\" id=\"chat-"+id+"\">"+
								"<div id=\"msg-box-"+id+"\" style=\"overflow:auto; height:400px;border: 1px #35fd0d solid;\">"+
								"</div>"+
								"<br/>"+
								"<div>"+
									"<div class=\"span9\">"+
										"<textarea class=\"span12\" id=\"gc-send-message-text-"+id+"\" rows=\"2\"></textarea>"+
									"</div>"+
									"<div  class=\"span3\">"+
										"<p>"+												
											"<a class=\"btn big green\" id=\"gc-send-message-"+id+"\">Send"+
										   	  " <i class=\"m-icon-big-swapup m-icon-white\"></i>"+
										   "</a>"+
										"</p>"+
									"</div>"+
								"</div>"+
							"</div>";
			$(".tab-content").append(chatbox);

			$("#gc-send-message-"+id).click(function(event){
				var data = $("#gc-send-message-text-"+id).val();
				$("#gc-send-message-text-"+id).val("");
				var key = k;
				if(key!=null){
					var encrypteddata = AESEncryption.encrypt(data , key);
					var h = hash.createHash(forge.util.encode64(encrypteddata) , forge.pki.decryptRsaPrivateKey(keyManage.getClientPrivateKey() , password));
					socket.emit('send group message' , {id:id , sender_id:user_id , receiver_id : members , data:encrypteddata , hash:h});
					var resp = "<p><u>"+forge.util.decode64(user_id)+
							   "</u> : "+data+"</p>"
					$("#msg-box-"+id).append(resp)
				}else{
					console.log("No user session found")
					return;
				}
			})
			$("#close-"+id).click(function(event){
				$("#msg-"+id).remove();
				$("#chat-"+id).remove();
				$("#shout").addClass("active");
				$("#shout-box").addClass("active");

				for(var i=0;i<imChatKeys.length;i++){
				$("#msg-"+forge.util.decode64(imChatKeys[i].id)).removeClass("active");
				$("#chat-"+forge.util.decode64(imChatKeys[i].id)).removeClass("active");
				}
				for(var i=0;i<groupChats.length;i++){
					$("#msg-"+groupChats[i].id).removeClass("active");
					$("#chat-"+groupChats[i].id).removeClass("active");
				}
			})

		}




		
		
		verifyHash = function(data , hash , pubKey){
			var md = forge.md.sha1.create();
			md.update(("message"));
			try{
				return true;
			}
			catch(err){
				return false;
			}
		}
		//
		createIMHtmlView= function(id){
			//remove current active elements
			$("#shout").removeClass("active");
			$("#shout-box").removeClass("active");
			for(var i=0;i<imChatKeys.length;i++){
				$("#msg-"+forge.util.decode64(imChatKeys[i].id)).removeClass("active");
				$("#chat-"+forge.util.decode64(imChatKeys[i].id)).removeClass("active");
			}
			for(var i=0;i<groupChats.length;i++){
				$("#msg-"+groupChats[i].id).removeClass("active");
				$("#chat-"+groupChats[i].id).removeClass("active");
			}

			//create element
			var tab = "<li class=\"active\" id=\"msg-"+id+"\"><a href=\"#chat-"+id+"\" data-toggle=\"tab\"><u>"+id+"</u> <span ><i class=\"close \" id=\"close-"+id+"\"></i></span></a></li>";
			$(".nav-tabs").append(tab);

			var chatbox = "<div class=\"tab-pane active\" id=\"chat-"+id+"\">"+
								"<div id=\"msg-box-"+id+"\" style=\"overflow:auto; height:400px;border: 1px #35fd0d solid;\">"+
								"</div>"+
								"<br/>"+
								"<div>"+
									"<div class=\"span9\">"+
										"<textarea class=\"span12\" id=\"im-send-message-text-"+id+"\" rows=\"2\"></textarea>"+
									"</div>"+
									"<div  class=\"span3\">"+
										"<p>"+												
											"<a class=\"btn big green\" id=\"im-send-message-"+id+"\">Send"+
										   	  " <i class=\"m-icon-big-swapup m-icon-white\"></i>"+
										   "</a>"+
										"</p>"+
									"</div>"+
								"</div>"+
							"</div>";
			$(".tab-content").append(chatbox);

			$("#im-send-message-"+id).click(function(event){
				var data = $("#im-send-message-text-"+id).val();
				$("#im-send-message-text-"+id).val("");
				var key = getChatKeyById(forge.util.encode64(id));
				if(key!=null){
					var encrypteddata = AESEncryption.encrypt(data , key);
					var h = hash.createHash(forge.util.encode64(encrypteddata) , forge.pki.decryptRsaPrivateKey(keyManage.getClientPrivateKey() , password));
					socket.emit('send instant message' , {sender_id:user_id , receiver_id : forge.util.encode64(id) , data:encrypteddata  , hash:h});
				//	var resp = "<p>"+forge.util.decode64(user_id)+" : "+data+"</p>"
					var resp = "<p><u>"+forge.util.decode64(user_id)+
							   "</u> : "+data+"</p>"
					$("#msg-box-"+id).append(resp)
					recentInstantMessages.push({sender:user_id , msg:data})

				}else{
					console.log("No user session found")
					return;
				}
			})
			$("#close-"+id).click(function(event){
				$("#msg-"+id).remove();
				$("#chat-"+id).remove();
				$("#shout").addClass("active");
				$("#shout-box").addClass("active");

				for(var i=0;i<imChatKeys.length;i++){
					$("#msg-"+forge.util.decode64(imChatKeys[i].id)).removeClass("active");
					$("#chat-"+forge.util.decode64(imChatKeys[i].id)).removeClass("active");
				}
				for(var i=0;i<groupChats.length;i++){
					$("#msg-"+groupChats[i].id).removeClass("active");
					$("#chat-"+groupChats[i].id).removeClass("active");
				}
			})

		}

		//utility methods
		getChatKeyById = function(id){
			for (var i = imChatKeys.length - 1; i >= 0; i--) {
				if(imChatKeys[i].id==id)
					return imChatKeys[i].key;
			};
			return null;
		}








		
	})