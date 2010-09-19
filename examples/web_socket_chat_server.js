WEB_SOCKET_MESSAGE_DELIMITER = "|"

// request codes
WEB_SOCKET_CHAT_REQ_CONN       = "1"
WEB_SOCKET_CHAT_REQ_CONN_CLOSE = "2"
WEB_SOCKET_CHAT_REQ_USER_MSG   = "40"

// response codes
WEB_SOCKET_CHAT_RSP_INVALID_MESSAGE     = "10"
WEB_SOCKET_CHAT_RSP_CONN_SUCCESS        = "20"
WEB_SOCKET_CHAT_RSP_CONN_USERNAME_TAKEN = "21"
WEB_SOCKET_CHAT_RSP_USER_LIST           = "30"
WEB_SOCKET_CHAT_RSP_USER_JOIN           = "31"
WEB_SOCKET_CHAT_RSP_USER_PART           = "32"
WEB_SOCKET_CHAT_RSP_USER_MSG            = "40"

$(document).ready(function(){
    web_socket = new WebSocket("ws://127.0.0.1:8080/trial", "Elements-test")

    web_socket.onopen = function(e) {
        $("#disconnected-status").hide();
        $("#log-on-box").show();
    }

    web_socket.onclose = function(e) {
        $("#log-on-box").hide();
        $("#disconnected-status").show();
    }

    web_socket.onmessage = function(e) {
        web_socket_chat.recieve_web_socket_message(e.data)
    }

    web_socket_chat = {

        username: null,

        split_message: function (message, num_split) {
            /**
             * Split a message on delimiter.
             *
             * @param message   (str)
             * @param num_split (int) Number of times to split. If none supplied it defaults to 1
             *
             * @return (Array)
             **/
            if (typeof num_split !== "number" || num_split < 1)
                num_split = 1;

            var del_pos       = message.indexOf(WEB_SOCKET_MESSAGE_DELIMITER);
            var split_count   = 0
            var split_message = new Array();

            if (del_pos < 0) {
                split_message.push(message);
            } else {
                while (split_count < num_split) {
                    split_message.push(message.substr(0, del_pos));
                    message = message.substr(del_pos + 1);
                    del_pos = message.indexOf(WEB_SOCKET_MESSAGE_DELIMITER);
                    if (del_pos < 0) {
                        break;
                    } else {
                        split_count++;
                    }
                }
                split_message.push(message);
            }
            console.log(message, split_message)
            return split_message;
        },

        recieve_web_socket_message : function(web_socket_message) {

            // parse incoming message
            var del_pos = web_socket_message.indexOf(WEB_SOCKET_MESSAGE_DELIMITER)

            if (del_pos < 0) {
                var code    = web_socket_message
                var message = ""
            } else {
                var code    = web_socket_message.substr(0, del_pos)
                var message = web_socket_message.substr(del_pos + 1)
            }

            var split_message = web_socket_chat.split_message(web_socket_message)

            var code    = split_message[0]
            var message = split_message[1]
            console.log(code + ": " + message)
            // route message data
            switch (code) {
                case WEB_SOCKET_CHAT_RSP_INVALID_MESSAGE:
                    $("#chat-content").append('<dt class="server-notice">Server Notice:</dt><dd class="server-notice"> -- Invalid Chat Message Sent To Server --</dd>');
                    break;

                case WEB_SOCKET_CHAT_RSP_CONN_SUCCESS:
                    web_socket_chat.username = message
                    $("#log-on-box").hide();
                    $("#chat-box").show();
                    $("#chat-input").focus();
                    $("#chat-content").append('<dt class="server-notice">Server Notice:</dt><dd class="server-notice"> -- Connected --</dd>');
                    break;

                case WEB_SOCKET_CHAT_RSP_CONN_USERNAME_TAKEN:
                    alert("Username already in use. Please select something different.");
                    break;

                case WEB_SOCKET_CHAT_RSP_USER_LIST:
                    var user_list = message.split("|").join(", ")
                    $("#chat-content").append('<dt class="user-list">User List:</dt><dd class="user-join"> -- '+user_list+' --</dd>');
                    break;

                case WEB_SOCKET_CHAT_RSP_USER_JOIN:
                    $("#chat-content").append('<dt class="user-join">User Joined:</dt><dd class="user-join"> -- '+message+' --</dd>');
                    break;

                case WEB_SOCKET_CHAT_RSP_USER_PART:
                    $("#chat-content").append('<dt class="user-part">User Parted:</dt><dd class="user-part"> -- '+message+' --</dd>');
                    break;

                case WEB_SOCKET_CHAT_RSP_USER_MSG:
                    var split_message = web_socket_chat.split_message(message)
                    $("#chat-content").append('<dt class="user-msg">'+split_message[0]+':</dt><dd class="user-msg">'+split_message[1]+"</dd>");
                    break;

                default:
                    console.log("Unhandled code return by server: " + code)
                    break;
            }


        },
        send_message: function(code, message) {
            web_socket.send(code + WEB_SOCKET_MESSAGE_DELIMITER + message)
        }
    }

    // Bind buttons and keyboard keys
    $('#cmd-log-on').bind('click',function(e) {
        var nickname = $("#nickname-input").val();
        if (nickname.length < 3) {
            alert("You must use a nick name with at least 3 characters.");
            $("#cmd-log-on, #nickname-input").removeAttr("disabled");
        } else {
            web_socket_chat.send_message(WEB_SOCKET_CHAT_REQ_CONN, nickname);
        }
    });

    $('#cmd-chat-send').bind('click',function(e) {
        var msg = $("#chat-input").val();
        $("#chat-input").val('');
        if (msg.length > 0) {
            web_socket_chat.send_message(WEB_SOCKET_CHAT_REQ_USER_MSG, msg)
            $("#chat-content").append('<dt class="my-msg">'+web_socket_chat.username+':</dt><dd class="my-msg">'+msg+"</dd>");
            $("#chat-input").focus();
        }
    });

    $('#chat-input').keydown(function (e) {
        var keyCode = e.keyCode || e.which;
        if (keyCode == 13) {
            $('#cmd-chat-send').click()
            return false;
        }
    });

    $('#nickname-input').keydown(function (e) {
        var keyCode = e.keyCode || e.which;
        if (keyCode == 13) {
            $('#cmd-log-on').click()
            return false;
        }
    });

});

