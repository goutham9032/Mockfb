$DOM = $(document)
$DOM.ready(function(){

    var OTP_SESSION = 45 // sec
    var TMP_PASS_LEN = 0

    function call_ajax(url, type, data) {
         data = data || '';
         var request = $.ajax({
                             type: type,
                             url: url,
                             data:data,
                       });
         return request;
    }

	function readURL(input) {
	  if (input.files && input.files[0]) {
		var reader = new FileReader();
		reader.onload = function(e) {
		  $('#preview_file').attr('src', e.target.result);
		}
		reader.readAsDataURL(input.files[0]);
	  }
    };

    function upload_file(){
    	readURL(this);
        $('#preview_file').removeClass('no_display');
        if(!$('#img_rmve_btn').is(':visible')){
           $('#img_rmve_btn').toggle();
           
        }
        $('#post_feed').removeClass('no_pointer').addClass('pointer').prop('disabled',false);
    }

    function click_file_choose(){
        $("#file_upload_ip").click();
    }

    function remove_selected_file(){
       $('#file_upload_ip').val(null);
       $('#preview_file').addClass('no_display');
       $('#img_rmve_btn').toggle();
    }

    function delete_feed(){
		obj = $(this);
        card_obj = obj.parents('.feed_card');
        feed = { 'feed_id': card_obj.attr('id'),
                 'action': 'delete'
               }
        url = '/activity/';
		$.confirm({
			title: 'Delete',
			content: 'Are you sure you want to delete post?',
			buttons: {
			  confirm: function() {
				req = call_ajax(url, 'POST', JSON.stringify(feed))
				$.when(req).done(function(data) {
                  if(data.success){
					 card_obj.remove();
                  }
                });
			  },
			  cancel: function() {},
			},
		});
    }


    function post_feed(){
        event.preventDefault();
        var request = new XMLHttpRequest();
        desc = $('#post_desc').val();
        request.open('POST', '/fileupload/?action=create&desc='+desc, false);
        var formData = new FormData(document.getElementById('file_upload_form'));
        request.send(formData);
        res = request.response;
        if (res == 'OK'){
           window.location.reload();
        }
    }

    function like_unlike_activity(){
        heart_obj = $(this);
        obj = heart_obj.parents('.feed_card');
        feed_id = obj.attr('id');
        feed = {'feed_id':feed_id };
        url = '/activity/';
        
        if($(this).hasClass('fa-heart-o')){
            feed['action'] = 'like';
        }
        else{
            feed['action'] = 'unlike';
        }
        feed_data = JSON.stringify(feed)
        req = call_ajax(url, 'POST', feed_data);
        $.when(req).done(function(data) {
          if(!data.success){
             return 0;
          }
		  if(feed.action == 'like'){
			 heart_obj.removeClass('fa-heart-o').addClass('fa-heart');
		  }
          else{
             heart_obj.removeClass('fa-heart').addClass('fa-heart-o');
          }
		  $('#'+feed_id+' #likes_count').html(data.likes);
        });
        
    }

    function feed_desc_count(){
        desc = $(this).val();
        $('#letters_count').html(desc.length+' / 130');
        if(desc.length > 0){
          $('#post_feed').removeClass('no_pointer').addClass('pointer').prop('disabled',false);
        }
        else{
          $('#post_feed').removeClass('pointer').addClass('no_pointer').prop('disabled',true);
        }
    }


    function change_checkbox_val(){
        $(this).val('YES');
    }


    function csrfSafeMethod(method) {
       // these HTTP methods do not require CSRF protection
       return (/^(GET|HEAD|OPTIONS|TRACE)$/.test(method));
    }
    function ajax_csrf_exempt_setup(){
		// set csrf header
        var csrftoken = jQuery("[name=csrfmiddlewaretoken]").val();
		$.ajaxSetup({
			beforeSend: function(xhr, settings) {
				if (!csrfSafeMethod(settings.type) && !this.crossDomain) {
					xhr.setRequestHeader("X-CSRFToken", csrftoken);
				}
			}
		});
    }
    var timer = null;
    function set_timer(){
       timer = setInterval(function() {
						   $(".otp_counter").html('00:'+OTP_SESSION).css('color', 'blue')
						   OTP_SESSION--;
                           if(OTP_SESSION < 10){
							 $(".otp_counter").html('00:0'+OTP_SESSION).css('color','red')
                           }
						   if(OTP_SESSION == 0){
							 $(".otp_counter").html('00:00').css('color','red')
                             $('#verify_otp').prop('disabled', true)
                             $('.err').toggleClass('no_display') 
							 clearInterval(timer);
							 return
						   }
					   }, 1000)
    }

    function send_otp(){
       event.preventDefault();
       ajax_csrf_exempt_setup()
       email_obj = $('#id_email')
       if(!email_obj.val().length){
           alert('Please enter valid email');
           return
       }
       if($('.btn-success').is(':visible')){
           // this case to resend otp, as the timer not getting stopped once he presses submit otp,
           // so again we are clearing this timer
           clearInterval(timer)
       }
       email = email_obj.val()
       url = window.location.pathname
       type = 'POST'
       data = {'email': email, 'type': 'register_otp'}
       req = call_ajax(url, type, data);
       OTP_SESSION = 45
       $.when(req).done(function(data) {
           if(data.success){
              $('.password_reset_btn').remove()
              var msg = `<div class="alert alert-success">`+ data.message +`</div>`
              var otp_ip_box= `<div class="form-group">
                                    <input class="form-control" placeholder="OTP" 
                                           required id="id_otp" 
                                           maxlength="6" name="otp" type="text" value="" />
                                    <p>
                                       <span class='otp_counter'>00:`+OTP_SESSION+`</span>
                                       <span class="invalid_otp err no_display">
                                             &nbsp&nbspInvalid otp/session time out, please try again
                                       </span>
                                    </p>
                                    <button class="btn otp_btns btn-success" id="verify_otp">Verify otp</button>
                                    <button class="btn otp_btns f_right btn-primary password_reset_btn" 
                                           id="resend_otp">Resend otp
                                    </button>
                               </div>`
              $('.otp_info_msg_div').empty().append(msg+otp_ip_box) 
              $('#id_email').prop('disabled', true);
              set_timer()
           }
           else{
              var msg = `<div class="alert alert-danger">`+ data.message +`</div>`
              $('.otp_info_msg_div').empty().append(msg) 
           }
       });

    }

    function verify_otp(){
       event.preventDefault();
       ajax_csrf_exempt_setup()
       email = $('#id_email').val()
       otp = $('#id_otp').val(); 
       if(!otp.length){
           alert('Please enter valid email');
           return
       }
       url = window.location.pathname
       type = 'POST'
       data = {'email': email, 'type': 'verify_otp', 'otp': otp}
       req = call_ajax(url, type, data);
       $.when(req).done(function(data) {
         if(data.success){
             window.location.href = data.pwd_reset_url
         }
         else{
             err_obj = $('.err')
             if(!err_obj.is(':visible')){
                $('.err').toggleClass('no_display') 
             }
             // clearInterval(timer)
             // $('#verify_otp').prop('disabled', true)
         }
       });

    }

    function check_password_format(){
        obj = $('.err_pass_msg')
        $('.err_con_msg').css('display', 'none')
        if(!$(this).val().match(/^[0-9a-zA-Z-_]+$/) && $(this).val().length >= 1){
            obj.css('display','block')
            TMP_PASS_LEN = 0
        }
        else{
            TMP_PASS_LEN ++;
            obj.css('display', 'none')
        }

        if($(this).val().length > 8 && TMP_PASS_LEN){
           $('#reset_password').prop('disabled', false)
        }
        else{
           $('#reset_password').prop('disabled', true)

        }
    }

    function reset_password(){
        event.preventDefault();
        ajax_csrf_exempt_setup()
        new_pass = $('#id_new_pass').val()
        con_pass = $('#id_con_pass').val()
        if (new_pass != con_pass && TMP_PASS_LEN != 0){
            $('.err_con_msg').css('display', 'block')
            return
        }
        else{
           url = window.location.pathname
           type = 'POST'
           data = {'new_password': btoa(new_pass)}
           req = call_ajax(url, type, data);
           $.when(req).done(function(data) {
             if(data.success){
                 window.location.href = '/'
             }
             else{
                 console.log('some thing went wrong please check')
             }
          })
       }
    }

    function check_con_passwd(){
        $('.err_con_msg').css('display', 'none')
    }

    function bindEvents() {
		$DOM.on('change', '#file_upload_ip', upload_file)
		    .on('input propertychange', "#post_desc", feed_desc_count)
		    .on('click', '#add_image', click_file_choose)
		    .on('click','#img_rmve_btn', remove_selected_file)
	        .on('click', '.delete_feed', delete_feed)
		    .on('click', '#post_feed', post_feed)
	        .on('click', '.like_heart', like_unlike_activity)
            .on('change', '#id_remember', change_checkbox_val)
            .on('click', '.password_reset_btn', send_otp)
            .on('click', '#verify_otp', verify_otp)
            .on('keyup', '#id_new_pass', check_password_format)
            .on('keyup', '#id_con_pass', check_con_passwd)
            .on('click', '#reset_password', reset_password)
    }

    bindEvents();
});
