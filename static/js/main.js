$DOM = $(document)
$DOM.ready(function(){
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

    function bindEvents() {
		$DOM.on('change', '#file_upload_ip', upload_file)
		    .on('input propertychange', "#post_desc", feed_desc_count)
		    .on('click', '#add_image', click_file_choose)
		    .on('click','#img_rmve_btn', remove_selected_file)
	        .on('click', '.delete_feed', delete_feed)
		    .on('click', '#post_feed', post_feed)
	        .on('click', '.like_heart', like_unlike_activity)
    }

    bindEvents();
});
