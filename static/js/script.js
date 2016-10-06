$(document).ready(function() {
	$(document).click(function(event) {
		if ($(event.target).hasClass("open-modal")) {
			event.preventDefault()
			var modalID = event.target.id.split("-")[1];
	    	$("#edit-"+modalID).modal("show");
		}
		if ($(event.target).hasClass("show-delete")) {
			event.preventDefault()
			var deleteID = event.target.id.split("-")[1];
			var target = "#confirm-" + deleteID;
			// console.log(target);
			$(target).removeClass("delete-warning");
			// $(target).delay(300).fadeIn(1000);
			
			$("#no-"+deleteID).click(function(e) {
				e.preventDefault();
				// console.log(target);
				$(target).addClass("delete-warning");
				// $("target").slideUp(500);
			});
		}
	});
	// $("#com-edit").click(function (e) {
	// 	e.preventDefault();
	// 	$("#slide-bottom-popup").modal("show"); // milliseconds
	// });
      
    $("#login-form-link").click(function(e) {
		$("#login-form").delay(100).fadeIn(100);
 		$("#register-form").fadeOut(100);
		$('#register-form-link').removeClass('active');
		$(this).addClass('active');
		e.preventDefault();
	});
	$('#register-form-link').click(function(e) {
		$("#register-form").delay(100).fadeIn(100);
 		$("#login-form").fadeOut(100);
		$('#login-form-link').removeClass('active');
		$(this).addClass('active');
		e.preventDefault();
	});
});
// Like and unlike
$(document).ready(function() {
	if ($(".heart").attr("rel") === "liked") {
		$(".heart").css("background-position", "right");
	}
	$("body").on("click", ".heart", function() {
		// var currentCount =parseInt($(".likeCount").html());
    	// $(this).css("background-position","");
		var D = $(this).attr("rel");
		if (D === "notliked") {
			// $(".likeCount").html(currentCount+1);
			$(this).addClass("heartAnimation");
			$("#likeform").submit();
		} else {
			// $(".likeCount").html(currentCount-1); 
			$(this).removeClass("heartAnimation");
			$(this).css("background-position","left");
			$("#likeform").submit();
		}
		
    });
});
// Navigation Scripts to Show Header on Scroll-Up
$(document).ready(function(o) {
    var s = 1170;
    if (o(window).width() > s) {
        var i = o(".navbar-custom").height();
        o(window).on("scroll", {
            previousTop: 0
        }, function() {
            var s = o(window).scrollTop();
            s < this.previousTop ? s > 0 && o(".navbar-custom").hasClass("is-fixed") ? o(".navbar-custom").addClass("is-visible") : o(".navbar-custom").removeClass("is-visible is-fixed") : s > this.previousTop && (o(".navbar-custom").removeClass("is-visible"), s > i && !o(".navbar-custom").hasClass("is-fixed") && o(".navbar-custom").addClass("is-fixed")), this.previousTop = s
        })
    }
});