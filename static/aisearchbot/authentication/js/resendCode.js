var storedCountdownTime = localStorage.getItem('timestamp');

if(storedCountdownTime !== null) {
    var currentTime = new Date().getTime();
    var elapsedTime = Math.floor((currentTime - parseInt(storedCountdownTime)) / 1000);
    var remainingCountdownTime = 20 - elapsedTime;
    if (remainingCountdownTime > 0) {
        disableLinkAndStartCountdown(remainingCountdownTime);
    } else {
        localStorage.removeItem('timestamp'); // Remove expired timestamp
    }
}

function resendOTP() {
    email = document.getElementById('varification_email').textContent
    getNewOTP(email)
    var currentTime = new Date().getTime();
    localStorage.setItem('timestamp', currentTime);
    var savedTimestamp = localStorage.getItem('timestamp');
    var elapsedTime = savedTimestamp ? Math.floor((currentTime - parseInt(savedTimestamp)) / 1000) : 0;
    var countdownTime = 20 - elapsedTime;
    disableLinkAndStartCountdown(countdownTime);
}

function disableLinkAndStartCountdown(countdownTime) {
    var resendbtn = document.getElementById('resendLink');
    resendbtn.classList.add('disabled');
    function updateCountdown() {
        resendbtn.innerHTML = 'Resend Code in ' + countdownTime + ' seconds';
        countdownTime--;
        if (countdownTime < 0) {
            resendbtn.classList.remove('disabled');
            resendbtn.innerHTML = 'Resend Code';              
            
        } else {
            setTimeout(updateCountdown, 1000);
        }
    }
    updateCountdown();
}

function getNewOTP(email) {
    var csrfToken = document.querySelector('input[name="csrfmiddlewaretoken"]').value
    $.ajax({
        type: "POST",
        url: '/send-otp/',
        headers: {
            "X-CSRFToken": csrfToken 
        },
        data: {
            "email": email
        },
        dataType: "json",
        success: function(token) {
            console.log('Token received: ' + token);
            console.log('OTP sent to this email address: ' + email); 
        },
        error: function(xhr, status, error) {
            
            console.log('Failed to send OTP: ' + error); 
        }
    });
}
