function togglePasswordField(event, icon) {
    let passwordField = icon.closest('.password-input-div').querySelector('input[data-type="password"]');

    if (icon.classList.contains('hide-password-icon') && passwordField.type == 'password') {
        passwordField.type = 'text';
        icon.classList.add('hide');
        console.log(icon.closest('.password-input-div').querySelector('.show-password-icon'));
        icon.closest('.password-input-div').querySelector('.show-password-icon').classList.remove('hide');
    }
    else if (icon.classList.contains('show-password-icon') && passwordField.type == 'text') {
        passwordField.type = 'password';
        icon.classList.add('hide');
        icon.closest('.password-input-div').querySelector('.hide-password-icon').classList.remove('hide');
    }
}

function preventSubmission(event) {
    event.preventDefault(); 
    location.pathname = '/account/'
}
function formDataToObject(formData) {
    let getData = {}
    formData.forEach(function(value, key) {
        getData[key] = value;
    });
    return getData
}

let old_password = document.getElementById('old_password_errors')
let password1 = document.getElementById('new_password1_errors')
let password2 = document.getElementById('new_password2_errors')


function updatePasswordForm(event) {
    event.preventDefault()
    let form = event.currentTarget;
    let formData = new FormData(form);
    let data = formDataToObject(formData);
    let isValid = true
    
    if (data.old_password.length < 8) {
        old_password.innerText = 'Password must be atleast 8 characters';
        isValid = false
    }
    else
        old_password.innerText = ''

    if (data.new_password1.length < 8) {
        password1.innerText = 'Password must be atleast 8 characters';
        isValid = false
    }
    else
        password1.innerText = ''
    if (data.new_password2.length < 8) {
        password2.innerText = 'Confirm Password must be atleast 8 characters';
        isValid = false
    }
    else
        password2.innerText= ''
    if (data.new_password1 != data.new_password2 || data.new_password2.length == 0) {
        password2.innerText = 'Password and Confirm Password do not match';
        isValid = false
    }
    else{
        password2.innerText=''
    }

    if(!isValid)
        return false
    form.submit();
}