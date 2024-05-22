async function requestAPI(url, data, headers, method) {
    // Default options are marked with *
    const response = await fetch(url, {
        method: method,
        mode: 'cors',
        // cache: 'no-cache', // *default, no-cache, reload, force-cache, only-if-cached
        headers: headers,
        body: data,
    });
    return response; // parses JSON response into native JavaScript objects
}


const phoneInput = document.querySelector("#phone");
let page_load = false
var phone = window.intlTelInput(phoneInput, {
    separateDialCode: true,
    initialCountry: "auto",
    //customPlaceholder: '000 00 000',
    showFlags:false,
    nationalMode: false,
    geoIpLookup: function(success, failure) {
        let headers = {
            Accept: "application/json",
        };
        requestAPI("https://ipinfo.io", null, headers, 'GET').then(function(response) {
            if (!response.ok) {
                throw new Error("Network response was not ok");
            }
            return response.json();
        }).then(function(resp) {
            var countryCode = (resp && resp.country) ? resp.country : "us";
            success(countryCode);
        }).catch(function(error) {
            if (typeof failure === "function") {
                failure(error.message);
            }
        })
    },
    hiddenInput: "full",
    utilsScript: "https://cdn.jsdelivr.net/npm/intl-tel-input@18.2.1/build/js/utils.js",
});

phone.promise.then(() => {
    phoneInput.value = phone_number;
})
const input = document.querySelector("#phone");
const errorMsg = document.querySelector("#error-msg");
const validMsg = document.querySelector("#valid-msg");
const sumit_btn = document.querySelector('#sumit_btn');
// here, the index maps to the error code returned from getValidationError - see readme
const errorMap = ["Invalid number", "Invalid country code", "Too short", "Too long", "Invalid number"];

// initialise plugin
// const iti = window.intlTelInput(input, {
//     initialCountry: "us",
//     utilsScript: "/intl-tel-input/js/utils.js?1714308177587"
//   });

const reset = () => {
    input.classList.remove("error");
    errorMsg.innerHTML = "";
    errorMsg.classList.add("hide");
    validMsg.classList.add("hide");
};
const showError = (msg) => {
    input.classList.add("error");
    errorMsg.innerHTML = msg;
    errorMsg.classList.remove("hide");
  };
  
// on click button: validate
phoneInput.addEventListener('keyup', () => {
    reset();
    if (!input.value.trim()) {
      showError("Required");
      sumit_btn.disabled = true;
    } else if (phone.isValidNumber()) {
      validMsg.classList.remove("hide");
      sumit_btn.disabled = false;
    } else {
      const errorCode = phone.getValidationError();
      const msg = errorMap[errorCode] || "Invalid number";
      showError(msg);
      sumit_btn.disabled = true;
    }
});
  
phoneInput.addEventListener("countrychange", function() {
    if (page_load){
        this.dispatchEvent(new KeyboardEvent('keyup'));
    }
    page_load = true
});

phoneInput.addEventListener("input", function() {
    var full_number = phone.getNumber(intlTelInputUtils.numberFormat.INTERNATIONAL);
    full_number = full_number.replaceAll(" ", "");
    full_number = full_number.replaceAll("-", "");
    this.value = full_number;
});
phoneInput.addEventListener("change", function() {
    var full_number = phone.getNumber(intlTelInputUtils.numberFormat.INTERNATIONAL);
    full_number = full_number.replaceAll(" ", "");
    full_number = full_number.replaceAll("-", "");
    this.value = full_number;
});
phoneInput.addEventListener("paste", function() {
    var full_number = phone.getNumber(intlTelInputUtils.numberFormat.INTERNATIONAL);
    full_number = full_number.replaceAll(" ", "");
    full_number = full_number.replaceAll("-", "");
    this.value = full_number;
});