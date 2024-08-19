let getFirstPageBtn = document.getElementById('pagination-get-first-record-btn');
let getPreviousPageBtn = document.getElementById('pagination-get-previous-record-btn');
let getNextPageBtn = document.getElementById('pagination-get-next-record-btn');
let getLastPageBtn = document.getElementById('pagination-get-last-record-btn');
let filerUploaderInput = document.getElementById('file-uploader');

const sortOrders = {};

function table_sort(event, index) {
    const arrows = event.target.closest('th').querySelectorAll('path');
    table = document.getElementById('company_table')
    const currentOrder = sortOrders[index] || 'asc';
    const arr = Array.from(table.querySelectorAll('tbody tr'));
    arr.sort((a, b) => {
        const a_val = a.children[index].innerText
        const b_val = b.children[index].innerText
        return currentOrder === 'asc' ? a_val.localeCompare(b_val) : b_val.localeCompare(a_val)
    })
    arr.forEach(elem => {
        table.querySelector("tbody").appendChild(elem)
    })

    arrows[0].setAttribute('opacity', currentOrder === 'asc' ? '0.2' : '1');
    arrows[1].setAttribute('opacity', currentOrder === 'asc' ? '1' : '0.2');

    sortOrders[index] = currentOrder === 'asc' ? 'desc' : 'asc';
}

function table_sort_by_state(event, index) {
    const arrows = event.target.closest('th').querySelectorAll('path');
    table = document.getElementById('company_table')
    const currentOrder = sortOrders[index] || 'asc';
    const arr = Array.from(table.querySelectorAll('tbody tr'));
    arr.sort((a, b) => {
        const a_val = a.getAttribute('data-state')
        const b_val = b.getAttribute('data-state')
        return currentOrder === 'asc' ? a_val.localeCompare(b_val) : b_val.localeCompare(a_val)
    })
    arr.forEach(elem => {
        table.querySelector("tbody").appendChild(elem)
    })

    arrows[0].setAttribute('opacity', currentOrder === 'asc' ? '0.2' : '1');
    arrows[1].setAttribute('opacity', currentOrder === 'asc' ? '1' : '0.2');

    sortOrders[index] = currentOrder === 'asc' ? 'desc' : 'asc';
}


let urlParams = 'q=&page=';


function searchForm(event) {
    event.preventDefault();
    let form = event.currentTarget;
    let formData = new FormData(form);
    let data = formDataToObject(formData);
    urlParams = setParams(urlParams, 'q', `${data.search}`);
    urlParams = setParams(urlParams, 'page', '1');
    getList(urlParams);
}


async function getList(params) {
    let registerUserTableContainer = document.getElementById('table-container-div');
    let loader = document.querySelector('#table-loader');
    user_count = document.querySelector("#user-count")
    registerUserTableContainer.classList.add('hide');
    loader.classList.remove('hide');
    let response = await requestAPI(`/get-candidate-data/${params}/`, null, {}, 'GET');
    response.json().then(function(res) {
        if(res.success) {
            registerUserTableContainer.innerHTML = res.html;
            loader.classList.add('hide');
            user_count.innerText = `(${res.user_count})`;
            generatePages(res.current_page, res.total_pages, res.has_previous, res.has_next);
            registerUserTableContainer.classList.remove('hide');
            urlParams = params;
            
        }
    })
}

window.addEventListener('load', getList(urlParams));


function generatePages(currentPage, totalPages, has_previous, has_next) {
    const pagesContainer = document.getElementById('pages-container');
    pagesContainer.innerHTML = '';

    let startPage = Math.max(1, currentPage - 1);
    let endPage = Math.min(totalPages, startPage + 2);

    if (endPage - startPage < 2) {
        startPage = Math.max(1, endPage - 2);
    }

    if (startPage > 1) {
        pagesContainer.innerHTML += '<span class="cursor-pointer">1</span>';
        if (startPage > 2) {
            pagesContainer.innerHTML += '<span class="ellipsis-container">...</span>';
        }
    }

    for (let i = startPage; i <= endPage; i++) {
        pagesContainer.innerHTML += `<span${i === currentPage ? ' class="active"' : ' class="cursor-pointer"'}>${i}</span>`;
    }

    if (endPage < totalPages) {
        if (endPage < totalPages - 1) {
            pagesContainer.innerHTML += '<span class="ellipsis-container">...</span>';
        }
        pagesContainer.innerHTML += `<span class="cursor-pointer">${totalPages}</span>`;
    }
    pagesContainer.querySelectorAll('span').forEach((span) => {
        if ((!span.classList.contains('active'))  && (!span.classList.contains('ellipsis-container'))) {
            let page = span.innerText;
            let pageUrl = setParams(urlParams, 'page', page);
            span.setAttribute("onclick", `getList('${pageUrl}')`);
        }
    })

    if (has_previous) {
        pageUrl = setParams(urlParams, 'page', 1);
        getFirstPageBtn.setAttribute('onclick', `getList('${pageUrl}')`);
        getFirstPageBtn.classList.remove('opacity-point-3-5');
        getFirstPageBtn.classList.add('cursor-pointer');
        
        pageUrl = setParams(urlParams, 'page', parseInt(currentPage) - 1);
        getPreviousPageBtn.setAttribute('onclick', `getList('${pageUrl}')`);
        getPreviousPageBtn.classList.remove('opacity-point-3-5');
        getPreviousPageBtn.classList.add('cursor-pointer');
    }
    else {
        getFirstPageBtn.removeAttribute('onclick');
        getFirstPageBtn.classList.add('opacity-point-3-5');
        getFirstPageBtn.classList.remove('cursor-pointer');
        
        getPreviousPageBtn.removeAttribute('onclick');
        getPreviousPageBtn.classList.add('opacity-point-3-5');
        getPreviousPageBtn.classList.remove('cursor-pointer');
    }

    if (has_next) {
        pageUrl = setParams(urlParams, 'page', totalPages);
        getLastPageBtn.setAttribute('onclick', `getList('${pageUrl}')`);
        getLastPageBtn.classList.remove('opacity-point-3-5');
        getLastPageBtn.classList.add('cursor-pointer');

        pageUrl = setParams(urlParams, 'page', parseInt(currentPage) + 1);
        getNextPageBtn.setAttribute('onclick', `getList('${pageUrl}')`);
        getNextPageBtn.classList.remove('opacity-point-3-5');
        getNextPageBtn.classList.add('cursor-pointer');
    }
    else {
        getLastPageBtn.removeAttribute('onclick');
        getLastPageBtn.classList.add('opacity-point-3-5');
        getLastPageBtn.classList.remove('cursor-pointer');
        
        getNextPageBtn.removeAttribute('onclick');
        getNextPageBtn.classList.add('opacity-point-3-5');
        getNextPageBtn.classList.remove('cursor-pointer');
    }
}


async function uploadFile(event, inputField, button){
    let buttonText = button.innerText;
    let file = event.target.files;
    let formData = new FormData();
    formData.append('data_file', file[0]);
    try {
        beforeLoad(button);
        let response = await requestAPI('/import-data/', formData, {}, 'POST');
        response.json().then(function(res) {
            if (!res.success) {
                inputField.value = null;
                afterLoad(button, res.message);
                setTimeout(() => {
                    afterLoad(button, 'Import');    
                }, 1200)
            }
            else {
                inputField.value = null;
                getList(urlParams);
                afterLoad(button, 'Import');
                if (res.is_duplicate) {
                    document.querySelector('.addUser').click();
                }
            }
        })
    }
    catch (err) {
        inputField.value = null;
        afterLoad(button, 'Error');
        console.log(err);
        setTimeout(() => {
            afterLoad(button, 'Import');    
        }, 1200)
    }
}

async function exportData() {
    let response = await requestAPI('/export-data/', null, {}, 'GET');
    response.json().then(function(data) {
        console.log(data);

        // var csvContent = "data:text/csv;charset=utf-8,";
        // csvContent += Object.keys(data[0]).join(",") + "\n";
        // data.forEach(function(item, index){
        //     // csvContent += Object.values(item).join(",") + "\n";
        //     var values = Object.values(item).map(value => {
        //         // Quote values containing special characters or commas
        //         if (/[",\n]/.test(value)) {
        //             return '"' + value.replace(/"/g, '""') + '"';
        //         } else {
        //             return value;
        //         }
        //     });

        //     csvContent += values.join(",") + "\n";
        // });

        // const header = Object.keys(data[0]);
        // console.log(header);
        // const headerString = "data:text/csv;charset=utf-8," + header.join(',');
        
        // const replacer = (key, value) => value ?? '';
        // const rowItems = data.map((row) =>
        //     header
        //     .map((fieldName) => JSON.stringify(row[fieldName], replacer))
        //     .join(',')
        // );
        // // join header and body, and break into separate lines
        // const csv = [headerString, ...rowItems].join('\r\n');

        // // Create a temporary link and initiate file download
        // var encodedUri = encodeURI(csv);
        // var link = document.createElement("a");
        // link.setAttribute("href", encodedUri);
        // link.setAttribute("download", "data.csv");
        // document.body.appendChild(link);
        // link.click();
    })
}


function openDeleteCandidateModal(modalId, id) {
    let modal = document.querySelector(`#${modalId}`);
    let form = modal.querySelector("form");
    form.setAttribute("onsubmit", `delCandidateForm(event, ${id});`);
    modal.addEventListener('hidden.bs.modal', event => {
        form.reset();
        form.removeAttribute("onsubmit");
        modal.querySelector('.btn-text').innerText = 'Delete';
        document.querySelector('.delete-error-msg').classList.remove('active');
        document.querySelector('.delete-error-msg').innerText = "";
    })
    document.querySelector(`.${modalId}`).click();
}

async function delCandidateForm(event, id) {
    event.preventDefault();
    let form = event.currentTarget;
    let formData = new FormData(form);
    let data = formDataToObject(formData);
    let button = form.querySelector('button[type="submit"]');
    let buttonText = button.innerText;
    let errorMsg = form.querySelector('.delete-error-msg');

    try {
        errorMsg.innerText = '';
        errorMsg.classList.remove('active');
        let headers = { "X-CSRFToken": data.csrfmiddlewaretoken };

        beforeLoad(button);
        let response = await requestAPI(`/del-candidate/${id}/`, null, headers, "DELETE");
        response.json().then(function (res) {
            if (res.success) {
                afterLoad(button, 'Deleted');
                button.disabled = true;
                getList(urlParams);
                setTimeout(() => {
                    button.disabled = false;
                    afterLoad(button, buttonText);
                    document.querySelector('.delModal').click();
                }, 1200)
            } 
            else {
                afterLoad(button, buttonText);
                errorMsg.innerText = res.message;
                errorMsg.classList.add('active');
            }
        });
    }
    catch (err) {
        console.log(err);
    }
}