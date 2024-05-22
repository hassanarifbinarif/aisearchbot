let getFirstPageBtn = document.getElementById('pagination-get-first-record-btn');
let getPreviousPageBtn = document.getElementById('pagination-get-previous-record-btn');
let getNextPageBtn = document.getElementById('pagination-get-next-record-btn');
let getLastPageBtn = document.getElementById('pagination-get-last-record-btn');

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
    registerUserTableContainer.classList.add('hide');
    loader.classList.remove('hide');
    let response = await requestAPI(`/users/get-duplicate-data/${params}/`, null, {}, 'GET');
    response.json().then(function(res) {
        if(res.success) {
            registerUserTableContainer.innerHTML = res.html;
            loader.classList.add('hide');
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
        
        pageUrl = setParams(urlParams, 'page', parseInt(currentPage) - 1);
        getPreviousPageBtn.setAttribute('onclick', `getList('${pageUrl}')`);
        getPreviousPageBtn.classList.remove('opacity-point-3-5');
    }
    else {
        getFirstPageBtn.removeAttribute('onclick');
        getFirstPageBtn.classList.add('opacity-point-3-5');
        getPreviousPageBtn.removeAttribute('onclick');
        getPreviousPageBtn.classList.add('opacity-point-3-5');
    }

    if (has_next) {
        pageUrl = setParams(urlParams, 'page', totalPages);
        getLastPageBtn.setAttribute('onclick', `getList('${pageUrl}')`);
        getLastPageBtn.classList.remove('opacity-point-3-5');

        pageUrl = setParams(urlParams, 'page', parseInt(currentPage) + 1);
        getNextPageBtn.setAttribute('onclick', `getList('${pageUrl}')`);
        getNextPageBtn.classList.remove('opacity-point-3-5');
    }
    else {
        getLastPageBtn.removeAttribute('onclick');
        getLastPageBtn.classList.add('opacity-point-3-5');
        getNextPageBtn.removeAttribute('onclick');
        getNextPageBtn.classList.add('opacity-point-3-5');
    }
}

async function resolveConflict(toPreserve, toDelete, type) {
    let data = { toPreserve: toPreserve, toDelete: toDelete, type: type };
    let headers = { "Content-Type": "application/json" };
    let response = await requestAPI('/users/resolve-conflict/', JSON.stringify(data), headers, 'POST');
    response.json().then(function(res) {
        console.log(res);
        getList(urlParams);
    })
}