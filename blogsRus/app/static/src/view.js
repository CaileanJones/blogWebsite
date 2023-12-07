function updateData(recordToUpdateId) {
    fetch("http://127.0.0.1:5000/view/UPDATE", {
        method: 'POST',
        headers: {
            'Content-type': 'application/json',
            'Accept': 'application/json'
        },
        body:JSON.stringify( {"recordToUpdateId" : recordToUpdateId} )}).then(res=> {
            if (res.ok) {
                return res.json()
            }
            else {
                alert("Something went wrong")
            }
        }).then(jsonResponse=> {
            window.location.href='/view/redirect';
    }).catch((err) => console.error(err));   
};

function deleteData(recordToDeleteId) {
    fetch("http://127.0.0.1:5000/view/DELETE", {
        method: 'POST',
        headers: {
            'Content-type': 'application/json',
            'Accept': 'application/json'
        },
        body:JSON.stringify( {"recordToDeleteId" : recordToDeleteId} )}).then(res=> {
            if (res.ok) {
                return res.json()
            }
            else {
                alert("Something went wrong")
            }
        }).then(jsonResponse=> {
            window.location.href='/view/redirect';
    }).catch((err) => console.error(err));
};