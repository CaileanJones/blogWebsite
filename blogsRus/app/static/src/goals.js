function deleteGoal() {
    fetch("http://127.0.0.1:5000/goal/DELETE", {
        method: 'POST',
        headers: {
            'Content-type': 'application/json',
            'Accept': 'application/json'
        },
        body:JSON.stringify( {"delete" : "del"} )}).then(res=> {
            if (res.ok) {
                return res.json()
            }
            else {
                alert("Something went wrong")
            }
        }).then(jsonResponse=> {
            window.location.href='/goal/redirect';
  }).catch((err) => console.error(err)); 
};
