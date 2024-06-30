document.getElementById('initializeBtn').addEventListener('click', async () => {
    const masterKey = prompt("Enter a new master key:");
    if (!masterKey) {
        alert('Master key is required to initialize');
        return;
    }
    const response = await fetch('http://172.21.37.237:8080/initialize', {
        method: 'POST',
        headers: {
            'Content-Type': 'application/json'
        },
        body: JSON.stringify({ master_key: masterKey })
    });
    if (response.ok) {
        alert('Master key initialized');
    } else {
        alert('Master key already initialized');
    }
});

document.getElementById('loginBtn').addEventListener('click', async () => {
    const masterKey = prompt("Enter your master key:");
    if (!masterKey) {
        alert('Master key is required to login');
        return;
    }
    const response = await fetch('http://172.21.37.237:8080/login', {
        method: 'POST',
        headers: {
            'Content-Type': 'application/json'
        },
        body: JSON.stringify({ master_key: masterKey })
    });
    if (response.ok) {
        alert('Login successful');
    } else {
        alert('Invalid master key');
    }
});

document.getElementById('generateBtn').addEventListener('click', async () => {
    const site = document.getElementById('siteInput').value;
    if (!site) {
        alert('Please enter a website');
        return;
    }
    const response = await fetch('http://172.21.37.237:8080/add_password', {
        method: 'POST',
        headers: {
            'Content-Type': 'application/json'
        },
        body: JSON.stringify({ site: site })
    });
    const result = await response.text();
    document.getElementById('result').innerText = result;
});

document.getElementById('showBtn').addEventListener('click', async () => {
    const response = await fetch('http://172.21.37.237:8080/show_passwords');
    if (response.ok) {
        const passwords = await response.json();
        const displayElement = document.getElementById('passwordList');
        displayElement.innerHTML = passwords.map(p => `<li>${p.site}: ${p.password}\n</li>`).join('');
    } else {
        console.error('Failed to fetch passwords');
        alert('Not authenticated');
    }
});
