const signupForm = document.getElementById('signupForm');
const loginForm = document.getElementById('loginForm');
const messageDiv = document.getElementById('message');
const logoutBtn = document.getElementById('logoutBtn');

// Check if user is already logged in (even after closing the tab)
function checkLoginStatus() {
    const token = localStorage.getItem('token'); 
    if (token) {
        messageDiv.innerText = "You are currently logged in!";
        logoutBtn.style.display = "block";
    } else {
        messageDiv.innerText = "";
        logoutBtn.style.display = "none";
    }
}
checkLoginStatus(); 

// Handle Sign Up
signupForm.addEventListener('submit', async (e) => {
    e.preventDefault(); 
    const username = document.getElementById('signupUser').value;
    const password = document.getElementById('signupPass').value;

    const response = await fetch('/signup', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ username, password })
    });
    
    const data = await response.json();
    messageDiv.innerText = data.message || data.error;
});

// Handle Log In
loginForm.addEventListener('submit', async (e) => {
    e.preventDefault();
    const username = document.getElementById('loginUser').value;
    const password = document.getElementById('loginPass').value;

    const response = await fetch('/login', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ username, password })
    });
    
    const data = await response.json();
    
    if (data.token) {
        localStorage.setItem('token', data.token); // Save token across devices
        messageDiv.innerText = "Logged in successfully!";
        checkLoginStatus();
    } else {
        messageDiv.innerText = data.error;
    }
});

// Handle Log Out
logoutBtn.addEventListener('click', () => {
    localStorage.removeItem('token'); 
    messageDiv.innerText = "You have been logged out.";
    checkLoginStatus();
});
