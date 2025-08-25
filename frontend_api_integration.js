// API Configuration
const API_BASE_URL = process.env.NODE_ENV === 'production' ? 'https://your-backend-url/api' : 'http://localhost:5000/api';

// API utility functions
const apiUtils = {
    getToken: () => window.currentAuthToken || null,
    setToken: (token) => { window.currentAuthToken = token; },
    removeToken: () => { delete window.currentAuthToken; },
    request: async (endpoint, options = {}) => {
        const url = `${API_BASE_URL}${endpoint}`;
        const token = apiUtils.getToken();
        const config = {
            headers: { 'Content-Type': 'application/json', ...options.headers },
            ...options
        };
        if (token) config.headers.Authorization = `Bearer ${token}`;
        if (options.body && typeof options.body === 'object') config.body = JSON.stringify(options.body);
        try {
            const response = await fetch(url, config);
            const data = await response.json();
            if (!response.ok) throw new Error(data.message || 'API request failed');
            return data;
        } catch (error) {
            console.error('API request failed:', error);
            throw error;
        }
    }
};

// Authentication API calls
const authAPI = {
    register: async (userData) => {
        const response = await apiUtils.request('/auth/register', { method: 'POST', body: userData });
        if (response.success && response.data.token) apiUtils.setToken(response.data.token);
        return response;
    },
    login: async (credentials) => {
        const response = await apiUtils.request('/auth/login', { method: 'POST', body: credentials });
        if (response.success && response.data.token) apiUtils.setToken(response.data.token);
        return response;
    },
    logout: async () => {
        try { await apiUtils.request('/auth/logout', { method: 'POST' }); } catch (error) { console.error('Logout failed:', error); }
        apiUtils.removeToken();
        return { success: true };
    },
    getCurrentUser: async () => apiUtils.request('/auth/me'),
    forgotPassword: async (email) => apiUtils.request('/auth/forgot-password', { method: 'POST', body: { email } }),
    resetPassword: async (token, password) => apiUtils.request('/auth/reset-password', { method: 'POST', body: { token, password } }),
    verifyEmail: async (token) => apiUtils.request('/auth/verify-email', { method: 'POST', body: { token } })
};

// Subscription API calls
const subscriptionAPI = {
    subscribeNewsletter: async (email) => apiUtils.request('/subscriptions/newsletter', { method: 'POST', body: { email } }),
    unsubscribe: async (token) => apiUtils.request('/subscriptions/unsubscribe', { method: 'POST', body: { token } }),
    getPreferences: async () => apiUtils.request('/subscriptions/preferences'),
    updatePreferences: async (preferences) => apiUtils.request('/subscriptions/preferences', { method: 'PUT', body: preferences })
};

// Updated auth functions for integration
const updatedAuthFunctions = `
function login() {
    const email = document.getElementById('loginEmail').value;
    const password = document.getElementById('loginPassword').value;
    authAPI.login({ email, password }).then(response => {
        if (response.success) {
            showAlert('Login successful!', 'success');
            window.location.href = 'dashboard.html';
        } else {
            showAlert(response.message, 'danger');
        }
    }).catch(error => showAlert('Server error', 'danger'));
}

function signup() {
    const name = document.getElementById('signupName').value;
    const email = document.getElementById('signupEmail').value;
    const password = document.getElementById('signupPassword').value;
    const role = document.getElementById('signupRole').value;
    authAPI.register({ name, email, password, role }).then(response => {
        if (response.success) {
            showAlert('Account created! Check your email to verify.', 'success');
            window.location.href = 'login.html';
        } else {
            showAlert(response.message, 'danger');
        }
    }).catch(error => showAlert('Server error', 'danger'));
}

function logout() {
    authAPI.logout().then(() => {
        showAlert('Logged out successfully.', 'success');
        window.location.href = 'index.html';
    });
}
`;