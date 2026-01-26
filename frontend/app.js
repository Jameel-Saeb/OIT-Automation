// Version: 2026-01-17-v1 - Added column selection dropdowns
const API_BASE_URL = 'http://localhost:5001/api';

// Google OAuth token storage
let googleAccessToken = null;
let googleClientId = null;

// Global sheet connection info
let connectedSheetUrl = null;
let connectedSheetName = null;
let isSheetConnected = false;

// Helper function to get the connected sheet info
function getConnectedSheetInfo() {
    // Use global variables first, fall back to DOM elements (Connection tab)
    const url = connectedSheetUrl || document.getElementById('sheet-url')?.value || '';
    const name = connectedSheetName || document.getElementById('sheet-name')?.value || '';
    console.log('getConnectedSheetInfo - url:', url, 'name:', name);
    return { url, name };
}

// Helper function to check if sheet is connected and show error if not
function requireSheetConnection(statusElementId) {
    console.log('requireSheetConnection called, isSheetConnected:', isSheetConnected);
    console.log('connectedSheetUrl:', connectedSheetUrl, 'connectedSheetName:', connectedSheetName);
    
    if (!isSheetConnected || !connectedSheetUrl || !connectedSheetName) {
        if (statusElementId) {
            showStatus(statusElementId, 'Please connect to a Google Sheet first (in the Connection tab)', 'error');
        }
        return null;
    }
    return { url: connectedSheetUrl, name: connectedSheetName };
}

// Helper function to refresh sheet connection (re-read data)
async function refreshSheetConnection() {
    const sheetInfo = getConnectedSheetInfo();
    if (!sheetInfo.url || !sheetInfo.name) {
        return false;
    }
    
    try {
        const oauthState = getOAuthState();
        await apiCall('/sheets/connect', 'POST', {
            sheet_url: sheetInfo.url,
            sheet_name: sheetInfo.name,
            oauth_state: oauthState
        });
        return true;
    } catch (error) {
        console.error('Failed to refresh sheet connection:', error);
        return false;
    }
}

// Update connection indicators in all tabs
function updateConnectionIndicators() {
    const indicators = ['add', 'revoke', 'status', 'convert', 'compare'];
    
    console.log('Updating indicators, isSheetConnected:', isSheetConnected);
    console.log('connectedSheetUrl:', connectedSheetUrl);
    console.log('connectedSheetName:', connectedSheetName);
    
    indicators.forEach(tab => {
        const indicator = document.getElementById(`${tab}-sheet-indicator`);
        console.log(`Looking for ${tab}-sheet-indicator:`, indicator);
        if (indicator) {
            if (isSheetConnected && connectedSheetUrl && connectedSheetName) {
                indicator.innerHTML = `🟢 Connected to: <strong>${connectedSheetName}</strong>`;
                indicator.parentElement.style.background = '#e8f5e9';
                indicator.parentElement.style.borderLeft = '4px solid #4caf50';
            } else {
                indicator.innerHTML = '⚪ No sheet connected - <a href="#" onclick="showTab(\'connection\'); return false;">Connect first</a>';
                indicator.parentElement.style.background = '#fff3e0';
                indicator.parentElement.style.borderLeft = '4px solid #ff9800';
            }
        }
    });
}

// Initialize Google Identity Services when page loads
window.addEventListener('load', function() {
    // Initialize the auth indicator to "not signed in"
    updateAuthIndicator(false);
    
    // Update connection indicators
    updateConnectionIndicators();
    
    // Check if returning from OAuth redirect
    const urlParams = new URLSearchParams(window.location.search);
    const oauthSuccess = urlParams.get('oauth_success');
    const oauthError = urlParams.get('oauth_error');
    const state = urlParams.get('state');
    const error = urlParams.get('error');
    
    if (oauthSuccess === 'true' && state) {
        // Restore state from sessionStorage
        const storedState = sessionStorage.getItem('oauth_state');
        const flowType = sessionStorage.getItem('oauth_flow');
        
        if (storedState === state) {
            currentOAuthState = state;
            updateAuthIndicator(true, 'Successfully authenticated with Google!');
            showStatus('oauth-status', 'Successfully signed in with Google! You can now connect to sheets.', 'success');
            document.getElementById('connect-btn').disabled = false;
            
            // Clean up sessionStorage
            sessionStorage.removeItem('oauth_state');
            sessionStorage.removeItem('oauth_flow');
            
            // Clean up URL
            window.history.replaceState({}, document.title, window.location.pathname);
        }
    } else if (oauthError === 'true') {
        updateAuthIndicator(false, 'Authorization failed - please try again');
        showStatus('oauth-status', `Authorization failed: ${error || 'Unknown error'}`, 'error');
        
        // Clean up sessionStorage
        sessionStorage.removeItem('oauth_state');
        sessionStorage.removeItem('oauth_flow');
        
        // Clean up URL
        window.history.replaceState({}, document.title, window.location.pathname);
    }
    
    // Get client ID from backend or use default
    fetch(`${API_BASE_URL}/sheets/oauth/client-id`)
        .then(response => response.json())
        .then(data => {
            if (data.client_id) {
                googleClientId = data.client_id;
                initializeGoogleSignIn(data.client_id);
            } else {
                // Show button area with helpful message
                const buttonContainer = document.getElementById('g_id_signin');
                if (buttonContainer) {
                    buttonContainer.innerHTML = `
                        <div style="padding: 20px; border: 2px dashed #ccc; border-radius: 8px; background: #f9f9f9;">
                            <p style="margin: 0 0 10px 0; color: #666;"><strong>Google Sign-In Not Configured</strong></p>
                            <p style="margin: 0 0 15px 0; color: #666; font-size: 0.9em;">
                                To enable Google Sign-In, please set <code>GOOGLE_CLIENT_ID</code> in your <code>.env</code> file.
                            </p>
                            <p style="margin: 0; font-size: 0.85em; color: #888;">
                                Get your Client ID from: 
                                <a href="https://console.cloud.google.com/apis/credentials" target="_blank" style="color: #667eea;">
                                    Google Cloud Console
                                </a>
                            </p>
                        </div>
                    `;
                }
                showStatus('oauth-status', 'OAuth not configured. Please set GOOGLE_CLIENT_ID in .env file. See instructions above.', 'error');
            }
        })
        .catch(error => {
            console.error('Error fetching client ID:', error);
            const buttonContainer = document.getElementById('g_id_signin');
            if (buttonContainer) {
                buttonContainer.innerHTML = `
                    <div style="padding: 20px; border: 2px dashed #ccc; border-radius: 8px; background: #f9f9f9;">
                        <p style="margin: 0; color: #666;">Could not connect to server. Please make sure the backend is running.</p>
                    </div>
                `;
            }
            showStatus('oauth-status', 'Could not initialize Google Sign-In. Please check server configuration.', 'error');
        });
});

// Initialize Google Sign-In
function initializeGoogleSignIn(clientId) {
    // Wait for Google Identity Services to load
    if (typeof google === 'undefined' || !google.accounts || !google.accounts.id) {
        setTimeout(() => initializeGoogleSignIn(clientId), 100);
        return;
    }
    
    try {
        google.accounts.id.initialize({
            client_id: clientId,
            callback: handleGoogleSignIn
        });
        
        google.accounts.id.renderButton(
            document.getElementById('g_id_signin'),
            {
                type: 'standard',
                size: 'large',
                theme: 'outline',
                text: 'sign_in_with',
                shape: 'rectangular',
                logo_alignment: 'left'
            }
        );
        
        // Optional: Show One Tap (can be annoying, so commented out)
        // google.accounts.id.prompt();
    } catch (error) {
        console.error('Error initializing Google Sign-In:', error);
        const buttonContainer = document.getElementById('g_id_signin');
        if (buttonContainer) {
            buttonContainer.innerHTML = `
                <div style="padding: 20px; border: 2px dashed #ccc; border-radius: 8px; background: #f9f9f9;">
                    <p style="margin: 0; color: #666;">Error initializing Google Sign-In. Please refresh the page.</p>
                </div>
            `;
        }
    }
}

// Handle Google Sign-In callback
function handleGoogleSignIn(response) {
    if (response.credential) {
        // This is a JWT token from Google
        googleAccessToken = response.credential;
        
        // Exchange JWT for access token via backend
        exchangeTokenForAccess(response.credential);
    }
}

// Exchange JWT credential for access token
async function exchangeTokenForAccess(credential) {
    updateAuthIndicator(false, 'Authenticating with Google...');
    showStatus('oauth-status', 'Authenticating with Google...', 'info');
    
    try {
        // Send current page URL so callback knows where to redirect
        // Normalize the URL - if pathname is just '/', use '/index.html'
        let pathname = window.location.pathname;
        if (pathname === '/' || pathname === '') {
            pathname = '/index.html';
        }
        const frontendUrl = window.location.origin + pathname;
        console.log('Sending frontend URL to backend:', frontendUrl);
        const result = await apiCall('/sheets/oauth/exchange-token', 'POST', {
            credential: credential,
            frontend_url: frontendUrl
        });
        
        if (result.success) {
            // Store the state before redirecting
            sessionStorage.setItem('oauth_state', result.state);
            sessionStorage.setItem('oauth_flow', 'google_signin');
            
            // Redirect to authorization URL (no popup needed!)
            updateAuthIndicator(false, 'Redirecting to Google for authorization...');
            showStatus('oauth-status', 'Redirecting to Google for authorization...', 'info');
            window.location.href = result.authorization_url;
        } else {
            updateAuthIndicator(false, 'Authentication failed - please try again');
            showStatus('oauth-status', `Error: ${result.error}`, 'error');
        }
    } catch (error) {
        updateAuthIndicator(false, 'Authentication failed - please try again');
        showStatus('oauth-status', `Error: ${error.message}`, 'error');
    }
}

// Connect to sheets using stored token
async function connectSheetsWithToken() {
    const sheetUrl = document.getElementById('sheet-url').value;
    const sheetName = document.getElementById('sheet-name').value;
    
    if (!sheetUrl || !sheetName) {
        showStatus('sheets-status', 'Please provide both Sheet URL and Worksheet Name', 'error');
        return;
    }
    
    if (!currentOAuthState) {
        showStatus('sheets-status', 'Please sign in with Google first', 'error');
        return;
    }
    
    clearStatus('sheets-status');
    showStatus('sheets-status', 'Connecting to Google Sheets...', 'info');
    
    try {
        const result = await apiCall('/sheets/connect', 'POST', {
            sheet_url: sheetUrl,
            sheet_name: sheetName,
            oauth_state: currentOAuthState
        });
        
        if (result.success) {
            // Store the connected sheet info globally
            connectedSheetUrl = sheetUrl;
            connectedSheetName = sheetName;
            isSheetConnected = true;
            
            // Update all connection indicators
            updateConnectionIndicators();
            
            showStatus('sheets-status', 
                `Connected successfully! Found ${result.columns_count} columns. This sheet will be used for all operations.`, 
                'success'
            );
        } else {
            isSheetConnected = false;
            updateConnectionIndicators();
            showStatus('sheets-status', `Error: ${result.error}`, 'error');
        }
    } catch (error) {
        isSheetConnected = false;
        updateConnectionIndicators();
        showStatus('sheets-status', `Error: ${error.message}`, 'error');
    }
}

// Tab management
function showTab(tabName, clickedButton) {
    // Hide all tabs
    document.querySelectorAll('.tab-content').forEach(tab => {
        tab.classList.remove('active');
    });
    
    // Remove active class from all buttons
    document.querySelectorAll('.tab-button').forEach(btn => {
        btn.classList.remove('active');
    });
    
    // Show selected tab
    document.getElementById(tabName).classList.add('active');
    
    // Add active class to clicked button
    if (clickedButton) {
        clickedButton.classList.add('active');
    }
    
    // Update connection indicators whenever switching tabs
    updateConnectionIndicators();
}

// Utility functions
function showStatus(elementId, message, type = 'info') {
    const element = document.getElementById(elementId);
    element.textContent = message;
    element.className = `status-message ${type}`;
    element.style.display = 'block';
}

function clearStatus(elementId) {
    const element = document.getElementById(elementId);
    element.style.display = 'none';
}

function showResults(elementId, results, formatFunction) {
    const element = document.getElementById(elementId);
    element.innerHTML = formatFunction(results);
}

// API call wrapper
async function apiCall(endpoint, method = 'GET', data = null) {
    try {
        const options = {
            method,
            headers: {
                'Content-Type': 'application/json',
            }
        };
        
        if (data) {
            options.body = JSON.stringify(data);
        }
        
        const response = await fetch(`${API_BASE_URL}${endpoint}`, options);
        const result = await response.json();
        
        if (!response.ok) {
            throw new Error(result.error || 'Request failed');
        }
        
        return result;
    } catch (error) {
        throw error;
    }
}

// Helper function to get service account data
async function getServiceAccountData() {
    const fileInput = document.getElementById('service-account-file');
    const jsonInput = document.getElementById('service-account-json');
    
    // Check if elements exist (they're only on the connection tab)
    if (!fileInput || !jsonInput) {
        return {};
    }
    
    const jsonInputValue = jsonInput.value.trim();
    
    // If JSON text is provided, use it
    if (jsonInputValue) {
        try {
            const jsonData = JSON.parse(jsonInputValue);
            return { service_account_json: jsonData };
        } catch (e) {
            throw new Error('Invalid JSON in service account field');
        }
    }
    
    // If file is provided, read it
    if (fileInput.files && fileInput.files.length > 0) {
        return new Promise((resolve, reject) => {
            const file = fileInput.files[0];
            const reader = new FileReader();
            reader.onload = (e) => {
                try {
                    const jsonData = JSON.parse(e.target.result);
                    resolve({ service_account_json: jsonData });
                } catch (err) {
                    reject(new Error('Invalid JSON file'));
                }
            };
            reader.onerror = () => reject(new Error('Error reading file'));
            reader.readAsText(file);
        });
    }
    
    return {};
}

// OAuth state storage
let currentOAuthState = null;

// Helper function to get current OAuth state
function getOAuthState() {
    return currentOAuthState;
}

// Update Google Sign-In status indicator
function updateAuthIndicator(isSignedIn, details = '') {
    const indicator = document.getElementById('google-auth-indicator');
    const icon = document.getElementById('auth-status-icon');
    const text = document.getElementById('auth-status-text');
    const detailsElement = document.getElementById('auth-status-details');
    
    if (!indicator || !icon || !text || !detailsElement) return;
    
    if (isSignedIn) {
        // Signed in - green indicator
        indicator.style.borderLeftColor = '#48bb78';
        indicator.style.background = '#f0fff4';
        icon.textContent = '🟢';
        text.textContent = 'Signed in with Google';
        detailsElement.textContent = details || 'You can now connect to Google Sheets';
        document.getElementById('connect-btn').disabled = false;
    } else {
        // Not signed in - gray indicator
        indicator.style.borderLeftColor = '#cbd5e0';
        indicator.style.background = '#f5f5f5';
        icon.textContent = '⚪';
        text.textContent = 'Not signed in';
        detailsElement.textContent = details || 'Click the button below to sign in with Google';
        document.getElementById('connect-btn').disabled = true;
    }
}

// Listen for OAuth callback messages
window.addEventListener('message', function(event) {
    // Accept messages from any origin (for local development)
    if (event.data.type === 'oauth_success') {
        currentOAuthState = event.data.state;
        showStatus('oauth-status', 'Successfully signed in with Google! You can now connect to sheets.', 'success');
        document.getElementById('connect-btn').disabled = false;
    } else if (event.data.type === 'oauth_error') {
        showStatus('oauth-status', `Authorization failed: ${event.data.error}`, 'error');
        currentOAuthState = null;
    }
});

// Connect with Google OAuth
async function connectWithGoogle() {
    const clientId = document.getElementById('oauth-client-id').value.trim();
    const clientSecret = document.getElementById('oauth-client-secret').value.trim();
    
    clearStatus('oauth-status');
    showStatus('oauth-status', 'Starting Google authorization...', 'info');
    
    try {
        const result = await apiCall('/sheets/oauth/authorize', 'POST', {
            client_id: clientId || undefined,
            client_secret: clientSecret || undefined
        });
        
        if (result.success) {
            // Open OAuth URL in popup
            const width = 600;
            const height = 700;
            const left = (screen.width - width) / 2;
            const top = (screen.height - height) / 2;
            
            const popup = window.open(
                result.authorization_url,
                'Google Authorization',
                `width=${width},height=${height},left=${left},top=${top},resizable=yes,scrollbars=yes`
            );
            
            currentOAuthState = result.state;
            showStatus('oauth-status', 'Please complete authorization in the popup window...', 'info');
            
            // Check if popup was closed
            const checkClosed = setInterval(() => {
                if (popup.closed) {
                    clearInterval(checkClosed);
                    if (!currentOAuthState) {
                        showStatus('oauth-status', 'Authorization was cancelled or failed.', 'error');
                    }
                }
            }, 500);
        } else {
            showStatus('oauth-status', `Error: ${result.error}`, 'error');
        }
    } catch (error) {
        showStatus('oauth-status', `Error: ${error.message}`, 'error');
    }
}

// Connect to sheets using OAuth
async function connectSheetsWithOAuth() {
    const sheetUrl = document.getElementById('sheet-url').value;
    const sheetName = document.getElementById('sheet-name').value;
    
    if (!sheetUrl || !sheetName) {
        showStatus('oauth-status', 'Please enter Sheet URL and Worksheet Name first', 'error');
        return;
    }
    
    if (!currentOAuthState) {
        showStatus('oauth-status', 'Please authorize with Google first', 'error');
        return;
    }
    
    try {
        const result = await apiCall('/sheets/connect', 'POST', {
            sheet_url: sheetUrl,
            sheet_name: sheetName,
            oauth_state: currentOAuthState
        });
        
        if (result.success) {
            showStatus('oauth-status', 
                `Connected successfully! Found ${result.columns_count} columns.`, 
                'success'
            );
        } else {
            showStatus('oauth-status', `Error: ${result.error}`, 'error');
        }
    } catch (error) {
        showStatus('oauth-status', `Error: ${error.message}`, 'error');
    }
}

// Connection functions
async function connectSheets() {
    const sheetUrl = document.getElementById('sheet-url').value;
    const sheetName = document.getElementById('sheet-name').value;
    
    if (!sheetUrl || !sheetName) {
        showStatus('sheets-status', 'Please provide both Sheet URL and Worksheet Name', 'error');
        return;
    }
    
    clearStatus('sheets-status');
    showStatus('sheets-status', 'Connecting to Google Sheets...', 'info');
    
    try {
        const serviceAccountData = await getServiceAccountData();
        const result = await apiCall('/sheets/connect', 'POST', {
            sheet_url: sheetUrl,
            sheet_name: sheetName,
            ...serviceAccountData
        });
        
        showStatus('sheets-status', 
            `Connected successfully! Found ${result.columns_count} columns.`, 
            'success'
        );
    } catch (error) {
        showStatus('sheets-status', `Error: ${error.message}`, 'error');
    }
}

async function login() {
    const username = document.getElementById('username').value;
    const password = document.getElementById('password').value;
    
    if (!username || !password) {
        showStatus('login-status', 'Please enter both username and password', 'error');
        return;
    }
    
    clearStatus('login-status');
    showStatus('login-status', 'Logging in... Please approve Duo push on your phone.', 'info');
    
    try {
        const result = await apiCall('/automation/login', 'POST', {
            username,
            password
        });
        
        showStatus('login-status', result.message || 'Login successful!', 'success');
    } catch (error) {
        showStatus('login-status', `Error: ${error.message}`, 'error');
    }
}

// Add privileges
async function addPrivileges() {
    // Get sheet info from global connection
    const sheetInfo = requireSheetConnection('add-status');
    if (!sheetInfo) return;
    
    const appName = document.getElementById('add-app-name').value;
    let dpNumber = document.getElementById('add-dp-number').value.trim();
    // Normalize DP prefix - ensure it's always uppercase "DP"
    if (dpNumber) {
        if (dpNumber.toUpperCase().startsWith('DP')) {
            dpNumber = 'DP' + dpNumber.substring(2);
        } else {
            dpNumber = 'DP' + dpNumber;
        }
    }
    const performedByName = document.getElementById('add-performed-by-name').value;
    const columnIndex = parseInt(document.getElementById('add-read-column').value);
    
    if (!performedByName || performedByName.trim() === '') {
        showStatus('add-status', 'Please provide a Performed By Name', 'error');
        return;
    }
    
    clearStatus('add-status');
    clearResults('add-results');
    showStatus('add-status', 'Refreshing sheet data and processing...', 'info');
    
    try {
        const oauthState = getOAuthState();
        
        // First, refresh the sheet connection to get latest data
        await apiCall('/sheets/connect', 'POST', {
            sheet_url: sheetInfo.url,
            sheet_name: sheetInfo.name,
            oauth_state: oauthState
        });
        
        const requestData = {
            sheet_url: sheetInfo.url,
            sheet_name: sheetInfo.name,
            app_name: appName,
            dp_number: dpNumber,
            performed_by_name: performedByName.trim(),
            column_index: columnIndex,
            oauth_state: oauthState
        };
        
        const result = await apiCall('/automation/add', 'POST', requestData);
        
        showStatus('add-status', 
            `Completed: ${result.successful} successful out of ${result.total}`, 
            result.successful === result.total ? 'success' : 'info'
        );
        
        showResults('add-results', result.results, formatAddResults);
    } catch (error) {
        showStatus('add-status', `Error: ${error.message}`, 'error');
    }
}

function formatAddResults(results) {
    if (!results || results.length === 0) return '<p>No results</p>';
    
    let html = '<table><thead><tr><th>ID</th><th>Status</th><th>Error</th></tr></thead><tbody>';
    
    results.forEach(result => {
        const statusClass = result.success ? 'success' : 'error';
        const statusText = result.success ? 'Success' : 'Failed';
        html += `
            <tr class="result-item ${statusClass}">
                <td>${result.id}</td>
                <td>${statusText}</td>
                <td>${result.error || '-'}</td>
            </tr>
        `;
    });
    
    html += '</tbody></table>';
    return html;
}

// Revoke privileges
async function revokePrivileges() {
    // Get sheet info from global connection
    const sheetInfo = requireSheetConnection('revoke-status');
    if (!sheetInfo) {
        return;
    }
    
    // Refresh sheet data before processing
    showStatus('revoke-status', 'Refreshing sheet data...', 'info');
    const refreshed = await refreshSheetConnection();
    if (!refreshed) {
        showStatus('revoke-status', 'Failed to refresh sheet connection', 'error');
        return;
    }
    
    const appName = document.getElementById('revoke-app-name').value;
    let dpNumber = document.getElementById('revoke-dp-number').value.trim();
    // Normalize DP prefix - ensure it's always uppercase "DP"
    if (dpNumber) {
        if (dpNumber.toUpperCase().startsWith('DP')) {
            dpNumber = 'DP' + dpNumber.substring(2);
        } else {
            dpNumber = 'DP' + dpNumber;
        }
    }
    const columnIndex = parseInt(document.getElementById('revoke-read-column').value);
    
    clearStatus('revoke-status');
    clearResults('revoke-results');
    showStatus('revoke-status', 'Reading IDs from sheet and processing...', 'info');
    
    try {
        const serviceAccountData = await getServiceAccountData();
        const oauthState = getOAuthState();
        const requestData = {
            sheet_url: sheetInfo.url,
            sheet_name: sheetInfo.name,
            app_name: appName,
            dp_number: dpNumber,
            column_index: columnIndex
        };
        
        if (oauthState) {
            requestData.oauth_state = oauthState;
        } else {
            Object.assign(requestData, serviceAccountData);
        }
        
        const result = await apiCall('/automation/revoke', 'POST', requestData);
        
        showStatus('revoke-status', 
            `Completed: ${result.successful} successful out of ${result.total}`, 
            result.successful === result.total ? 'success' : 'info'
        );
        
        showResults('revoke-results', result.results, formatRevokeResults);
    } catch (error) {
        showStatus('revoke-status', `Error: ${error.message}`, 'error');
    }
}

function formatRevokeResults(results) {
    return formatAddResults(results); // Same format
}

// Get employment status
async function getEmploymentStatus() {
    // Get sheet info from global connection
    const sheetInfo = requireSheetConnection('status-status');
    if (!sheetInfo) {
        return;
    }
    
    // Refresh sheet data before processing
    showStatus('status-status', 'Refreshing sheet data...', 'info');
    const refreshed = await refreshSheetConnection();
    if (!refreshed) {
        showStatus('status-status', 'Failed to refresh sheet connection', 'error');
        return;
    }
    
    const idsText = document.getElementById('status-ids').value;
    const idType = document.getElementById('status-id-type').value;
    const columnIndex = parseInt(document.getElementById('status-read-column').value);
    const writeColumn = document.getElementById('status-write-column').value;
    const sourceColumn = document.getElementById('status-source-column').value;
    
    const ids = idsText.trim() ? idsText.split('\n').map(id => id.trim()).filter(id => id) : [];
    
    clearStatus('status-status');
    clearResults('status-results');
    showStatus('status-status', 'Fetching employment status...', 'info');
    
    try {
        const serviceAccountData = await getServiceAccountData();
        const oauthState = getOAuthState();
        const requestData = {
            sheet_url: sheetInfo.url,
            sheet_name: sheetInfo.name,
            ids: ids.length > 0 ? ids : undefined,
            id_type: idType,
            column_index: columnIndex,
            write_column: writeColumn,
            source_column: sourceColumn
        };
        
        if (oauthState) {
            requestData.oauth_state = oauthState;
        } else {
            Object.assign(requestData, serviceAccountData);
        }
        
        const result = await apiCall('/automation/get-employment-status', 'POST', requestData);
        
        showStatus('status-status', `Status retrieved and written to columns ${writeColumn} and ${sourceColumn}`, 'success');
        showResults('status-results', result.results, formatStatusResults);
    } catch (error) {
        showStatus('status-status', `Error: ${error.message}`, 'error');
    }
}

function formatStatusResults(results) {
    if (!results || results.length === 0) return '<p>No results</p>';
    
    let html = '<table><thead><tr><th>ID</th><th>Employment Status</th><th>Source</th><th>Status</th></tr></thead><tbody>';
    
    results.forEach(result => {
        const statusClass = result.success ? 'success' : 'error';
        html += `
            <tr class="result-item ${statusClass}">
                <td>${result.id}</td>
                <td>${result.employment_status || '-'}</td>
                <td>${result.source || '-'}</td>
                <td>${result.success ? 'Success' : result.error}</td>
            </tr>
        `;
    });
    
    html += '</tbody></table>';
    return html;
}

// Convert IDs
async function convertIds() {
    // Get sheet info from global connection
    const sheetInfo = requireSheetConnection('convert-status');
    if (!sheetInfo) {
        return;
    }
    
    // Refresh sheet data before processing
    showStatus('convert-status', 'Refreshing sheet data...', 'info');
    const refreshed = await refreshSheetConnection();
    if (!refreshed) {
        showStatus('convert-status', 'Failed to refresh sheet connection', 'error');
        return;
    }
    
    const idsText = document.getElementById('convert-ids').value;
    const fromType = document.getElementById('convert-from-type').value;
    const toType = document.getElementById('convert-to-type').value;
    const columnIndex = parseInt(document.getElementById('convert-read-column').value);
    const writeColumn = document.getElementById('convert-write-column').value;
    
    const ids = idsText.trim() ? idsText.split('\n').map(id => id.trim()).filter(id => id) : [];
    
    clearStatus('convert-status');
    clearResults('convert-results');
    showStatus('convert-status', 'Converting IDs...', 'info');
    
    try {
        const serviceAccountData = await getServiceAccountData();
        const oauthState = getOAuthState();
        const requestData = {
            sheet_url: sheetInfo.url,
            sheet_name: sheetInfo.name,
            ids: ids.length > 0 ? ids : undefined,
            from_type: fromType,
            to_type: toType,
            column_index: columnIndex,
            write_column: writeColumn
        };
        
        if (oauthState) {
            requestData.oauth_state = oauthState;
        } else {
            Object.assign(requestData, serviceAccountData);
        }
        
        const result = await apiCall('/automation/convert-id', 'POST', requestData);
        
        showStatus('convert-status', `Conversion completed and written to column ${writeColumn}`, 'success');
        showResults('convert-results', result.results, formatConvertResults);
    } catch (error) {
        showStatus('convert-status', `Error: ${error.message}`, 'error');
    }
}

function formatConvertResults(results) {
    if (!results || results.length === 0) return '<p>No results</p>';
    
    let html = '<table><thead><tr><th>Original ID</th><th>Converted ID</th><th>Status</th></tr></thead><tbody>';
    
    results.forEach(result => {
        const statusClass = result.success ? 'success' : 'error';
        html += `
            <tr class="result-item ${statusClass}">
                <td>${result.id}</td>
                <td>${result.converted_id || '-'}</td>
                <td>${result.success ? 'Success' : result.error}</td>
            </tr>
        `;
    });
    
    html += '</tbody></table>';
    return html;
}

// Compare lists
async function compareLists() {
    // Get sheet info from global connection
    const sheetInfo = requireSheetConnection('compare-status');
    if (!sheetInfo) {
        return;
    }
    
    // Refresh sheet data before processing
    showStatus('compare-status', 'Refreshing sheet data...', 'info');
    const refreshed = await refreshSheetConnection();
    if (!refreshed) {
        showStatus('compare-status', 'Failed to refresh sheet connection', 'error');
        return;
    }
    
    const list1Text = document.getElementById('list1').value;
    const list2Text = document.getElementById('list2').value;
    const column1Index = parseInt(document.getElementById('compare-list1-column').value);
    const column2Index = parseInt(document.getElementById('compare-list2-column').value);
    const toAddColumn = document.getElementById('compare-toadd-column').value;
    const toRemoveColumn = document.getElementById('compare-toremove-column').value;
    
    const list1 = list1Text.trim() ? list1Text.split('\n').map(item => item.trim()).filter(item => item) : [];
    const list2 = list2Text.trim() ? list2Text.split('\n').map(item => item.trim()).filter(item => item) : [];
    
    clearStatus('compare-status');
    clearResults('compare-results');
    
    try {
        const serviceAccountData = await getServiceAccountData();
        const oauthState = getOAuthState();
        const requestData = {
            sheet_url: sheetInfo.url,
            sheet_name: sheetInfo.name,
            list1: list1.length > 0 ? list1 : undefined,
            list2: list2.length > 0 ? list2 : undefined,
            column1_index: column1Index,
            column2_index: column2Index,
            to_add_column: toAddColumn,
            to_remove_column: toRemoveColumn
        };
        
        if (oauthState) {
            requestData.oauth_state = oauthState;
        } else {
            Object.assign(requestData, serviceAccountData);
        }
        
        const result = await apiCall('/automation/compare-lists', 'POST', requestData);
        
        showStatus('compare-status', 
            `Found ${result.to_add_count} to add, ${result.to_remove_count} to remove. Results written to columns ${toAddColumn} and ${toRemoveColumn}.`, 
            'success'
        );
        showResults('compare-results', result, formatCompareResults);
    } catch (error) {
        showStatus('compare-status', `Error: ${error.message}`, 'error');
    }
}

function formatCompareResults(result) {
    let html = '<div style="display: grid; grid-template-columns: 1fr 1fr; gap: 20px;">';
    
    html += '<div><h3>To Add (' + result.to_add_count + ')</h3><ul>';
    if (result.to_add.length > 0) {
        result.to_add.forEach(item => {
            html += `<li>${item}</li>`;
        });
    } else {
        html += '<li>None</li>';
    }
    html += '</ul></div>';
    
    html += '<div><h3>To Remove (' + result.to_remove_count + ')</h3><ul>';
    if (result.to_remove.length > 0) {
        result.to_remove.forEach(item => {
            html += `<li>${item}</li>`;
        });
    } else {
        html += '<li>None</li>';
    }
    html += '</ul></div>';
    
    html += '</div>';
    return html;
}

// Logout
async function logout() {
    if (!confirm('Are you sure you want to logout and close the browser?')) {
        return;
    }
    
    try {
        await apiCall('/automation/logout', 'POST');
        alert('Logged out successfully');
    } catch (error) {
        alert(`Error: ${error.message}`);
    }
}

function clearResults(elementId) {
    const element = document.getElementById(elementId);
    element.innerHTML = '';
}

// Health check on load
window.addEventListener('load', async () => {
    try {
        await apiCall('/health');
        console.log('API connection successful');
    } catch (error) {
        showStatus('sheets-status', 
            'Warning: Could not connect to API. Make sure the server is running on http://localhost:5001', 
            'error'
        );
    }
});

