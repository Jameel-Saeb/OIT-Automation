from flask import Flask, request, jsonify, session, redirect, url_for
from flask_cors import CORS
import os
import sys
import json

# Add parent directory to path for imports
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from config import Config
from backend.automation_service import AutomationService
from backend.sheets_service import SheetsService

app = Flask(__name__)
CORS(app, supports_credentials=True)  # Enable CORS for frontend with credentials
app.config['SECRET_KEY'] = Config().SECRET_KEY

config = Config()

# Store OAuth credentials in memory (in production, use Redis or database)
oauth_credentials_store = {}

# Initialize services (will be authenticated per request)
sheets_service = SheetsService(config)
automation_service = AutomationService(config, sheets_service)

def authenticate_sheets_service(data):
    """Helper function to authenticate sheets service from request data"""
    oauth_state = data.get('oauth_state')
    service_account_file = data.get('service_account_file')
    service_account_json = data.get('service_account_json')
    
    # Authenticate - OAuth first, then service account
    if oauth_state:
        if oauth_state not in oauth_credentials_store or 'credentials' not in oauth_credentials_store[oauth_state]:
            raise Exception('OAuth credentials not found. Please authorize again.')
        creds_dict = oauth_credentials_store[oauth_state]['credentials']
        sheets_service.authenticate_with_oauth(creds_dict)
    elif service_account_file or service_account_json:
        sheets_service.authenticate(service_account_file, service_account_json)
    elif not sheets_service.gc:
        try:
            sheets_service.authenticate()
        except:
            raise Exception('Google authentication required. Please use OAuth or provide service account credentials.')

@app.route('/api/health', methods=['GET'])
def health():
    """Health check endpoint"""
    return jsonify({'status': 'ok'})

@app.route('/api/oauth/config', methods=['GET'])
def get_oauth_config():
    """Get OAuth configuration for debugging"""
    return jsonify({
        'client_id': config.GOOGLE_CLIENT_ID[:30] + '...' if config.GOOGLE_CLIENT_ID else None,
        'redirect_uri': config.GOOGLE_REDIRECT_URI,
        'instructions': 'Make sure these URIs are added to Google Cloud Console',
        'required_javascript_origins': [
            'http://localhost:8000',
            'http://localhost:5001',
            'http://127.0.0.1:5500'
        ],
        'required_redirect_uris': [
            config.GOOGLE_REDIRECT_URI
        ],
        'console_url': 'https://console.cloud.google.com/apis/credentials'
    })

@app.route('/api/sheets/oauth/client-id', methods=['GET'])
def get_client_id():
    """Get Google OAuth Client ID for frontend"""
    client_id = config.GOOGLE_CLIENT_ID
    if not client_id:
        return jsonify({'client_id': None, 'error': 'GOOGLE_CLIENT_ID not configured'})
    return jsonify({'client_id': client_id})

@app.route('/api/sheets/oauth/exchange-token', methods=['POST'])
def exchange_token():
    """Exchange Google JWT credential for access token"""
    try:
        from google.auth.transport import requests
        from google.oauth2 import id_token
        import uuid
        
        data = request.json
        credential = data.get('credential')
        frontend_url = data.get('frontend_url')  # Get frontend URL from request
        
        if not credential:
            return jsonify({'success': False, 'error': 'Credential required'}), 400
        
        if not config.GOOGLE_CLIENT_ID:
            return jsonify({'success': False, 'error': 'OAuth not configured on server'}), 500
        
        # Verify the JWT token
        try:
            idinfo = id_token.verify_oauth2_token(
                credential, 
                requests.Request(), 
                config.GOOGLE_CLIENT_ID
            )
        except ValueError as e:
            return jsonify({'success': False, 'error': f'Invalid token: {str(e)}'}), 400
        
        # Get user info
        user_email = idinfo.get('email')
        
        # Now we need to get an access token for Google Sheets API
        # We'll use the authorization code flow instead
        # For now, store the credential and use it to get access token via OAuth flow
        
        # Generate a state for this session
        state = str(uuid.uuid4())
        
        # Store the credential temporarily
        oauth_credentials_store[state] = {
            'credential': credential,
            'user_email': user_email,
            'idinfo': idinfo
        }
        
        # We need to initiate OAuth flow to get access token
        # But we can use the credential to get user info and then request access
        from google_auth_oauthlib.flow import Flow
        
        print(f"=== OAuth Exchange Token ===")
        print(f"GOOGLE_CLIENT_ID: {config.GOOGLE_CLIENT_ID[:20]}..." if config.GOOGLE_CLIENT_ID else None)
        print(f"GOOGLE_REDIRECT_URI: {config.GOOGLE_REDIRECT_URI}")
        
        scopes = [
            'openid',
            'https://www.googleapis.com/auth/userinfo.email',
            'https://www.googleapis.com/auth/userinfo.profile',
            'https://www.googleapis.com/auth/spreadsheets',
            'https://www.googleapis.com/auth/drive.readonly'
        ]
        
        client_config = {
            "web": {
                "client_id": config.GOOGLE_CLIENT_ID,
                "client_secret": config.GOOGLE_CLIENT_SECRET,
                "auth_uri": "https://accounts.google.com/o/oauth2/auth",
                "token_uri": "https://oauth2.googleapis.com/token",
                "redirect_uris": [config.GOOGLE_REDIRECT_URI]
            }
        }
        
        flow = Flow.from_client_config(
            client_config,
            scopes=scopes,
            redirect_uri=config.GOOGLE_REDIRECT_URI
        )
        
        # Generate authorization URL - flow creates its own state
        authorization_url, flow_state = flow.authorization_url(
            access_type='offline',
            include_granted_scopes='true',
            prompt='consent',
            login_hint=user_email  # Pre-fill the email
        )
        
        print(f"Generated authorization URL: {authorization_url[:100]}...")
        print(f"Flow state: {flow_state}")
        
        # Get frontend URL from request body, headers, or use default
        if not frontend_url:
            frontend_url = request.headers.get('Origin') or request.headers.get('Referer', 'http://localhost:8000/index.html')
        
        # Clean up the frontend URL - remove query params and hash, but keep the path
        try:
            from urllib.parse import urlparse, urlunparse
            parsed = urlparse(frontend_url)
            # Normalize path - if it's just '/', use '/index.html'
            path = parsed.path if parsed.path and parsed.path != '/' else '/index.html'
            # Reconstruct URL without query or fragment
            frontend_url = urlunparse((
                parsed.scheme,
                parsed.netloc,
                path,
                '',  # params
                '',  # query
                ''   # fragment
            ))
        except Exception as e:
            # Fallback to default
            print(f"Error parsing frontend URL '{frontend_url}': {e}")
            frontend_url = 'http://localhost:8000/index.html'
        
        print(f"Storing frontend URL: {frontend_url}")
        
        # IMPORTANT: Store using flow_state (the state Google will send back)
        # not our custom UUID
        oauth_credentials_store[flow_state] = {
            'credential': credential,
            'user_email': user_email,
            'idinfo': idinfo,
            'flow': flow,
            'frontend_url': frontend_url
        }
        
        # Return authorization URL for frontend to open
        return jsonify({
            'success': True,
            'authorization_url': authorization_url,
            'state': flow_state,  # Use the flow's state, not a custom UUID
            'message': 'Please complete authorization'
        })
        
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500

@app.route('/api/sheets/oauth/authorize', methods=['POST'])
def oauth_authorize():
    """Start OAuth2 flow - returns authorization URL"""
    try:
        from google_auth_oauthlib.flow import Flow
        
        # Get OAuth credentials from request or config
        data = request.json or {}
        client_id = data.get('client_id') or config.GOOGLE_CLIENT_ID
        client_secret = data.get('client_secret') or config.GOOGLE_CLIENT_SECRET
        redirect_uri = data.get('redirect_uri') or config.GOOGLE_REDIRECT_URI
        
        if not client_id or not client_secret:
            return jsonify({
                'success': False,
                'error': 'OAuth credentials required. Please provide client_id and client_secret, or set GOOGLE_CLIENT_ID and GOOGLE_CLIENT_SECRET in .env'
            }), 400
        
        # OAuth scopes
        scopes = [
            'openid',
            'https://www.googleapis.com/auth/userinfo.email',
            'https://www.googleapis.com/auth/userinfo.profile',
            'https://www.googleapis.com/auth/spreadsheets',
            'https://www.googleapis.com/auth/drive.readonly'
        ]
        
        # Create OAuth flow
        client_config = {
            "web": {
                "client_id": client_id,
                "client_secret": client_secret,
                "auth_uri": "https://accounts.google.com/o/oauth2/auth",
                "token_uri": "https://oauth2.googleapis.com/token",
                "redirect_uris": [redirect_uri]
            }
        }
        
        flow = Flow.from_client_config(
            client_config,
            scopes=scopes,
            redirect_uri=redirect_uri
        )
        
        # Generate authorization URL
        authorization_url, state = flow.authorization_url(
            access_type='offline',
            include_granted_scopes='true',
            prompt='consent'
        )
        
        # Store flow in session (using state as key)
        oauth_credentials_store[state] = {
            'flow': flow,
            'client_id': client_id,
            'client_secret': client_secret,
            'redirect_uri': redirect_uri
        }
        
        return jsonify({
            'success': True,
            'authorization_url': authorization_url,
            'state': state
        })
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500

@app.route('/api/sheets/oauth/callback', methods=['GET'])
def oauth_callback():
    """Handle OAuth2 callback"""
    print(f"=== OAuth Callback Hit ===")
    print(f"Request URL: {request.url}")
    print(f"Request args: {request.args}")
    try:
        from google_auth_oauthlib.flow import Flow
        
        state = request.args.get('state')
        code = request.args.get('code')
        
        print(f"State: {state}")
        print(f"Code: {code[:20] if code else None}...")
        print(f"Available states in store: {list(oauth_credentials_store.keys())}")
        
        if not state or not code:
            return jsonify({'success': False, 'error': 'Missing state or code'}), 400
        
        if state not in oauth_credentials_store:
            return jsonify({'success': False, 'error': 'Invalid state. Please start authorization again.'}), 400
        
        stored = oauth_credentials_store[state]
        flow = stored['flow']
        
        # Exchange code for tokens
        flow.fetch_token(code=code)
        credentials = flow.credentials
        
        # Store credentials (convert to dict for JSON serialization)
        creds_dict = {
            'token': credentials.token,
            'refresh_token': credentials.refresh_token,
            'token_uri': credentials.token_uri,
            'client_id': credentials.client_id,
            'client_secret': credentials.client_secret,
            'scopes': credentials.scopes
        }
        
        # Store credentials with state
        oauth_credentials_store[state]['credentials'] = creds_dict
        
        # Get frontend URL from stored state or use default
        stored_data = oauth_credentials_store.get(state, {})
        frontend_url = stored_data.get('frontend_url', 'http://localhost:8000/index.html')
        
        print(f"=== OAuth Callback Redirect ===")
        print(f"State: {state}")
        print(f"Frontend URL to redirect to: {frontend_url}")
        print(f"Available states: {list(oauth_credentials_store.keys())}")
        if state in oauth_credentials_store:
            print(f"Stored data keys: {list(oauth_credentials_store[state].keys())}")
        
        # Return HTML page that automatically redirects back
        return f'''
        <!DOCTYPE html>
        <html>
        <head>
            <title>Authorization Successful</title>
        </head>
        <body>
            <h2>Authorization Successful!</h2>
            <p>Redirecting back to application...</p>
            <script>
                // Send message to parent window if in popup
                if (window.opener) {{
                    window.opener.postMessage({{
                        type: 'oauth_success',
                        state: '{state}'
                    }}, '*');
                    // Close popup immediately
                    window.close();
                }} else {{
                    // If not in popup, redirect back to frontend immediately
                    const redirectUrl = '{frontend_url}?oauth_success=true&state={state}';
                    console.log('Redirecting to:', redirectUrl);
                    window.location.href = redirectUrl;
                }}
            </script>
        </body>
        </html>
        '''
    except Exception as e:
        error_msg = str(e).replace("'", "&#39;").replace('"', '&quot;')  # HTML escape
        
        # Try to get frontend URL from state if available
        state = request.args.get('state')
        frontend_url = 'http://localhost:8000/index.html'  # Default for port 8000
        if state and state in oauth_credentials_store:
            frontend_url = oauth_credentials_store[state].get('frontend_url', frontend_url)
        
        return f'''
        <!DOCTYPE html>
        <html>
        <head>
            <title>Authorization Failed</title>
        </head>
        <body>
            <h2>Authorization Failed</h2>
            <p>Error: {error_msg}</p>
            <p>Redirecting back to application...</p>
            <script>
                if (window.opener) {{
                    window.opener.postMessage({{
                        type: 'oauth_error',
                        error: '{error_msg}'
                    }}, '*');
                    // Close popup immediately
                    window.close();
                }} else {{
                    // If not in popup, redirect back to frontend with error
                    window.location.href = '{frontend_url}?oauth_error=true&error=' + encodeURIComponent('{error_msg}');
                }}
            </script>
        </body>
        </html>
        ''', 400

@app.route('/api/sheets/oauth/use-credentials', methods=['POST'])
def use_oauth_credentials():
    """Use stored OAuth credentials to authenticate"""
    try:
        data = request.json
        state = data.get('state')
        
        if not state or state not in oauth_credentials_store:
            return jsonify({'success': False, 'error': 'Invalid state. Please authorize again.'}), 400
        
        stored = oauth_credentials_store[state]
        if 'credentials' not in stored:
            return jsonify({'success': False, 'error': 'Credentials not found. Please authorize again.'}), 400
        
        # Use credentials to authenticate
        creds_dict = stored['credentials']
        sheets_service.authenticate_with_oauth(creds_dict)
        
        return jsonify({'success': True, 'message': 'Authenticated successfully'})
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500

@app.route('/api/sheets/connect', methods=['POST'])
def connect_sheets():
    """Connect to Google Sheets"""
    try:
        data = request.json
        sheet_url = data.get('sheet_url')
        sheet_name = data.get('sheet_name')
        service_account_file = data.get('service_account_file')
        service_account_json = data.get('service_account_json')
        oauth_state = data.get('oauth_state')  # For OAuth flow
        
        print(f"=== Connect Sheets Request ===")
        print(f"Sheet URL: {sheet_url}")
        print(f"Sheet name: {sheet_name}")
        print(f"OAuth state: {oauth_state}")
        print(f"Available states: {list(oauth_credentials_store.keys())}")
        
        if not sheet_url:
            return jsonify({'success': False, 'error': 'Sheet URL is required'}), 400
        if not sheet_name:
            return jsonify({'success': False, 'error': 'Sheet name is required'}), 400
        
        # Authenticate if OAuth state provided
        if oauth_state:
            print(f"Using OAuth state: {oauth_state}")
            if oauth_state not in oauth_credentials_store:
                print(f"ERROR: OAuth state not found in store")
                return jsonify({'success': False, 'error': f'OAuth state not found. Available states: {list(oauth_credentials_store.keys())}'}, 400)
            if 'credentials' not in oauth_credentials_store[oauth_state]:
                print(f"ERROR: Credentials not found for state")
                return jsonify({'success': False, 'error': 'OAuth credentials not found. Please authorize again.'}), 400
            creds_dict = oauth_credentials_store[oauth_state]['credentials']
            print(f"Authenticating with OAuth credentials")
            sheets_service.authenticate_with_oauth(creds_dict)
        # Authenticate if service account provided
        elif service_account_file or service_account_json:
            print(f"Using service account")
            sheets_service.authenticate(service_account_file, service_account_json)
        elif not sheets_service.gc:
            # Try to authenticate with config
            print(f"Trying to authenticate with config")
            try:
                sheets_service.authenticate()
            except Exception as auth_error:
                print(f"ERROR: Authentication failed: {str(auth_error)}")
                return jsonify({
                    'success': False, 
                    'error': 'Google authentication required. Please use OAuth or provide service account credentials.'
                }), 400
        
        print(f"Connecting to sheet...")
        worksheet = sheets_service.connect(sheet_url, sheet_name)
        print(f"Getting columns...")
        columns = sheets_service.get_columns(worksheet)
        print(f"Success! Found {len(columns)} columns")
        
        return jsonify({
            'success': True,
            'columns_count': len(columns),
            'columns': columns
        })
    except Exception as e:
        print(f"ERROR in connect_sheets: {str(e)}")
        import traceback
        traceback.print_exc()
        return jsonify({'success': False, 'error': str(e)}), 500

@app.route('/api/automation/login', methods=['POST'])
def login():
    """Login to myaccount.brown.edu"""
    try:
        data = request.json
        username = data.get('username') or config.MYACCOUNT_USERNAME
        password = data.get('password') or config.MYACCOUNT_PASSWORD
        
        if not username or not password:
            return jsonify({'success': False, 'error': 'Username and password required'}), 400
        
        # Check if driver is alive, cleanup if not
        if automation_service.driver and not automation_service._is_driver_alive():
            print("Detected dead driver session, cleaning up...")
            automation_service._cleanup_driver()
        
        success = automation_service.login(username, password)
        
        if success:
            return jsonify({'success': True, 'message': 'Login successful. Please approve Duo push.'})
        else:
            return jsonify({'success': False, 'error': 'Login failed'}), 401
    except Exception as e:
        error_msg = str(e)
        print(f"Login error: {error_msg}")
        
        # If it's a driver connection error, cleanup and provide better error message
        if "disconnected" in error_msg.lower() or "unable to connect" in error_msg.lower():
            automation_service._cleanup_driver()
            return jsonify({
                'success': False, 
                'error': 'Browser connection lost. Please try logging in again.'
            }), 500
        
        return jsonify({'success': False, 'error': error_msg}), 500

@app.route('/api/automation/add', methods=['POST'])
def add_privileges():
    """Add privileges to users - reads from Google Sheets column E (index 4)"""
    try:
        data = request.json
        print(f"📋 Received request data: {data}")  # Debug logging
        
        sheet_url = data.get('sheet_url')
        sheet_name = data.get('sheet_name')
        app_name = data.get('app_name', 'Slate [SLATE]')
        dp_number = data.get('dp_number', '575922')
        performed_by_name = data.get('performed_by_name')
        column_index = data.get('column_index', 4)  # Column E (index 4)
        oauth_state = data.get('oauth_state')
        service_account_file = data.get('service_account_file')
        service_account_json = data.get('service_account_json')
        
        print(f"🔍 performed_by_name value: '{performed_by_name}'")  # Debug logging
        
        if not sheet_url or not sheet_name:
            return jsonify({'success': False, 'error': 'Sheet URL and sheet name are required'}), 400
        
        if not performed_by_name:
            return jsonify({'success': False, 'error': 'Performed By Name is required'}), 400
        
        # Authenticate
        try:
            authenticate_sheets_service(data)
        except Exception as e:
            return jsonify({'success': False, 'error': str(e)}), 400
        
        # Connect to sheet and get IDs from column
        worksheet = sheets_service.connect(sheet_url, sheet_name)
        columns = sheets_service.get_columns(worksheet)
        
        if column_index >= len(columns):
            return jsonify({'success': False, 'error': f'Column index {column_index} not found'}), 400
        
        # Get IDs from column (skip header row)
        ids = [id.strip() for id in columns[column_index][1:] if id.strip()]
        
        if not ids:
            return jsonify({'success': False, 'error': 'No IDs found in the specified column'}), 400
        
        results = automation_service.add_privileges(ids, app_name, dp_number, performed_by_name)
        
        return jsonify({
            'success': True,
            'results': results,
            'total': len(results),
            'successful': sum(1 for r in results if r.get('success'))
        })
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500

@app.route('/api/automation/revoke', methods=['POST'])
def revoke_privileges():
    """Revoke privileges from users - reads from Google Sheets column F (index 5)"""
    try:
        data = request.json
        sheet_url = data.get('sheet_url')
        sheet_name = data.get('sheet_name')
        app_name = data.get('app_name', 'SLATE')
        dp_number = data.get('dp_number', 'DP575922')
        column_index = data.get('column_index', 5)  # Column F (index 5)
        if not sheet_url or not sheet_name:
            return jsonify({'success': False, 'error': 'Sheet URL and sheet name are required'}), 400
        
        # Authenticate
        try:
            authenticate_sheets_service(data)
        except Exception as e:
            return jsonify({'success': False, 'error': str(e)}), 400
        
        # Connect to sheet and get IDs from column
        worksheet = sheets_service.connect(sheet_url, sheet_name)
        columns = sheets_service.get_columns(worksheet)
        
        if column_index >= len(columns):
            return jsonify({'success': False, 'error': f'Column index {column_index} not found'}), 400
        
        # Get IDs from column (skip header row)
        ids = [id.strip() for id in columns[column_index][1:] if id.strip()]
        
        if not ids:
            return jsonify({'success': False, 'error': 'No IDs found in the specified column'}), 400
        
        results = automation_service.revoke_privileges(ids, app_name, dp_number)
        
        return jsonify({
            'success': True,
            'results': results,
            'total': len(results),
            'successful': sum(1 for r in results if r.get('success'))
        })
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500

@app.route('/api/automation/get-employment-status', methods=['POST'])
def get_employment_status():
    """Get employment status and source for users - writes to Google Sheets"""
    try:
        data = request.json
        sheet_url = data.get('sheet_url')
        sheet_name = data.get('sheet_name')
        ids = data.get('ids', [])
        id_type = data.get('id_type', 'SID')  # BID, SID, or N
        column_index = data.get('column_index', 0)  # Column A (index 0) for IDs
        write_column = data.get('write_column', 'G')  # Column for employment status
        source_column = data.get('source_column', 'J')  # Column for source
        
        if not sheet_url or not sheet_name:
            return jsonify({'success': False, 'error': 'Sheet URL and sheet name are required'}), 400
        
        # Authenticate
        try:
            authenticate_sheets_service(data)
        except Exception as e:
            return jsonify({'success': False, 'error': str(e)}), 400
        
        # Connect to sheet
        worksheet = sheets_service.connect(sheet_url, sheet_name)
        
        # If IDs not provided, read from sheet
        if not ids:
            columns = sheets_service.get_columns(worksheet)
            if column_index >= len(columns):
                return jsonify({'success': False, 'error': f'Column index {column_index} not found'}), 400
            ids = [id.strip() for id in columns[column_index][1:] if id.strip()]
        
        if not ids:
            return jsonify({'success': False, 'error': 'No IDs provided or found'}), 400
        
        print(f"📊 Starting employment status check for {len(ids)} users")
        print(f"📝 Will write status to column {write_column}, source to column {source_column}")
        
        # Define callback to update sheet after each result
        def update_sheet_callback(index, result):
            """Update Google Sheets immediately after processing each user"""
            row_number = index + 2  # +2 because: +1 for 0-index, +1 for header row
            
            if result.get('success'):
                emp_status = result.get('employment_status', '')
                source = result.get('source', '')
                print(f"  ✅ [{index+1}/{len(ids)}] {result.get('id')}: Status='{emp_status}', Source='{source}'")
            else:
                emp_status = 'Not found'
                source = 'Not found'
                error = result.get('error', 'Unknown error')
                print(f"  ❌ [{index+1}/{len(ids)}] {result.get('id')}: {error}")
            
            # Update both columns for this row immediately
            try:
                status_cell = f'{write_column}{row_number}'
                source_cell = f'{source_column}{row_number}'
                
                # Update both cells
                worksheet.update(status_cell, [[emp_status]])
                worksheet.update(source_cell, [[source]])
                
                print(f"  📝 Updated sheet: {status_cell}='{emp_status}', {source_cell}='{source}'")
            except Exception as e:
                print(f"  ⚠️  Failed to update sheet for row {row_number}: {str(e)}")
        
        # Process all IDs with real-time sheet updates
        results = automation_service.get_employment_status(ids, id_type, on_result_callback=update_sheet_callback)
        
        print(f"✅ Completed employment status check for {len(ids)} users")
        
        return jsonify({
            'success': True,
            'results': results,
            'message': f'Processed {len(ids)} users with real-time sheet updates'
        })
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500

@app.route('/api/automation/convert-id', methods=['POST'])
def convert_id():
    """Convert between ID types (Net ID to SID, Brown ID to SID)"""
    try:
        data = request.json
        sheet_url = data.get('sheet_url')
        sheet_name = data.get('sheet_name')
        ids = data.get('ids', [])
        from_type = data.get('from_type', 'NETID')  # NETID, BID, or SID
        to_type = data.get('to_type', 'SID')
        column_index = data.get('column_index', 0)  # Column A (index 0) for input IDs
        write_column = data.get('write_column', 'B')  # Column for output
        
        if not sheet_url or not sheet_name:
            return jsonify({'success': False, 'error': 'Sheet URL and sheet name are required'}), 400
        
        # Authenticate
        try:
            authenticate_sheets_service(data)
        except Exception as e:
            return jsonify({'success': False, 'error': str(e)}), 400
        
        # Connect to sheet
        worksheet = sheets_service.connect(sheet_url, sheet_name)
        
        # If IDs not provided, read from sheet
        if not ids:
            columns = sheets_service.get_columns(worksheet)
            if column_index >= len(columns):
                return jsonify({'success': False, 'error': f'Column index {column_index} not found'}), 400
            ids = [id.strip() for id in columns[column_index][1:] if id.strip()]
        
        if not ids:
            return jsonify({'success': False, 'error': 'No IDs provided or found'}), 400
        
        print(f"📊 Starting ID conversion for {len(ids)} users ({from_type} → {to_type})")
        print(f"� Will write results to column {write_column}")
        
        # Define callback to update sheet after each result
        def update_sheet_callback(index, result):
            """Update Google Sheets immediately after converting each ID"""
            row_number = index + 2  # +2 because: +1 for 0-index, +1 for header row
            
            if result.get('success'):
                converted_id = result.get('converted_id', '')
                print(f"  ✅ [{index+1}/{len(ids)}] {result.get('id')} → {converted_id}")
            else:
                converted_id = 'Not found'
                error = result.get('error', 'Unknown error')
                print(f"  ❌ [{index+1}/{len(ids)}] {result.get('id')}: {error}")
            
            # Update the specified column for this row immediately
            try:
                cell = f'{write_column}{row_number}'
                worksheet.update(cell, [[converted_id]])
                print(f"  📝 Updated sheet: {cell}='{converted_id}'")
            except Exception as e:
                print(f"  ⚠️  Failed to update sheet for row {row_number}: {str(e)}")
        
        # Process all IDs with real-time sheet updates
        results = automation_service.convert_ids(ids, from_type, to_type, on_result_callback=update_sheet_callback)
        
        print(f"✅ Completed ID conversion for {len(ids)} users")
        
        return jsonify({
            'success': True,
            'results': results,
            'message': f'Converted {len(ids)} IDs with real-time sheet updates'
        })
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500

@app.route('/api/automation/compare-lists', methods=['POST'])
def compare_lists():
    """Compare two lists to find who to add and remove"""
    try:
        data = request.json
        sheet_url = data.get('sheet_url')
        sheet_name = data.get('sheet_name')
        list1 = data.get('list1', [])
        list2 = data.get('list2', [])
        column1_index = data.get('column1_index', 0)  # Column A (index 0)
        column2_index = data.get('column2_index', 1)  # Column B (index 1)
        to_add_column = data.get('to_add_column', 'E')  # Column for "To Add" results
        to_remove_column = data.get('to_remove_column', 'F')  # Column for "To Remove" results
        
        if not sheet_url or not sheet_name:
            return jsonify({'success': False, 'error': 'Sheet URL and sheet name are required'}), 400
        
        # Authenticate
        try:
            authenticate_sheets_service(data)
        except Exception as e:
            return jsonify({'success': False, 'error': str(e)}), 400
        
        # Connect to sheet
        worksheet = sheets_service.connect(sheet_url, sheet_name)
        columns = sheets_service.get_columns(worksheet)
        
        # If lists not provided, read from sheet
        if not list1 and column1_index < len(columns):
            list1 = [item.strip() for item in columns[column1_index][1:] if item.strip()]
        if not list2 and column2_index < len(columns):
            list2 = [item.strip() for item in columns[column2_index][1:] if item.strip()]
        
        # Create lowercase versions for case-insensitive comparison
        list1_lower = [item.lower() for item in list1]
        list2_lower = [item.lower() for item in list2]
        
        # Case-insensitive comparison (keep original casing in output)
        to_add = [item for item in list1 if item.lower() not in list2_lower and item != ""]
        to_remove = [item for item in list2 if item.lower() not in list1_lower and item != ""]
        
        # Write results to specified columns using batch update
        updates = []
        
        # To Add column
        updates.append({'range': f'{to_add_column}1', 'values': [['To Add']]})
        if to_add:
            add_range = f'{to_add_column}2:{to_add_column}{len(to_add) + 1}'
            add_values = [[item] for item in to_add]
            updates.append({'range': add_range, 'values': add_values})
        
        # To Remove column
        updates.append({'range': f'{to_remove_column}1', 'values': [['To Remove']]})
        if to_remove:
            remove_range = f'{to_remove_column}2:{to_remove_column}{len(to_remove) + 1}'
            remove_values = [[item] for item in to_remove]
            updates.append({'range': remove_range, 'values': remove_values})
        
        # Execute batch update
        if updates:
            sheets_service.update_cells_batch(worksheet, updates)
        
        return jsonify({
            'success': True,
            'to_add': to_add,
            'to_remove': to_remove,
            'to_add_count': len(to_add),
            'to_remove_count': len(to_remove),
            'message': f'Results written to columns {to_add_column} and {to_remove_column}'
        })
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500

@app.route('/api/automation/logout', methods=['POST'])
def logout():
    """Logout and close browser"""
    try:
        automation_service.logout()
        return jsonify({'success': True, 'message': 'Logged out successfully'})
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500

if __name__ == '__main__':
    app.run(debug=config.FLASK_DEBUG, port=config.PORT, host='0.0.0.0')



###Older

from flask import Flask, request, jsonify, session, redirect, url_for
from flask_cors import CORS
import os
import sys
import json

# Add parent directory to path for imports
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from config import Config
from backend.automation_service import AutomationService
from backend.sheets_service import SheetsService

app = Flask(__name__)
CORS(app, supports_credentials=True)  # Enable CORS for frontend with credentials
app.config['SECRET_KEY'] = Config().SECRET_KEY

config = Config()

# Store OAuth credentials in memory (in production, use Redis or database)
oauth_credentials_store = {}

# Initialize services (will be authenticated per request)
sheets_service = SheetsService(config)
automation_service = AutomationService(config, sheets_service)

def authenticate_sheets_service(data):
    """Helper function to authenticate sheets service from request data"""
    oauth_state = data.get('oauth_state')
    service_account_file = data.get('service_account_file')
    service_account_json = data.get('service_account_json')
    
    # Authenticate - OAuth first, then service account
    if oauth_state:
        if oauth_state not in oauth_credentials_store or 'credentials' not in oauth_credentials_store[oauth_state]:
            raise Exception('OAuth credentials not found. Please authorize again.')
        creds_dict = oauth_credentials_store[oauth_state]['credentials']
        sheets_service.authenticate_with_oauth(creds_dict)
    elif service_account_file or service_account_json:
        sheets_service.authenticate(service_account_file, service_account_json)
    elif not sheets_service.gc:
        try:
            sheets_service.authenticate()
        except:
            raise Exception('Google authentication required. Please use OAuth or provide service account credentials.')

@app.route('/api/health', methods=['GET'])
def health():
    """Health check endpoint"""
    return jsonify({'status': 'ok'})

@app.route('/api/sheets/oauth/client-id', methods=['GET'])
def get_client_id():
    """Get Google OAuth Client ID for frontend"""
    client_id = config.GOOGLE_CLIENT_ID
    if not client_id:
        return jsonify({'client_id': None, 'error': 'GOOGLE_CLIENT_ID not configured'})
    return jsonify({'client_id': client_id})

@app.route('/api/sheets/oauth/exchange-token', methods=['POST'])
def exchange_token():
    """Exchange Google JWT credential for access token"""
    try:
        from google.auth.transport import requests
        from google.oauth2 import id_token
        import uuid
        
        data = request.json
        credential = data.get('credential')
        
        if not credential:
            return jsonify({'success': False, 'error': 'Credential required'}), 400
        
        if not config.GOOGLE_CLIENT_ID:
            return jsonify({'success': False, 'error': 'OAuth not configured on server'}), 500
        
        # Verify the JWT token
        try:
            idinfo = id_token.verify_oauth2_token(
                credential, 
                requests.Request(), 
                config.GOOGLE_CLIENT_ID
            )
        except ValueError as e:
            return jsonify({'success': False, 'error': f'Invalid token: {str(e)}'}), 400
        
        # Get user info
        user_email = idinfo.get('email')
        
        # Now we need to get an access token for Google Sheets API
        # We'll use the authorization code flow instead
        # For now, store the credential and use it to get access token via OAuth flow
        
        # Generate a state for this session
        state = str(uuid.uuid4())
        
        # Store the credential temporarily
        oauth_credentials_store[state] = {
            'credential': credential,
            'user_email': user_email,
            'idinfo': idinfo
        }
        
        # We need to initiate OAuth flow to get access token
        # But we can use the credential to get user info and then request access
        from google_auth_oauthlib.flow import Flow
        
        print(f"=== OAuth Exchange Token ===")
        print(f"GOOGLE_CLIENT_ID: {config.GOOGLE_CLIENT_ID[:20]}..." if config.GOOGLE_CLIENT_ID else None)
        print(f"GOOGLE_REDIRECT_URI: {config.GOOGLE_REDIRECT_URI}")
        
        scopes = [
            'openid',
            'https://www.googleapis.com/auth/userinfo.email',
            'https://www.googleapis.com/auth/userinfo.profile',
            'https://www.googleapis.com/auth/spreadsheets',
            'https://www.googleapis.com/auth/drive.readonly'
        ]
        
        client_config = {
            "web": {
                "client_id": config.GOOGLE_CLIENT_ID,
                "client_secret": config.GOOGLE_CLIENT_SECRET,
                "auth_uri": "https://accounts.google.com/o/oauth2/auth",
                "token_uri": "https://oauth2.googleapis.com/token",
                "redirect_uris": [config.GOOGLE_REDIRECT_URI]
            }
        }
        
        flow = Flow.from_client_config(
            client_config,
            scopes=scopes,
            redirect_uri=config.GOOGLE_REDIRECT_URI
        )
        
        # Generate authorization URL - flow creates its own state
        authorization_url, flow_state = flow.authorization_url(
            access_type='offline',
            include_granted_scopes='true',
            prompt='consent',
            login_hint=user_email  # Pre-fill the email
        )
        
        print(f"Generated authorization URL: {authorization_url[:100]}...")
        print(f"Flow state: {flow_state}")
        
        # IMPORTANT: Store using flow_state (the state Google will send back)
        # not our custom UUID
        oauth_credentials_store[flow_state] = {
            'credential': credential,
            'user_email': user_email,
            'idinfo': idinfo,
            'flow': flow
        }
        
        # Return authorization URL for frontend to open
        return jsonify({
            'success': True,
            'authorization_url': authorization_url,
            'state': flow_state,  # Use the flow's state, not a custom UUID
            'message': 'Please complete authorization'
        })
        
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500

@app.route('/api/sheets/oauth/authorize', methods=['POST'])
def oauth_authorize():
    """Start OAuth2 flow - returns authorization URL"""
    try:
        from google_auth_oauthlib.flow import Flow
        
        # Get OAuth credentials from request or config
        data = request.json or {}
        client_id = data.get('client_id') or config.GOOGLE_CLIENT_ID
        client_secret = data.get('client_secret') or config.GOOGLE_CLIENT_SECRET
        redirect_uri = data.get('redirect_uri') or config.GOOGLE_REDIRECT_URI
        
        if not client_id or not client_secret:
            return jsonify({
                'success': False,
                'error': 'OAuth credentials required. Please provide client_id and client_secret, or set GOOGLE_CLIENT_ID and GOOGLE_CLIENT_SECRET in .env'
            }), 400
        
        # OAuth scopes
        scopes = [
            'openid',
            'https://www.googleapis.com/auth/userinfo.email',
            'https://www.googleapis.com/auth/userinfo.profile',
            'https://www.googleapis.com/auth/spreadsheets',
            'https://www.googleapis.com/auth/drive.readonly'
        ]
        
        # Create OAuth flow
        client_config = {
            "web": {
                "client_id": client_id,
                "client_secret": client_secret,
                "auth_uri": "https://accounts.google.com/o/oauth2/auth",
                "token_uri": "https://oauth2.googleapis.com/token",
                "redirect_uris": [redirect_uri]
            }
        }
        
        flow = Flow.from_client_config(
            client_config,
            scopes=scopes,
            redirect_uri=redirect_uri
        )
        
        # Generate authorization URL
        authorization_url, state = flow.authorization_url(
            access_type='offline',
            include_granted_scopes='true',
            prompt='consent'
        )
        
        # Store flow in session (using state as key)
        oauth_credentials_store[state] = {
            'flow': flow,
            'client_id': client_id,
            'client_secret': client_secret,
            'redirect_uri': redirect_uri
        }
        
        return jsonify({
            'success': True,
            'authorization_url': authorization_url,
            'state': state
        })
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500

@app.route('/api/sheets/oauth/callback', methods=['GET'])
def oauth_callback():
    """Handle OAuth2 callback"""
    print(f"=== OAuth Callback Hit ===")
    print(f"Request URL: {request.url}")
    print(f"Request args: {request.args}")
    try:
        from google_auth_oauthlib.flow import Flow
        
        state = request.args.get('state')
        code = request.args.get('code')
        
        print(f"State: {state}")
        print(f"Code: {code[:20] if code else None}...")
        print(f"Available states in store: {list(oauth_credentials_store.keys())}")
        
        if not state or not code:
            return jsonify({'success': False, 'error': 'Missing state or code'}), 400
        
        if state not in oauth_credentials_store:
            return jsonify({'success': False, 'error': 'Invalid state. Please start authorization again.'}), 400
        
        stored = oauth_credentials_store[state]
        flow = stored['flow']
        
        # Exchange code for tokens
        flow.fetch_token(code=code)
        credentials = flow.credentials
        
        # Store credentials (convert to dict for JSON serialization)
        creds_dict = {
            'token': credentials.token,
            'refresh_token': credentials.refresh_token,
            'token_uri': credentials.token_uri,
            'client_id': credentials.client_id,
            'client_secret': credentials.client_secret,
            'scopes': credentials.scopes
        }
        
        # Store credentials with state
        oauth_credentials_store[state]['credentials'] = creds_dict
        
        # Return HTML page that redirects back to frontend
        # Frontend should be served separately (e.g., http://localhost:8000 or file://...)
        frontend_url = 'http://localhost:8000'  # Adjust if your frontend is on a different port
        return f'''
        <!DOCTYPE html>
        <html>
        <head>
            <title>Authorization Successful</title>
            <script>
                // Redirect back to frontend with state parameter
                window.location.href = '{frontend_url}/?oauth_success=true&state={state}';
            </script>
        </head>
        <body>
            <h2>Authorization Successful!</h2>
            <p>Redirecting back to application...</p>
        </body>
        </html>
        '''
    except Exception as e:
        error_msg = str(e).replace("'", "&#39;")  # HTML escape single quotes
        frontend_url = 'http://localhost:8000'  # Adjust if your frontend is on a different port
        return f'''
        <!DOCTYPE html>
        <html>
        <head>
            <title>Authorization Failed</title>
            <script>
                // Redirect back to frontend with error
                window.location.href = '{frontend_url}/?oauth_error=true&error={error_msg}';
            </script>
        </head>
        <body>
            <h2>Authorization Failed</h2>
            <p>Error: {str(e)}</p>
            <p>Redirecting back to application...</p>
        </body>
        </html>
        ''', 400

@app.route('/api/sheets/oauth/use-credentials', methods=['POST'])
def use_oauth_credentials():
    """Use stored OAuth credentials to authenticate"""
    try:
        data = request.json
        state = data.get('state')
        
        if not state or state not in oauth_credentials_store:
            return jsonify({'success': False, 'error': 'Invalid state. Please authorize again.'}), 400
        
        stored = oauth_credentials_store[state]
        if 'credentials' not in stored:
            return jsonify({'success': False, 'error': 'Credentials not found. Please authorize again.'}), 400
        
        # Use credentials to authenticate
        creds_dict = stored['credentials']
        sheets_service.authenticate_with_oauth(creds_dict)
        
        return jsonify({'success': True, 'message': 'Authenticated successfully'})
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500

@app.route('/api/sheets/connect', methods=['POST'])
def connect_sheets():
    """Connect to Google Sheets"""
    try:
        data = request.json
        sheet_url = data.get('sheet_url')
        sheet_name = data.get('sheet_name')
        service_account_file = data.get('service_account_file')
        service_account_json = data.get('service_account_json')
        oauth_state = data.get('oauth_state')  # For OAuth flow
        
        print(f"=== Connect Sheets Request ===")
        print(f"Sheet URL: {sheet_url}")
        print(f"Sheet name: {sheet_name}")
        print(f"OAuth state: {oauth_state}")
        print(f"Available states: {list(oauth_credentials_store.keys())}")
        
        if not sheet_url:
            return jsonify({'success': False, 'error': 'Sheet URL is required'}), 400
        if not sheet_name:
            return jsonify({'success': False, 'error': 'Sheet name is required'}), 400
        
        # Authenticate if OAuth state provided
        if oauth_state:
            print(f"Using OAuth state: {oauth_state}")
            if oauth_state not in oauth_credentials_store:
                print(f"ERROR: OAuth state not found in store")
                return jsonify({'success': False, 'error': f'OAuth state not found. Available states: {list(oauth_credentials_store.keys())}'}, 400)
            if 'credentials' not in oauth_credentials_store[oauth_state]:
                print(f"ERROR: Credentials not found for state")
                return jsonify({'success': False, 'error': 'OAuth credentials not found. Please authorize again.'}), 400
            creds_dict = oauth_credentials_store[oauth_state]['credentials']
            print(f"Authenticating with OAuth credentials")
            sheets_service.authenticate_with_oauth(creds_dict)
        # Authenticate if service account provided
        elif service_account_file or service_account_json:
            print(f"Using service account")
            sheets_service.authenticate(service_account_file, service_account_json)
        elif not sheets_service.gc:
            # Try to authenticate with config
            print(f"Trying to authenticate with config")
            try:
                sheets_service.authenticate()
            except Exception as auth_error:
                print(f"ERROR: Authentication failed: {str(auth_error)}")
                return jsonify({
                    'success': False, 
                    'error': 'Google authentication required. Please use OAuth or provide service account credentials.'
                }), 400
        
        print(f"Connecting to sheet...")
        worksheet = sheets_service.connect(sheet_url, sheet_name)
        print(f"Getting columns...")
        columns = sheets_service.get_columns(worksheet)
        print(f"Success! Found {len(columns)} columns")
        
        return jsonify({
            'success': True,
            'columns_count': len(columns),
            'columns': columns
        })
    except Exception as e:
        print(f"ERROR in connect_sheets: {str(e)}")
        import traceback
        traceback.print_exc()
        return jsonify({'success': False, 'error': str(e)}), 500

@app.route('/api/automation/login', methods=['POST'])
def login():
    """Login to myaccount.brown.edu"""
    try:
        data = request.json
        username = data.get('username') or config.MYACCOUNT_USERNAME
        password = data.get('password') or config.MYACCOUNT_PASSWORD
        
        if not username or not password:
            return jsonify({'success': False, 'error': 'Username and password required'}), 400
        
        success = automation_service.login(username, password)
        
        if success:
            return jsonify({'success': True, 'message': 'Login successful. Please approve Duo push.'})
        else:
            return jsonify({'success': False, 'error': 'Login failed'}), 401
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500

@app.route('/api/automation/add', methods=['POST'])
def add_privileges():
    """Add privileges to users - reads from Google Sheets column E (index 4)"""
    try:
        data = request.json
        sheet_url = data.get('sheet_url')
        sheet_name = data.get('sheet_name')
        app_name = data.get('app_name', 'Slate [SLATE]')
        dp_number = data.get('dp_number', '575922')
        column_index = data.get('column_index', 4)  # Column E (index 4)
        oauth_state = data.get('oauth_state')
        service_account_file = data.get('service_account_file')
        service_account_json = data.get('service_account_json')
        
        if not sheet_url or not sheet_name:
            return jsonify({'success': False, 'error': 'Sheet URL and sheet name are required'}), 400
        
        # Authenticate
        try:
            authenticate_sheets_service(data)
        except Exception as e:
            return jsonify({'success': False, 'error': str(e)}), 400
        
        # Connect to sheet and get IDs from column
        worksheet = sheets_service.connect(sheet_url, sheet_name)
        columns = sheets_service.get_columns(worksheet)
        
        if column_index >= len(columns):
            return jsonify({'success': False, 'error': f'Column index {column_index} not found'}), 400
        
        # Get IDs from column (skip header row)
        ids = [id.strip() for id in columns[column_index][1:] if id.strip()]
        
        if not ids:
            return jsonify({'success': False, 'error': 'No IDs found in the specified column'}), 400
        
        results = automation_service.add_privileges(ids, app_name, dp_number)
        
        return jsonify({
            'success': True,
            'results': results,
            'total': len(results),
            'successful': sum(1 for r in results if r.get('success'))
        })
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500

@app.route('/api/automation/revoke', methods=['POST'])
def revoke_privileges():
    """Revoke privileges from users - reads from Google Sheets column F (index 5)"""
    try:
        data = request.json
        sheet_url = data.get('sheet_url')
        sheet_name = data.get('sheet_name')
        app_name = data.get('app_name', 'SLATE')
        dp_number = data.get('dp_number', 'DP575922')
        column_index = data.get('column_index', 5)  # Column F (index 5)
        if not sheet_url or not sheet_name:
            return jsonify({'success': False, 'error': 'Sheet URL and sheet name are required'}), 400
        
        # Authenticate
        try:
            authenticate_sheets_service(data)
        except Exception as e:
            return jsonify({'success': False, 'error': str(e)}), 400
        
        # Connect to sheet and get IDs from column
        worksheet = sheets_service.connect(sheet_url, sheet_name)
        columns = sheets_service.get_columns(worksheet)
        
        if column_index >= len(columns):
            return jsonify({'success': False, 'error': f'Column index {column_index} not found'}), 400
        
        # Get IDs from column (skip header row)
        ids = [id.strip() for id in columns[column_index][1:] if id.strip()]
        
        if not ids:
            return jsonify({'success': False, 'error': 'No IDs found in the specified column'}), 400
        
        results = automation_service.revoke_privileges(ids, app_name, dp_number)
        
        return jsonify({
            'success': True,
            'results': results,
            'total': len(results),
            'successful': sum(1 for r in results if r.get('success'))
        })
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500

@app.route('/api/automation/get-employment-status', methods=['POST'])
def get_employment_status():
    """Get employment status and source for users - writes to Google Sheets columns G and J"""
    try:
        data = request.json
        sheet_url = data.get('sheet_url')
        sheet_name = data.get('sheet_name')
        ids = data.get('ids', [])
        id_type = data.get('id_type', 'SID')  # BID, SID, or N
        column_index = data.get('column_index', 0)  # Column A (index 0) for IDs
        if not sheet_url or not sheet_name:
            return jsonify({'success': False, 'error': 'Sheet URL and sheet name are required'}), 400
        
        # Authenticate
        try:
            authenticate_sheets_service(data)
        except Exception as e:
            return jsonify({'success': False, 'error': str(e)}), 400
        
        # Connect to sheet
        worksheet = sheets_service.connect(sheet_url, sheet_name)
        
        # If IDs not provided, read from sheet
        if not ids:
            columns = sheets_service.get_columns(worksheet)
            if column_index >= len(columns):
                return jsonify({'success': False, 'error': f'Column index {column_index} not found'}), 400
            ids = [id.strip() for id in columns[column_index][1:] if id.strip()]
        
        if not ids:
            return jsonify({'success': False, 'error': 'No IDs provided or found'}), 400
        
        results = automation_service.get_employment_status(ids, id_type)
        
        # Write results to sheet (columns G and J) using batch update
        updates = []
        g_values = []
        j_values = []
        
        for result in results:
            if result.get('success'):
                g_values.append([result.get('employment_status', '')])
                j_values.append([result.get('source', '')])
            else:
                g_values.append(['Not found'])
                j_values.append(['Not found'])
        
        # Add batch updates
        if g_values:
            g_range = f'G2:G{len(g_values) + 1}'
            updates.append({'range': g_range, 'values': g_values})
        if j_values:
            j_range = f'J2:J{len(j_values) + 1}'
            updates.append({'range': j_range, 'values': j_values})
        
        # Execute batch update
        if updates:
            sheets_service.update_cells_batch(worksheet, updates)
        
        return jsonify({
            'success': True,
            'results': results,
            'message': 'Results written to columns G and J'
        })
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500

@app.route('/api/automation/convert-id', methods=['POST'])
def convert_id():
    """Convert between ID types (Net ID to SID, Brown ID to SID) - writes to column B"""
    try:
        data = request.json
        sheet_url = data.get('sheet_url')
        sheet_name = data.get('sheet_name')
        ids = data.get('ids', [])
        from_type = data.get('from_type', 'NETID')  # NETID, BID, or SID
        to_type = data.get('to_type', 'SID')
        column_index = data.get('column_index', 0)  # Column A (index 0) for input IDs
        if not sheet_url or not sheet_name:
            return jsonify({'success': False, 'error': 'Sheet URL and sheet name are required'}), 400
        
        # Authenticate
        try:
            authenticate_sheets_service(data)
        except Exception as e:
            return jsonify({'success': False, 'error': str(e)}), 400
        
        # Connect to sheet
        worksheet = sheets_service.connect(sheet_url, sheet_name)
        
        # If IDs not provided, read from sheet
        if not ids:
            columns = sheets_service.get_columns(worksheet)
            if column_index >= len(columns):
                return jsonify({'success': False, 'error': f'Column index {column_index} not found'}), 400
            ids = [id.strip() for id in columns[column_index][1:] if id.strip()]
        
        if not ids:
            return jsonify({'success': False, 'error': 'No IDs provided or found'}), 400
        
        results = automation_service.convert_ids(ids, from_type, to_type)
        
        # Write results to column B using batch update
        b_values = []
        for result in results:
            if result.get('success'):
                b_values.append([result.get('converted_id', '')])
            else:
                b_values.append(['Not found'])
        
        # Execute batch update
        if b_values:
            b_range = f'B2:B{len(b_values) + 1}'
            sheets_service.update_cells_batch(worksheet, [{'range': b_range, 'values': b_values}])
        
        return jsonify({
            'success': True,
            'results': results,
            'message': 'Results written to column B'
        })
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500

@app.route('/api/automation/compare-lists', methods=['POST'])
def compare_lists():
    """Compare two lists to find who to add and remove - writes to columns E and F"""
    try:
        data = request.json
        sheet_url = data.get('sheet_url')
        sheet_name = data.get('sheet_name')
        list1 = data.get('list1', [])
        list2 = data.get('list2', [])
        column1_index = data.get('column1_index', 0)  # Column A (index 0)
        column2_index = data.get('column2_index', 1)  # Column B (index 1)
        if not sheet_url or not sheet_name:
            return jsonify({'success': False, 'error': 'Sheet URL and sheet name are required'}), 400
        
        # Authenticate
        try:
            authenticate_sheets_service(data)
        except Exception as e:
            return jsonify({'success': False, 'error': str(e)}), 400
        
        # Connect to sheet
        worksheet = sheets_service.connect(sheet_url, sheet_name)
        columns = sheets_service.get_columns(worksheet)
        
        # If lists not provided, read from sheet
        if not list1 and column1_index < len(columns):
            list1 = [item.strip() for item in columns[column1_index][1:] if item.strip()]
        if not list2 and column2_index < len(columns):
            list2 = [item.strip() for item in columns[column2_index][1:] if item.strip()]
        
        to_add = [item for item in list1 if item not in list2 and item != ""]
        to_remove = [item for item in list2 if item not in list1 and item != ""]
        
        # Write results to columns E and F using batch update
        updates = []
        
        # Column E: To Add
        updates.append({'range': 'E1', 'values': [['To Add']]})
        if to_add:
            e_range = f'E2:E{len(to_add) + 1}'
            e_values = [[item] for item in to_add]
            updates.append({'range': e_range, 'values': e_values})
        
        # Column F: To Remove
        updates.append({'range': 'F1', 'values': [['To remove']]})
        if to_remove:
            f_range = f'F2:F{len(to_remove) + 1}'
            f_values = [[item] for item in to_remove]
            updates.append({'range': f_range, 'values': f_values})
        
        # Execute batch update
        if updates:
            sheets_service.update_cells_batch(worksheet, updates)
        
        return jsonify({
            'success': True,
            'to_add': to_add,
            'to_remove': to_remove,
            'to_add_count': len(to_add),
            'to_remove_count': len(to_remove),
            'message': 'Results written to columns E and F'
        })
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500

@app.route('/api/automation/logout', methods=['POST'])
def logout():
    """Logout and close browser"""
    try:
        automation_service.logout()
        return jsonify({'success': True, 'message': 'Logged out successfully'})
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500

if __name__ == '__main__':
    app.run(debug=config.FLASK_DEBUG, port=config.PORT, host='0.0.0.0')
