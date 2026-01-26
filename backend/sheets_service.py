import gspread
from google.oauth2.service_account import Credentials
from google.oauth2.credentials import Credentials as OAuthCredentials
from google.auth.transport.requests import Request
from google_auth_oauthlib.flow import InstalledAppFlow
import os
import json
import base64

class SheetsService:
    def __init__(self, config):
        self.config = config
        self.gc = None
        # Don't authenticate on init - wait for credentials from request
    
    def authenticate(self, service_account_file=None, service_account_json=None):
        """Authenticate with Google Sheets API"""
        scope = [
            'https://spreadsheets.google.com/feeds',
            'https://www.googleapis.com/auth/drive'
        ]
        
        # Try service account from parameter
        if service_account_json:
            try:
                # If it's a base64 encoded string, decode it
                if isinstance(service_account_json, str):
                    try:
                        service_account_json = json.loads(base64.b64decode(service_account_json).decode('utf-8'))
                    except:
                        service_account_json = json.loads(service_account_json)
                creds = Credentials.from_service_account_info(
                    service_account_json,
                    scopes=scope
                )
                self.gc = gspread.authorize(creds)
                return
            except Exception as e:
                raise Exception(f"Failed to authenticate with provided service account JSON: {str(e)}")
        
        # Try service account file from parameter
        if service_account_file and os.path.exists(service_account_file):
            creds = Credentials.from_service_account_file(
                service_account_file,
                scopes=scope
            )
            self.gc = gspread.authorize(creds)
            return
        
        # Try service account from config
        if self.config.GOOGLE_SERVICE_ACCOUNT_FILE and os.path.exists(self.config.GOOGLE_SERVICE_ACCOUNT_FILE):
            creds = Credentials.from_service_account_file(
                self.config.GOOGLE_SERVICE_ACCOUNT_FILE,
                scopes=scope
            )
            self.gc = gspread.authorize(creds)
            return
        
        # Try OAuth credentials
        if self.config.GOOGLE_CREDENTIALS_FILE and os.path.exists(self.config.GOOGLE_CREDENTIALS_FILE):
            flow = InstalledAppFlow.from_client_secrets_file(
                self.config.GOOGLE_CREDENTIALS_FILE,
                scope
            )
            creds = flow.run_local_server(port=0)
            self.gc = gspread.authorize(creds)
            return
        
        raise Exception(
            "Google authentication not configured. "
            "Please provide service account file or JSON in the request, use OAuth, or set GOOGLE_SERVICE_ACCOUNT_FILE in .env"
        )
    
    def authenticate_with_oauth(self, creds_dict):
        """Authenticate using OAuth2 credentials"""
        scope = [
            'https://spreadsheets.google.com/feeds',
            'https://www.googleapis.com/auth/drive'
        ]
        
        try:
            # Reconstruct credentials from dict
            creds = OAuthCredentials(
                token=creds_dict.get('token'),
                refresh_token=creds_dict.get('refresh_token'),
                token_uri=creds_dict.get('token_uri', 'https://oauth2.googleapis.com/token'),
                client_id=creds_dict.get('client_id'),
                client_secret=creds_dict.get('client_secret'),
                scopes=creds_dict.get('scopes', scope)
            )
            
            # Refresh token if needed
            if creds.expired and creds.refresh_token:
                creds.refresh(Request())
            
            self.gc = gspread.authorize(creds)
        except Exception as e:
            raise Exception(f"Failed to authenticate with OAuth credentials: {str(e)}")
    
    def connect(self, sheet_url, sheet_name):
        """Connect to a specific worksheet"""
        if not sheet_url:
            raise Exception("Google Sheet URL is required")
        
        if not sheet_name:
            raise Exception("Worksheet name is required")
        
        if not self.gc:
            raise Exception("Not authenticated. Please authenticate first.")
        
        # Open spreadsheet by URL
        spreadsheet = self.gc.open_by_url(sheet_url)
        
        # Get worksheet
        worksheet = spreadsheet.worksheet(sheet_name)
        
        return worksheet
    
    def get_columns(self, worksheet):
        """Get all columns from worksheet"""
        data = worksheet.get_all_values()
        if not data:
            return []
        
        # Transpose to get columns
        columns = list(zip(*data))
        return columns
    
    def update_cell(self, worksheet, cell, value):
        """Update a single cell"""
        worksheet.update(cell, [[value]])
    
    def update_cells_batch(self, worksheet, updates):
        """
        Update multiple cells in a single batch request
        updates: list of dicts with 'range' and 'values' keys
        Example: [{'range': 'A1', 'values': [[value1]]}, {'range': 'B2:B5', 'values': [[v1], [v2], [v3], [v4]]}]
        """
        if not updates:
            return
        worksheet.batch_update(updates)
    
    def update_column(self, worksheet, column_letter, start_row, values):
        """Update a column with values using batch update"""
        if not values:
            return
        # Create range like "A2:A10" for batch update
        end_row = start_row + len(values) - 1
        range_name = f"{column_letter}{start_row}:{column_letter}{end_row}"
        # Format values as list of lists (each value in its own row)
        formatted_values = [[v] for v in values]
        worksheet.update(range_name, formatted_values)

