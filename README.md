# OIT Automation Tool

A web-based automation tool for managing Brown University MyAccount privileges and user information. This tool automates tasks that were previously performed in Google Colab.

## Features

- **Add Privileges**: Automatically add application privileges to multiple users
- **Revoke Privileges**: Revoke application privileges from multiple users
- **Employment Status**: Retrieve employment status and source information
- **ID Conversion**: Convert between different ID types (Net ID, Brown ID, Short ID)
- **List Comparison**: Compare two lists to find users to add or remove
- **Google Sheets Integration**: Connect to Google Sheets for data management

## Prerequisites

- Python 3.8 or higher
- Google Chrome browser
- Google Cloud Project with Sheets API enabled
- Service account key file or OAuth credentials for Google Sheets

## Installation

1. **Clone or download this repository**

2. **Install Python dependencies:**
   ```bash
   pip install -r requirements.txt
   ```

3. **Set up Google Sheets authentication:**

   **Option A: Service Account (Recommended)**
   - Go to [Google Cloud Console](https://console.cloud.google.com/)
   - Create a new project or select an existing one
   - Enable the Google Sheets API
   - Create a service account and download the JSON key file
   - Share your Google Sheet with the service account email

   **Option B: OAuth**
   - Follow Google's OAuth setup guide
   - Download the credentials.json file

4. **Configure environment variables:**
   ```bash
   cp env.example .env
   ```
   Edit `.env` and fill in your configuration:
   - `GOOGLE_SERVICE_ACCOUNT_FILE`: Path to your service account JSON file
   - `GOOGLE_SHEET_URL`: URL of your Google Sheet
   - `GOOGLE_SHEET_NAME`: Name of the worksheet
   - `MYACCOUNT_USERNAME`: Your Brown username
   - `MYACCOUNT_PASSWORD`: Your Brown password

## Running the Application

1. **Start the backend server:**
   ```bash
   python backend/app.py
   ```
   The server will start on `http://localhost:5001`

2. **Open the frontend:**
   - Open `frontend/index.html` in your web browser
   - Or serve it using a local web server:
     ```bash
     cd frontend
     python -m http.server 8000
     ```
     Then open `http://localhost:8000` in your browser

## Usage

1. **Connect to Google Sheets:**
   - Enter your Google Sheet URL and worksheet name
   - Click "Connect to Sheets"

2. **Login to MyAccount:**
   - Enter your Brown username and password
   - Click "Login"
   - Approve the Duo push notification on your phone

3. **Perform Operations:**
   - Use the tabs to navigate between different operations
   - Enter the required information
   - Click the appropriate button to execute

## API Endpoints

- `GET /api/health` - Health check
- `POST /api/sheets/connect` - Connect to Google Sheets
- `POST /api/automation/login` - Login to MyAccount
- `POST /api/automation/add` - Add privileges
- `POST /api/automation/revoke` - Revoke privileges
- `POST /api/automation/get-employment-status` - Get employment status
- `POST /api/automation/convert-id` - Convert IDs
- `POST /api/automation/compare-lists` - Compare lists
- `POST /api/automation/logout` - Logout and close browser

## Differences from Colab Version

1. **Authentication**: Uses standard Google OAuth/service account instead of Colab's `auth.authenticate_user()`
2. **Chrome Setup**: Uses `webdriver-manager` to automatically handle ChromeDriver installation
3. **Environment**: Runs as a standard Flask application instead of Colab notebook
4. **Frontend**: Provides a web UI instead of notebook cells
5. **Configuration**: Uses environment variables instead of hardcoded values

## Troubleshooting

### Chrome/ChromeDriver Issues
- Make sure Google Chrome is installed
- The `webdriver-manager` package will automatically download ChromeDriver
- If issues persist, manually install ChromeDriver and ensure it's in your PATH

### Google Sheets Authentication
- Ensure your service account has access to the Google Sheet
- Check that the JSON key file path is correct in `.env`
- Verify that the Google Sheets API is enabled in your Google Cloud project

### MyAccount Login Issues
- Ensure your credentials are correct
- Check that Duo push notifications are working
- The browser runs in headless mode by default; set `headless=False` in `automation_service.py` for debugging

## Security Notes

- **Never commit your `.env` file or credentials to version control**
- Store credentials securely
- Use environment variables or a secrets manager in production
- Consider using a service account with minimal required permissions

## License

This project is for internal use at Brown University.

