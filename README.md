
# SecureDocs - Secure Document Management System

## Overview
SecureDocs is a web-based application designed to provide a secure platform for users to upload, store, encrypt, and share sensitive documents. Built with Python using the Flask framework, it integrates advanced security features like AES encryption, two-factor authentication (2FA), and OAuth 2.0 authentication with Google, Okta, and GitHub. The application uses MariaDB to store user data, documents, and logs, ensuring accountability and data integrity.

## Features
- **User Authentication**:
  - Traditional login with email and password.
  - OAuth 2.0 login support for Google, Okta, and GitHub.
  - User registration with secure password hashing.
- **Document Management**:
  - Upload PDF documents with AES encryption.
  - View a list of uploaded documents in a user dashboard.
  - Share documents securely with other users via email.
- **Security Features**:
  - Two-factor authentication (2FA) using TOTP (via `pyotp`).
  - Event logging for actions like logins and document uploads.
  - HMAC for document integrity verification.
- **Database**:
  - Uses MariaDB to store users, documents, and logs.

## Installation

### Prerequisites
- Python 3.13
- MariaDB
- Virtual environment (e.g., `virtualenv`)
- Required Python packages (listed in `requirements.txt`)

### Setup Instructions
1. **Clone the Repository**:
   git clone https://github.com/yourusername/SecureDocs.git
   cd SecureDocs

2. **Set Up Virtual Environment**:
   python -m venv venv
   source venv/bin/activate  # On Windows: venv\Scripts\activate

3. **Install Dependencies**:
   pip install -r requirements.txt

   **The requirements.txt includes**:

   Flask  
   Flask-Login  
   Flask-WTF  
   Flask-Mail  
   Flask-Dance  
   Flask-SQLAlchemy  
   python-dotenv  
   pyotp  
   cryptography  
   itsdangerous  
   requests-oauthlib  
   pymysql  
   qrcode  
   pillow  
   requests  
   werkzeug  
   pytz

4. **Configure MariaDB**:
   Create a database and user:

   CREATE DATABASE securedocs;  
   CREATE USER 'securedocs_user'@'localhost' IDENTIFIED BY 'your_password';  
   GRANT ALL PRIVILEGES ON securedocs.* TO 'securedocs_user'@'localhost';  
   FLUSH PRIVILEGES;

5. **Set Up Environment Variables**:
   Create a .env file in the project root with:

   DATABASE_URL=mysql+pymysql://securedocs_user:your_password@localhost/securedocs  
   GOOGLE_CLIENT_ID=your_google_client_id  
   GOOGLE_CLIENT_SECRET=your_google_client_secret  
   OKTA_CLIENT_ID=your_okta_client_id  
   OKTA_CLIENT_SECRET=your_okta_client_secret  
   GITHUB_CLIENT_ID=your_github_client_id  
   GITHUB_CLIENT_SECRET=your_github_client_secret  

   **Replace placeholders with actual values from Google Cloud Console, Okta Dashboard, and GitHub Developer Settings.**

6. **Ensure Encryption Keys**:
   Ensure `fernet_key.key` and `hmac_key.key` exist for AES encryption and HMAC computation. These should already be in your project directory.

7. **Run the Application**:
   python app.py  
   Access the app at http://localhost:5000.

## Project Structure
- app.py: Main application file with routes and logic.
- models.py: Defines database models (User, Document, Log) using SQLAlchemy.
- templates/: HTML templates (login.html, register.html, dashboard.html, etc.)
- static/: CSS and JavaScript files
- uploads/: Encrypted documents
- fernet_key.key / hmac_key.key: Encryption and HMAC keys
- RSA key pairs: public_key.pem, private_key.pem, etc.
- .env: Environment variables
- requirements.txt: Python dependencies

## Usage
- Register or log in
- Authenticate via Google, Okta, or GitHub
- Set up 2FA with a QR code and TOTP
- Upload encrypted PDFs
- Share documents via email
- View audit logs

## Security Considerations
- Add `.env`, key files, and `.pem` files to `.gitignore`
- Use HTTPS in production
- Rotate credentials and passwords regularly

## Troubleshooting
- **Okta Login Issue**: Ensure user is added to Okta Assignments tab
- **Database Errors**: Check MariaDB setup and permissions
- **2FA Issues**: Ensure `pyotp` and `qrcode` are installed

## Contributing
Contributions are welcome! Please fork the repository and submit pull requests.
