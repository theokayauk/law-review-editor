import os
import google.oauth2.credentials
from google_auth_oauthlib.flow import Flow
from googleapiclient.discovery import build
from flask import Flask, render_template, request, jsonify, redirect, url_for, session
from flask import send_file
import re
from flask import Flask, render_template, request, redirect, url_for, session, flash, Response
from flask import Flask
from models import db
from flask_migrate import Migrate
from flask_login import LoginManager, UserMixin
from flask_sqlalchemy import SQLAlchemy
import boto3
from datetime import datetime
from flask_login import LoginManager, login_user, logout_user, login_required, current_user
from werkzeug.security import generate_password_hash, check_password_hash


from flask import render_template, redirect, url_for, flash, request
from flask_login import login_user, logout_user, login_required, current_user
from werkzeug.security import check_password_hash

import pathlib
import io
from googleapiclient.http import MediaIoBaseDownload
import json


import logging

app = Flask(__name__)
app.config['SECRET_KEY'] = 'your-secret-key'  # Replace with a secure key
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///app.db'

logging.basicConfig(level=logging.DEBUG)
app.logger.setLevel(logging.DEBUG)

handler = logging.StreamHandler()  # StreamHandler outputs logs to console
handler.setLevel(logging.DEBUG)    # Set level to DEBUG
formatter = logging.Formatter('[%(asctime)s] %(levelname)s in %(module)s: %(message)s')
handler.setFormatter(formatter)

# Add handler to Flask app logger
app.logger.addHandler(handler)



db = SQLAlchemy(app)
migrate = Migrate(app, db)  # Initialize Flask-Migrate



login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

# Models
class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(150), nullable=False)
    role = db.Column(db.String(50), nullable=False)  # e.g., 'Executive Editor', 'Staff Editor', etc.
    email = db.Column(db.String(150), unique=True, nullable=False)
    password = db.Column(db.String(150), nullable=False)

    # Relationships
    assignments = db.relationship('Assignment', backref='user', lazy=True)

class Article(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(255), nullable=False)
    author = db.Column(db.String(255), nullable=False)
    semesters = db.Column(db.String(255), nullable=False)  # You can use a string like 'Fall 2023' or 'Spring 2024'
    google_sheet_url = db.Column(db.String(255), nullable=False)
    google_drive_url = db.Column(db.String(255), nullable=False)
    date_created = db.Column(db.DateTime, default=datetime.utcnow)

    # Relationships
    assignments = db.relationship('Assignment', backref='article', lazy=True)

class Assignment(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    article_id = db.Column(db.Integer, db.ForeignKey('article.id'), nullable=False)

class Annotation(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    pdf_id = db.Column(db.String(255), nullable=False)
    page_number = db.Column(db.Integer, nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=True)
    data = db.Column(db.Text, nullable=False)

# Configuration
PDF_FOLDER = os.path.join('static', 'pdfs')
ANNOTATION_FOLDER = 'annotations'  # Ensure this folder exists

# Ensure annotation folder exists
if not os.path.exists(ANNOTATION_FOLDER):
    os.makedirs(ANNOTATION_FOLDER)

def get_s3_folder_structure(s3_client, bucket_name):
    paginator = s3_client.get_paginator('list_objects_v2')
    operation_parameters = {'Bucket': bucket_name, 'Prefix': 'articles/', 'Delimiter': '/'}
    page_iterator = paginator.paginate(**operation_parameters)

    folder_structure = {}

    for page in page_iterator:
        for prefix in page.get('CommonPrefixes', []):
            semester_prefix = prefix.get('Prefix')  # e.g., 'articles/AU24/'
            semester = semester_prefix.split('/')[-2]

            folder_structure[semester] = {}

            # List articles under the semester
            sub_operation_parameters = {'Bucket': bucket_name, 'Prefix': semester_prefix, 'Delimiter': '/'}
            sub_page_iterator = paginator.paginate(**sub_operation_parameters)

            for sub_page in sub_page_iterator:
                for sub_prefix in sub_page.get('CommonPrefixes', []):
                    article_prefix = sub_prefix.get('Prefix')  # e.g., 'articles/AU24/Shapiro/'
                    article = article_prefix.split('/')[-2]

                    # List PDFs under the article
                    pdfs = []
                    pdf_operation_parameters = {'Bucket': bucket_name, 'Prefix': article_prefix}
                    pdf_page_iterator = paginator.paginate(**pdf_operation_parameters)

                    for pdf_page in pdf_page_iterator:
                        for content in pdf_page.get('Contents', []):
                            key = content.get('Key')
                            if key.lower().endswith('.pdf'):
                                pdf_name = key.split('/')[-1]
                                pdfs.append(pdf_name)

                    folder_structure[semester][article] = pdfs

    return folder_structure


@app.route('/create_folder', methods=['GET', 'POST'])
@login_required
def create_folder():
    if current_user.role != 'Executive Editor':
        return "Unauthorized Access", 403

    if request.method == 'POST':
        folder_type = request.form.get('folder_type')
        semester = request.form.get('semester')
        article = request.form.get('article')

        s3_client = boto3.client(
            's3',
            aws_access_key_id=os.environ.get('AWS_ACCESS_KEY_ID'),
            aws_secret_access_key=os.environ.get('AWS_SECRET_ACCESS_KEY')
        )
        bucket_name = 'my-pdf-storage-bucket-oslj'

        if folder_type == 'semester':
            prefix = f'articles/{semester}/'
        elif folder_type == 'article':
            if not semester or not article:
                flash('Semester and Article are required.')
                return redirect(url_for('create_folder'))
            prefix = f'articles/{semester}/{article}/'
        else:
            flash('Invalid folder type.')
            return redirect(url_for('create_folder'))

        # Create the folder by uploading a zero-byte object
        s3_client.put_object(Bucket=bucket_name, Key=prefix)
        flash('Folder created successfully.')
        return redirect(url_for('executive_dashboard'))

    return render_template('create_folder.html')



def get_pdfs_from_s3(article):
    s3_client = boto3.client('s3', aws_access_key_id= os.environ.get('AWS_ACCESS_KEY_ID'), aws_secret_access_key= os.environ.get('AWS_SECRET_ACCESS_KEY'))
    bucket_name = 'my-pdf-storage-bucket-oslj'
    prefix = f'articles/{article.id}'  # Assuming PDFs are stored under 'articles/{article.id}/'

    print(prefix)

    response = s3_client.list_objects_v2(Bucket=bucket_name, Prefix=prefix)
    print(response)
    pdfs = []
    for obj in response.get('Contents', []):
        key = obj['Key']
        if key.lower().endswith('.pdf'):
            pdf_name = key.split('/')[-1]
            pdfs.append({'key': key, 'name': pdf_name})
    return pdfs

@app.route('/api/get_pdfs', methods=['GET'])
def get_pdfs():
    pdfs = [f for f in os.listdir(PDF_FOLDER) if f.lower().endswith('.pdf')]
    return jsonify({'pdfs': pdfs})

from models import User

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

def credentials_to_dict(credentials):
    print("I got here")
    print("Converting credentials to dict:")  # Debug output
    print(f"Token: {credentials.token}")
    print(f"Refresh Token: {credentials.refresh_token}")
    print(f"Token URI: {credentials.token_uri}")
    print(f"Client ID: {credentials.client_id}")
    print(f"Client Secret: {credentials.client_secret}")
    return {
        'token': credentials.token,
        'refresh_token': credentials.refresh_token,
        'token_uri': credentials.token_uri,
        'client_id': credentials.client_id,
        'client_secret': credentials.client_secret,
        'scopes': credentials.scopes
    }





def extract_id_from_url(url):
    """
    Extracts the file or folder ID from a Google Drive URL.
    """

    import re

    # List of regex patterns to match different URL formats
    patterns = [
        r'/folders/([a-zA-Z0-9_-]+)',  # For folder URLs
        r'/d/([a-zA-Z0-9_-]+)',        # For file URLs
        r'\?id=([a-zA-Z0-9_-]+)',      # For URLs with '?id='
        r'id=([a-zA-Z0-9_-]+)',        # For embedded URLs or other variations
    ]

    for pattern in patterns:
        match = re.search(pattern, url)
        if match:
            return match.group(1)
    return None

def parse_footnote_sentences(doc):
    """
    Parses a Word document to extract sentences and their associated footnote numbers.

    Args:
        doc (Document): The Word document object.

    Returns:
        dict: A dictionary with base footnote numbers as keys and sub-footnotes (e.g., 3.01, 3.02) mapped to sentences.
    """
    results = {}
    superscript_pattern = re.compile(r'(\d+)')  # Matches superscript footnote numbers

    # Iterate over all paragraphs in the document
    for paragraph in doc.paragraphs:
        text = paragraph.text

        # Check for superscript footnote markers
        matches = re.finditer(superscript_pattern, text)
        for match in matches:
            footnote_number = int(match.group(1))

            # Extract the sentence containing the footnote marker
            sentence = extract_sentence_containing_marker(text, match.start())

            # Assign to base footnote number and its sub-footnotes
            sub_footnote_number = f"{footnote_number}.01"
            if footnote_number not in results:
                results[footnote_number] = {}

            results[footnote_number][sub_footnote_number] = sentence

    return results

def extract_sentence_containing_marker(text, marker_position):
    """
    Extracts the full sentence containing a specific marker position in the text.

    Args:
        text (str): The paragraph text.
        marker_position (int): The position of the marker in the text.

    Returns:
        str: The full sentence containing the marker.
    """
    sentences = re.split(r'(?<=[.!?])\s+', text)
    current_position = 0
    for sentence in sentences:
        end_position = current_position + len(sentence)
        if current_position <= marker_position < end_position:
            return sentence.strip()
        current_position = end_position + 1

    return text.strip()

def get_pdfs_in_drive(drive_service, folder_id):
    query = f"'{folder_id}' in parents and mimeType='application/pdf'"
    results = drive_service.files().list(q=query).execute()
    items = results.get('files', [])
    return items

GOOGLE_CLIENT_SECRETS_FILE = "credentials.json"
print(GOOGLE_CLIENT_SECRETS_FILE)
print("I got here")
SCOPES = [
    'https://www.googleapis.com/auth/drive.readonly',
    'https://www.googleapis.com/auth/spreadsheets'
]
os.environ['OAUTHLIB_INSECURE_TRANSPORT'] = '1'  # For development only

from flask import render_template, redirect, url_for, flash, request
from flask_login import login_user, logout_user, login_required, current_user

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        # Collect form data
        name = request.form.get('name')
        email = request.form.get('email')
        password = request.form.get('password')
        role = request.form.get('role')  # Ensure role is set appropriately

        # Check if user already exists
        user = User.query.filter_by(email=email).first()
        if user:
            return 'Email address already exists'

        # Create a new user
        new_user = User(
            name=name,
            email=email,
            password=generate_password_hash(password, method='sha256'),
            role=role
        )
        db.session.add(new_user)
        db.session.commit()

        return redirect(url_for('login'))

    return render_template('register.html')


@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email = request.form.get('email')
        password = request.form.get('password')

        user = User.query.filter_by(email=email).first()
        if not user or not check_password_hash(user.password, password):
            return 'Invalid credentials'

        login_user(user)
        return redirect(url_for('dashboard'))

    return render_template('login.html')


@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('login'))

@app.route('/add_article', methods=['GET', 'POST'])
@login_required
def add_article():
    # Check if current user is an Executive Editor
    if current_user.role != 'Executive Editor':
        return "Unauthorized Access", 403

    if request.method == 'POST':
        # Collect form data
        title = request.form.get('title')
        author = request.form.get('author')
        semesters = request.form.get('semesters')
        google_sheet_url = request.form.get('google_sheet_url')
        google_drive_url = request.form.get('google_drive_url')
        editor_ids = request.form.getlist('editors')  # List of user IDs

        # Create a new article
        new_article = Article(
            title=title,
            author=author,
            semesters=semesters,
            google_sheet_url=google_sheet_url,
            google_drive_url=google_drive_url
        )
        db.session.add(new_article)
        db.session.commit()

        # Assign editors to the article
        for editor_id in editor_ids:
            assignment = Assignment(user_id=editor_id, article_id=new_article.id)
            db.session.add(assignment)
        db.session.commit()

        return redirect(url_for('dashboard'))  # Redirect to a dashboard or relevant page

    else:
        # Get list of staff editors to assign
        staff_editors = User.query.filter_by(role='Staff Editor').all()
        return render_template('add_article.html', staff_editors=staff_editors)


@app.route('/', methods=['GET', 'POST'])

@app.route('/', methods=['GET', 'POST'])
def upload_files():
    if request.method == 'POST':
        article_name = request.form.get('article_name')
        word_file = request.files.get('word_doc')
        sheet_url = request.form.get('sheet_url')
        drive_url = request.form.get('drive_url')
        sheet_name = request.form.get('sheet_name')

        if not sheet_url or not drive_url:
            return "Error: Please provide both the Google Sheet URL and the Google Drive Folder URL."

        # Parse and store Word document sentences keyed by base footnote number
        if word_file and word_file.filename != '':
            from docx import Document
            doc = Document(word_file)
            
            # This is a placeholder parsing logic; actual footnote parsing is more complex.
            # You'll need a reliable way to map footnotes to text.
            # For demonstration, let's assume we have a function parse_footnote_sentences(doc)
            # that returns a dict like: {1: "Sentence for footnote 1", 2: "Sentence for footnote 2", ...}
            footnote_sentences = parse_footnote_sentences(doc)
            session['footnote_sentences'] = footnote_sentences
        else:
            session['footnote_sentences'] = {}

        session['article_name'] = article_name
        session['sheet_url'] = sheet_url
        session['drive_url'] = drive_url
        session['sheet_name'] = sheet_name

        return redirect(url_for('editor_interface'))

    else:
        # On GET, load the list of articles from AWS S3
        s3_client = boto3.client('s3',
                                 aws_access_key_id=os.environ.get('AWS_ACCESS_KEY_ID'),
                                 aws_secret_access_key=os.environ.get('AWS_SECRET_ACCESS_KEY'))
        bucket_name = 'my-pdf-storage-bucket-oslj'

        # Assuming your structure is articles/AU24/Shapiro, etc.
        # We'll just fetch the "semester" level for demonstration:
        response = s3_client.list_objects_v2(Bucket=bucket_name, Prefix='articles/1/', Delimiter='/')
        articles = []
        print(articles)
        for prefix in response.get('CommonPrefixes', []):
            print(prefix)
            folder_name = prefix['Prefix'].split('/')[2]
            articles.append(folder_name)

        return render_template('upload.html', articles=articles)

def parse_footnote_sentences(doc):
    # This is a pseudo-implementation. Actual logic depends on doc structure:
    # - You might find footnote references and map them to sentences in paragraphs.
    # - Suppose we return a dict {footnote_int: sentence_text}.
    results = {}
    # ... parse logic ...
    # For now, just a dummy result:
    results[1] = "This is the sentence containing footnote 1."
    results[2] = "This is the sentence containing footnote 2."
    return results
# def upload_files():
#     if request.method == 'POST':
#         # Get the uploaded Word document
#         word_file = request.files.get('word_doc')
#         # Get the inputted URLs and sheet name
#         sheet_url = request.form.get('sheet_url')
#         drive_url = request.form.get('drive_url')
#         sheet_name = request.form.get('sheet_name')  # New line

#         # Validate the inputs
#         if not sheet_url or not drive_url:
#             return "Error: Please provide both the Google Sheet URL and the Google Drive Folder URL."

#         # Save the uploaded Word document if provided
#         if word_file and word_file.filename != '':
#             word_filename = word_file.filename
#             word_path = os.path.join(app.config['UPLOAD_FOLDER'], word_filename)
#             word_file.save(word_path)
#             session['word_path'] = word_path
#         else:
#             session['word_path'] = None

#         # Store the sheet URL, drive URL, and sheet name in the session
#         session['sheet_url'] = sheet_url
#         session['drive_url'] = drive_url
#         session['sheet_name'] = sheet_name  # New line

#         return redirect(url_for('editor_interface'))
#     return render_template('upload.html')

@app.route('/set_sheet_name', methods=['POST'])
def set_sheet_name():
    sheet_name = request.form.get('sheet_name')
    session['sheet_name'] = sheet_name
    return redirect(url_for('editor_interface'))

@app.route('/select_sheet')
def select_sheet():
    if 'credentials' not in session:
        return redirect(url_for('authorize'))

    creds_dict = session['credentials']
    print(creds_dict)
    credentials = google.oauth2.credentials.Credentials(
        token=creds_dict.get('token'),
        refresh_token=creds_dict.get('refresh_token'),
        token_uri=creds_dict.get('token_uri'),
        client_id=creds_dict.get('client_id'),
        client_secret=creds_dict.get('client_secret'),
        scopes=creds_dict.get('scopes')
    )

    print(credentials)
    sheets_service = build('sheets', 'v4', credentials=credentials)

    sheet_url = session.get('sheet_url')
    sheet_id = extract_id_from_url(sheet_url)

    try:
        # Retrieve spreadsheet metadata
        spreadsheet = sheets_service.spreadsheets().get(spreadsheetId=sheet_id).execute()
        sheets = spreadsheet.get('sheets', [])
        sheet_names = [sheet['properties']['title'] for sheet in sheets]

        return render_template('select_sheet.html', sheet_names=sheet_names)
    except Exception as e:
        return f"An error occurred: {e}"

def get_footnotes(sheets_service, sheet_id, sheet_name=None):

    dot = '.'
    # Adjust the range to include columns A to L
    if sheet_name and sheet_name.strip():
        sheet_range = f"'{sheet_name}'!A:L"
    else:
        sheet_range = 'A:L'

    try:
        result = sheets_service.spreadsheets().values().get(
            spreadsheetId=sheet_id,
            range=sheet_range,
            valueRenderOption='UNFORMATTED_VALUE'
        ).execute()
        rows = result.get('values', [])

        # Skip the header row if present
        if rows and isinstance(rows[0][0], str) and rows[0][0].strip().lower() == 'fn':
            rows = rows[1:]

        footnotes = []
        for idx, row in enumerate(rows):
            # Extract footnote data
            footnote_data = {}
            footnote_data['row_number'] = idx + 2  # Google Sheets row number (accounting for header)
            if dot in str(row[0]):
                footnote_data['number'] = float(row[0]) if len(row) > 0 and row[0] else None
            else:
                try:
                    footnote_data['number'] = int(row[0]) if len(row) > 0 and row[0] else None
                except:
                    continue

            footnote_data['page'] = row[1] if len(row) > 1 else 'N/A'
            footnote_data['text'] = row[2] if len(row) > 2 else ''
            footnote_data['col_e'] = row[4] if len(row) > 4 else ''
            footnote_data['col_f'] = row[5] if len(row) > 5 else ''
            footnote_data['col_h'] = row[7] if len(row) > 7 else ''
            footnote_data['col_i'] = row[8] if len(row) > 8 else ''
            footnote_data['col_l'] = row[11] if len(row) > 11 else ''

            if footnote_data['number'] is not None:
                footnotes.append(footnote_data)
        # Sort footnotes by footnote number
        footnotes.sort(key=lambda x: x['number'])
        return footnotes
    except Exception as e:
        print(f"An error occurred while retrieving footnotes: {e}")
        return []

@app.route('/update_footnotes', methods=['POST'])
def update_footnotes():
    if 'credentials' not in session:
        return redirect(url_for('authorize'))

    creds_dict = session['credentials']
    credentials = google.oauth2.credentials.Credentials(
        token=creds_dict.get('token'),
        refresh_token=creds_dict.get('refresh_token'),
        token_uri=creds_dict.get('token_uri'),
        client_id=creds_dict.get('client_id'),
        client_secret=creds_dict.get('client_secret'),
        scopes=creds_dict.get('scopes')
    )
    sheets_service = build('sheets', 'v4', credentials=credentials)

    # Retrieve form data
    sheet_id = request.form.get('sheet_id')
    sheet_name = request.form.get('sheet_name')
    form_data = request.form.to_dict()

    # Prepare data for batch update
    data_to_update = []

    for key, value in form_data.items():
        if key.startswith('col_'):
            # Extract column and row numbers
            match = re.match(r'col_(\w)_(\d+)', key)
            if match:
                col_letter = match.group(1).upper()
                row_number = match.group(2)
                cell_address = f"{col_letter}{row_number}"

                # Add the cell update to the list
                data_to_update.append({
                    'range': f"{sheet_name}!{cell_address}",
                    'values': [[value]]
                })

    if data_to_update:
        try:
            body = {
                'valueInputOption': 'USER_ENTERED',
                'data': data_to_update
            }
            sheets_service.spreadsheets().values().batchUpdate(
                spreadsheetId=sheet_id,
                body=body
            ).execute()
            message = "Updates submitted successfully."
        except Exception as e:
            print(f"An error occurred while updating the sheet: {e}")
            message = f"An error occurred: {e}"
    else:
        message = "No updates to submit."

    # Update session credentials
    session['credentials'] = credentials_to_dict(credentials)

    return redirect(url_for('editor_interface', message=message))


@app.shell_context_processor
def make_shell_context():
    return {
        'db': db,
        'User': User,
        'Article': Article,
        'Assignment': Assignment
    }

@app.route('/editor')
def editor_interface():
    if 'credentials' not in session:
        return redirect(url_for('authorize'))

    creds_dict = session['credentials']
    credentials = google.oauth2.credentials.Credentials(
        token=creds_dict.get('token'),
        refresh_token=creds_dict.get('refresh_token'),
        token_uri=creds_dict.get('token_uri'),
        client_id=creds_dict.get('client_id'),
        client_secret=creds_dict.get('client_secret'),
        scopes=creds_dict.get('scopes')
    )

    drive_service = build('drive', 'v3', credentials=credentials)
    sheets_service = build('sheets', 'v4', credentials=credentials)

    name = session.get('name')
    role = session.get('role')
    article_id = session.get('article_id')

    if not all([name, role, article_id]):
        return redirect(url_for('landing'))

    # Convert article_id to an integer
    try:
        article_id = int(article_id)
    except ValueError:
        return "Invalid article ID.", 400

    # Retrieve the article from the database
    article = Article.query.get(article_id)
    if not article:
        return "Article not found.", 404

    # Retrieve stored session data
    word_path = session.get('word_path')
    sheet_url = session.get('sheet_url')
    drive_url = session.get('drive_url')
    sheet_name = session.get('sheet_name')

    # Extract IDs from URLs
    sheet_id = extract_id_from_url(sheet_url)
    folder_id = extract_id_from_url(drive_url)

    # Get footnotes
    footnotes = get_footnotes(sheets_service, sheet_id, sheet_name)

    # Get PDFs from Google Drive
    pdfs = get_pdfs_in_drive(drive_service, folder_id)

      # Fetch PDFs from S3 associated with the article
    pdf_files = get_pdfs_from_s3(article)

    # Sort the PDFs alphabetically by name
    pdfs_sorted = sorted(pdfs, key=lambda pdf: pdf['name'].lower())

    # Prepare the PDF files list
    pdf_files_google = [{'id': pdf['id'], 'name': pdf['name']} for pdf in pdfs_sorted]

    session['credentials'] = credentials_to_dict(credentials)

    # Retrieve message if any
    message = request.args.get('message')

    # Set a default PDF if available
    if pdf_files:
        selected_pdf = pdf_files[0]  # Select the first PDF by default
        pdf_url = url_for('serve_pdf', key=selected_pdf['key'])
        pdf_id = selected_pdf['key']
    else:
        pdf_url = None
        pdf_id = None

    return render_template(
    'editor.html',
    footnotes=footnotes,
    pdfs=pdf_files,
    sheet_id=sheet_id,
    sheet_name=sheet_name,
    message=message,
    pdf_url=pdf_url,
    pdf_id=pdf_id,
    article=article, 
    name=name, 
    role=role
    )

@app.route('/executive_dashboard')
#@login_required
def executive_dashboard():
    # Check if current user is an Executive Editor
    # if current_user.role != 'Executive Editor':
    #     return "Unauthorized Access", 403

    s3_client = boto3.client(
        's3',
        aws_access_key_id=os.environ.get('AWS_ACCESS_KEY_ID'),
        aws_secret_access_key=os.environ.get('AWS_SECRET_ACCESS_KEY')
    )
    bucket_name = 'my-pdf-storage-bucket-oslj'

    # Fetch the folder structure
    folder_structure = get_s3_folder_structure(s3_client, bucket_name)

    return render_template('executive_dashboard.html', folder_structure=folder_structure)


@app.route('/upload_from_drive', methods=['GET', 'POST'])
@login_required
def upload_from_drive():
    if current_user.role != 'Executive Editor':
        return "Unauthorized Access", 403

    if request.method == 'POST':
        semester = request.form.get('semester')
        article = request.form.get('article')
        drive_url = request.form.get('drive_url')

        if not all([semester, article, drive_url]):
            flash('All fields are required.')
            return redirect(url_for('upload_from_drive'))

        file_id = extract_id_from_url(drive_url)
        if not file_id:
            flash('Invalid Google Drive URL.')
            return redirect(url_for('upload_from_drive'))

        # Obtain Google API credentials
        if 'credentials' not in session:
            return redirect(url_for('authorize'))

        creds_dict = session['credentials']
        credentials = google.oauth2.credentials.Credentials(
            token=creds_dict.get('token'),
            refresh_token=creds_dict.get('refresh_token'),
            token_uri=creds_dict.get('token_uri'),
            client_id=creds_dict.get('client_id'),
            client_secret=creds_dict.get('client_secret'),
            scopes=creds_dict.get('scopes')
        )
        drive_service = build('drive', 'v3', credentials=credentials)

        # Download the file from Google Drive
        try:
            request_drive = drive_service.files().get_media(fileId=file_id)
            fh = io.BytesIO()
            downloader = MediaIoBaseDownload(fh, request_drive)
            done = False
            while not done:
                status, done = downloader.next_chunk()
            fh.seek(0)

            # Get file metadata
            file_metadata = drive_service.files().get(fileId=file_id, fields='name').execute()
            file_name = file_metadata.get('name', 'document.pdf')

        except Exception as e:
            flash(f"Error downloading file: {e}")
            return redirect(url_for('upload_from_drive'))

        # Upload the file to S3
        s3_client = boto3.client(
            's3',
            aws_access_key_id=os.environ.get('AWS_ACCESS_KEY_ID'),
            aws_secret_access_key=os.environ.get('AWS_SECRET_ACCESS_KEY')
        )
        bucket_name = 'my-pdf-storage-bucket-oslj'
        s3_key = f'articles/{semester}/{article}/{file_name}'

        try:
            s3_client.upload_fileobj(fh, bucket_name, s3_key)
            flash('File uploaded successfully.')
            return redirect(url_for('executive_dashboard'))
        except Exception as e:
            flash(f"Error uploading to S3: {e}")
            return redirect(url_for('upload_from_drive'))

    return render_template('upload_from_drive.html')

@app.route('/delete_folder', methods=['POST'])
@login_required
def delete_folder():
    if current_user.role != 'Executive Editor':
        return "Unauthorized Access", 403

    folder_type = request.form.get('folder_type')
    semester = request.form.get('semester')
    article = request.form.get('article')

    s3_client = boto3.client(
        's3',
        aws_access_key_id=os.environ.get('AWS_ACCESS_KEY_ID'),
        aws_secret_access_key=os.environ.get('AWS_SECRET_ACCESS_KEY')
    )
    bucket_name = 'my-pdf-storage-bucket-oslj'

    if folder_type == 'semester':
        prefix = f'articles/{semester}/'
    elif folder_type == 'article':
        prefix = f'articles/{semester}/{article}/'
    else:
        flash('Invalid folder type.')
        return redirect(url_for('executive_dashboard'))

    # List all objects under the prefix
    objects_to_delete = []
    paginator = s3_client.get_paginator('list_objects_v2')
    pages = paginator.paginate(Bucket=bucket_name, Prefix=prefix)

    for page in pages:
        for obj in page.get('Contents', []):
            objects_to_delete.append({'Key': obj['Key']})

    # Delete the objects
    if objects_to_delete:
        s3_client.delete_objects(Bucket=bucket_name, Delete={'Objects': objects_to_delete})

    flash('Folder deleted successfully.')
    return redirect(url_for('executive_dashboard'))


@app.route('/landing', methods=['GET', 'POST'])
def landing():
    if request.method == 'POST':
        name = request.form.get('name')
        role = request.form.get('role')
        article_id = request.form.get('article_id')  # Note the key 'article_id'

        print(f"Form Data - Name: {name}, Role: {role}, Article ID: {article_id}")

        # Store the user info in session
        session['name'] = name
        session['role'] = role
        session['article_id'] = article_id

        # Redirect to the editor interface
        return redirect(url_for('editor_interface'))

    else:
        articles = Article.query.all()
        return render_template('landing.html', articles=articles)

@app.route('/pdf')
def serve_pdf():
    key = request.args.get('key')
    if not key:
        return "No PDF key provided.", 400

    s3_client = boto3.client('s3',
                             aws_access_key_id=os.environ.get('AWS_ACCESS_KEY_ID'),
                             aws_secret_access_key=os.environ.get('AWS_SECRET_ACCESS_KEY'))
    bucket_name = 'my-pdf-storage-bucket-oslj'

    try:
        # Get the object metadata to retrieve the file size
        head = s3_client.head_object(Bucket=bucket_name, Key=key)
        file_size = head['ContentLength']

        # Handle range requests
        range_header = request.headers.get('Range', None)
        if not range_header:
            # Return the entire file
            pdf_object = s3_client.get_object(Bucket=bucket_name, Key=key)
            data = pdf_object['Body'].read()
            response = Response(data, mimetype='application/pdf')
            response.headers['Content-Length'] = str(file_size)
            response.headers['Accept-Ranges'] = 'bytes'
            return response
        else:
            # Parse the range header
            byte1, byte2 = 0, None
            m = re.search(r'bytes=(\d+)-(\d*)', range_header)
            if m:
                g = m.groups()
                byte1 = int(g[0])
                if g[1]:
                    byte2 = int(g[1])
            length = file_size - byte1
            if byte2 is not None:
                length = byte2 - byte1 + 1

            # Fetch the partial content
            range_header = f'bytes={byte1}-{byte2 if byte2 is not None else ""}'
            pdf_object = s3_client.get_object(Bucket=bucket_name, Key=key, Range=range_header)
            data = pdf_object['Body'].read()

            rv = Response(data,
                          206,
                          mimetype='application/pdf',
                          content_type='application/pdf',
                          direct_passthrough=True)
            rv.headers.add('Content-Range', f'bytes {byte1}-{byte1 + len(data) - 1}/{file_size}')
            rv.headers.add('Accept-Ranges', 'bytes')
            rv.headers.add('Content-Length', str(len(data)))
            return rv

    except Exception as e:
        return f"An error occurred while fetching the PDF: {e}", 500

@app.route('/authorize')
def authorize():
    session.pop('credentials', None)
    print("I got here")
    flow = Flow.from_client_secrets_file(
        GOOGLE_CLIENT_SECRETS_FILE,
        scopes=SCOPES,
        redirect_uri=url_for('oauth2callback', _external=True)
    )
    authorization_url, state = flow.authorization_url(
        access_type='offline',        # Request offline access for a refresh token
        include_granted_scopes='true',# Keep user’s previously granted scopes
        prompt='consent'             # Always prompt user to ensure refresh token is returned
    )
    session['state'] = state
    return redirect(authorization_url)


@app.route('/oauth2callback')
def oauth2callback():
    state = session['state']
    flow = Flow.from_client_secrets_file(
        GOOGLE_CLIENT_SECRETS_FILE,
        scopes=SCOPES,
        state=state,
        redirect_uri=url_for('oauth2callback', _external=True)
    )
    flow.fetch_token(authorization_response=request.url)

    credentials = flow.credentials

    # Debug logs (optional, but helps confirm refresh_token presence)
    app.logger.debug("After fetch_token:")
    app.logger.debug(f"Token: {credentials.token}")
    app.logger.debug(f"Refresh Token: {credentials.refresh_token}")
    app.logger.debug(f"Token URI: {credentials.token_uri}")
    app.logger.debug(f"Client ID: {credentials.client_id}")
    app.logger.debug(f"Client Secret: {credentials.client_secret}")

    # Convert credentials to dict and store in session
    session['credentials'] = credentials_to_dict(credentials)

    return redirect(url_for('editor_interface'))


from flask import request, jsonify
import json

@app.route('/api/save_annotation', methods=['POST'])
def save_annotation():
    data = request.get_json()
    pdf_id = data.get('pdf_id')
    page_number = data.get('pageNumber')
    annotation_data = data.copy()

    # Remove fields that are stored separately
    annotation_data.pop('pdf_id', None)
    annotation_data.pop('pageNumber', None)

    # Save the annotation to the database
    annotation = Annotation(
        pdf_id=pdf_id,
        page_number=page_number,
        user_id=current_user.id if current_user.is_authenticated else None,
        data=json.dumps(annotation_data)
    )
    db.session.add(annotation)
    db.session.commit()

    return jsonify({'status': 'success', 'annotation_id': annotation.id})

@app.route('/api/get_annotations', methods=['GET'])
def get_annotations():
    pdf_id = request.args.get('pdf_id')
    page_number = request.args.get('page', type=int)

    annotations = Annotation.query.filter_by(pdf_id=pdf_id, page_number=page_number).all()
    annotations_data = []
    for annotation in annotations:
        annotation_data = json.loads(annotation.data)
        annotation_data['id'] = annotation.id
        annotation_data['user_id'] = annotation.user_id
        annotations_data.append(annotation_data)
    return jsonify({'annotations': annotations_data})



@app.route('/api/update_annotation_comment', methods=['POST'])
def update_annotation_comment():
    data = request.get_json()
    annotation_id = data.get('id')
    comment = data.get('comment')

    annotation = Annotation.query.get(annotation_id)
    if not annotation:
        return jsonify({'status': 'error', 'message': 'Annotation not found'}), 404

    # Update the comment in the annotation data
    annotation_data = json.loads(annotation.data)
    annotation_data['comment'] = comment
    annotation.data = json.dumps(annotation_data)

    db.session.commit()

    return jsonify({'status': 'success'})




if __name__ == '__main__':
    app.run(debug=True)