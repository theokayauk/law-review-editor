import os
import io
import re
import json
import logging
import pathlib
import sys

from datetime import datetime

# ------------- Flask Imports -------------
from flask import Flask, render_template, request, redirect, url_for, session, jsonify, Response, flash
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_required, current_user, login_user, logout_user
from werkzeug.security import generate_password_hash, check_password_hash

# ------------- Google + OAuth Imports -------------
import google.oauth2.credentials
from google_auth_oauthlib.flow import Flow
from googleapiclient.discovery import build
from googleapiclient.http import MediaIoBaseDownload

# ------------- Docx + PDF + AWS Imports -------------
import boto3
from docx import Document

# ------------- OpenAI Imports -------------
import openai
from openai import OpenAI, OpenAIError, RateLimitError

# Set your OpenAI API key (pull from env var or set directly)
openai.api_key = os.environ.get("OPENAI_API_KEY", "")

# ------------- Flask Setup -------------
app = Flask(__name__)
app.config['SECRET_KEY'] = 'your-secret-key'  # Replace with a secure key

app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///app.db'
db = SQLAlchemy(app)

logging.basicConfig(level=logging.DEBUG)
app.logger.setLevel(logging.DEBUG)
handler = logging.StreamHandler()
handler.setLevel(logging.DEBUG)
formatter = logging.Formatter('[%(asctime)s] %(levelname)s in %(module)s: %(message)s')
handler.setFormatter(formatter)
app.logger.addHandler(handler)

# ------------- Minimal Models -------------
class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(255), nullable=False)
    password = db.Column(db.String(255), nullable=False)

class Annotation(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    pdf_id = db.Column(db.String(255), nullable=False)
    page_number = db.Column(db.Integer, nullable=False)
    user_id = db.Column(db.Integer, nullable=True)
    data = db.Column(db.Text, nullable=False)

# ------------- Login Manager -------------
login_manager = LoginManager()
login_manager.init_app(app)

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

# ------------- Google Config -------------
GOOGLE_CLIENT_SECRETS_FILE = "credentials.json"
SCOPES = [
    'https://www.googleapis.com/auth/drive.readonly',
    'https://www.googleapis.com/auth/spreadsheets'
]
os.environ['OAUTHLIB_INSECURE_TRANSPORT'] = '1'  # For development only

# ------------- Utility Functions -------------

def credentials_to_dict(credentials):
    return {
        'token': credentials.token,
        'refresh_token': credentials.refresh_token,
        'token_uri': credentials.token_uri,
        'client_id': credentials.client_id,
        'client_secret': credentials.client_secret,
        'scopes': credentials.scopes
    }

def extract_id_from_url(url):
    patterns = [
        r'/folders/([a-zA-Z0-9_-]+)',
        r'/d/([a-zA-Z0-9_-]+)',
        r'\?id=([a-zA-Z0-9_-]+)',
        r'id=([a-zA-Z0-9_-]+)',
    ]
    for pattern in patterns:
        match = re.search(pattern, url)
        if match:
            return match.group(1)
    return None

def parse_footnote_sentences(doc):
    """
    **VERY** simplified function. Real usage might require advanced logic.
    Returns dict {footnote_number: "Sentence containing footnote n"}
    """
    # Dummy version:
    results = {}
    results[1] = "Powell, supra note 6, something about the Powell source."
    results[2] = "Smith, supra note 2, referencing the Smith article."
    return results

def get_footnotes(sheets_service, spreadsheet_id, sheet_name):
    """
    Reads the footnotes from the Google Sheet tab (A:L).
    Returns list of dicts with footnote details.
    """
    try:
        range_str = f"'{sheet_name}'!A:L"
        result = sheets_service.spreadsheets().values().get(
            spreadsheetId=spreadsheet_id,
            range=range_str,
            valueRenderOption='UNFORMATTED_VALUE'
        ).execute()
        rows = result.get('values', [])
        if rows and isinstance(rows[0][0], str) and rows[0][0].strip().lower() == 'fn':
            rows = rows[1:]

        dot = '.'
        footnotes = []
        for idx, row in enumerate(rows):
            footnote = {}
            footnote['row_number'] = idx + 2
            if len(row) > 0:
                if dot in str(row[0]):
                    try:
                        footnote['number'] = float(row[0])
                    except:
                        continue
                else:
                    try:
                        footnote['number'] = int(row[0])
                    except:
                        continue
            else:
                continue

            footnote['page'] = row[1] if len(row) > 1 else 'N/A'
            footnote['text'] = row[2] if len(row) > 2 else ''
            footnote['col_e'] = row[4] if len(row) > 4 else ''
            footnote['col_f'] = row[5] if len(row) > 5 else ''
            footnote['col_h'] = row[7] if len(row) > 7 else ''
            footnote['col_i'] = row[8] if len(row) > 8 else ''
            footnote['col_l'] = row[11] if len(row) > 11 else ''

            footnotes.append(footnote)

        footnotes.sort(key=lambda x: x['number'])
        return footnotes

    except Exception as e:
        print(f"Error reading footnotes from sheet: {e}")
        return []

def get_pdfs_in_drive(drive_service, folder_id):
    """
    Return a list of PDFs in the specified Google Drive folder.
    Each item: {id, name, webViewLink, ...}
    """
    q = f"'{folder_id}' in parents and mimeType='application/pdf'"
    results = drive_service.files().list(q=q, fields="files(id, name, webViewLink)").execute()
    return results.get('files', [])

def match_pdf_via_openai(footnote_text, pdf_titles):
    """
    Calls OpenAI to figure out which pdf title best matches the footnote_text.
    Returns a string: the best matching title or "No match" if uncertain.
    """
    if not pdf_titles:
        return "No match"

    user_prompt = (
        "You are a helpful assistant. We have a footnote:\n\n"
        f"{footnote_text}\n\n"
        "We also have a list of PDF titles:\n"
        f"{', '.join(pdf_titles)}\n\n"
        "Return the single title from that list which best matches the name/author in the footnote. "
        "If none seems relevant, return 'No match'."
    )

    try:
        response = openai.chat.completions.create(
            model="gpt-3.5-turbo",  # or any valid model you have
            messages=[
                {
                    "role": "system",
                    "content": "You match footnotes to a single PDF title from a given list."
                },
                {
                    "role": "user",
                    "content": user_prompt
                }
            ],
            temperature=0.0,
            max_tokens=100
        )
        # No subscript, use attributes:
        ans = response.choices[0].message.content.strip()

        best_match = None
        for title in pdf_titles:
            if title.lower() in ans.lower():
                best_match = title
                break

        if not best_match:
            if "no match" in ans.lower():
                return "No match"
            best_match = ans

        return best_match

    except RateLimitError as e:
        print("Got a 429 Too Many Requests error from OpenAI. Stopping code.")
        # You can either sys.exit(1) or return an error string
        # For demonstration, let's just raise again:
        raise e
    except Exception as e:
        print(f"OpenAI error: {e}")
        return "No match"

# ------------- Routes -------------

@app.route('/', methods=['GET', 'POST'])
def upload_files():
    """
    Page 1: Gather the sheet URL, drive URL, docx, etc.
    """
    if request.method == 'POST':
        sheet_url = request.form.get('sheet_url')
        drive_url = request.form.get('drive_url')
        sheet_name = request.form.get('sheet_name')
        word_file = request.files.get('word_doc')

        if not sheet_url or not drive_url or not sheet_name:
            return "Error: Missing required fields."

        if word_file and word_file.filename.endswith('.docx'):
            doc = Document(word_file)
            footnote_sentences = parse_footnote_sentences(doc)
            session['footnote_sentences'] = footnote_sentences
        else:
            session['footnote_sentences'] = {}

        session['sheet_url'] = sheet_url
        session['drive_url'] = drive_url
        session['sheet_name'] = sheet_name

        return redirect(url_for('authorize'))

    return render_template('upload.html')

@app.route('/editor')
def editor_interface():
    """
    Page 2: Show footnotes, docx sentences, plus a button to "Generate PDF Link" on demand.
    """
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

    # Retrieve stored data
    sheet_url = session.get('sheet_url')
    drive_url = session.get('drive_url')
    sheet_name = session.get('sheet_name')
    footnote_sentences = session.get('footnote_sentences', {})

    # Extract IDs
    sheet_id = extract_id_from_url(sheet_url)
    folder_id = extract_id_from_url(drive_url)

    # 1) Get footnotes from Google Sheets
    footnotes = get_footnotes(sheets_service, sheet_id, sheet_name)

    # 2) Get PDFs from Drive
    drive_pdfs = get_pdfs_in_drive(drive_service, folder_id)
    # Build dict for PDF => link
    pdf_dict = {item['name']: item['webViewLink'] for item in drive_pdfs}
    # We'll send this dict to the template as JSON
    pdf_dict_json = json.dumps(pdf_dict)

    session['credentials'] = credentials_to_dict(credentials)

    # Note: we are NOT calling match_pdf_via_openai for each footnote here
    # We'll do that on-demand in a new route.

    return render_template(
        'editor.html',
        footnotes=footnotes,
        footnote_sentences=footnote_sentences,
        drive_pdfs=drive_pdfs,
        sheet_id=sheet_id,
        sheet_name=sheet_name,
        pdf_dict_json=pdf_dict_json
    )

@app.route('/api/match_pdf', methods=['POST'])
def match_pdf():
    """
    AJAX endpoint to match a single footnote to a PDF link using OpenAI, on demand.
    Expects JSON like:
      {
        "footnote_number": 2,
        "footnote_text": "...",
        "docx_sentence": "...",
        "pdf_titles": ["PowellArticle.pdf", "SmithDoc.pdf", ...],
        "pdf_dict": {"PowellArticle.pdf": "...link...", "SmithDoc.pdf": "...link..."}
      }
    Returns JSON: { "pdf_link": "... or null ...", "error": "... if any" }
    """
    from flask import request
    data = request.get_json()

    footnote_text = data.get('footnote_text') or ""
    docx_sentence = data.get('docx_sentence') or ""
    pdf_titles = data.get('pdf_titles') or []
    pdf_dict = data.get('pdf_dict') or {}

    combined_text = f"{docx_sentence}\n\n{footnote_text}"

    try:
        best_title = match_pdf_via_openai(combined_text, pdf_titles)
        if best_title != "No match" and best_title in pdf_dict:
            pdf_link = pdf_dict[best_title]
        else:
            pdf_link = None
        return jsonify({"pdf_link": pdf_link})
    except RateLimitError:
        print("Rate-limited by OpenAI.")
        return jsonify({"error": "rate_limited"}), 429
    except Exception as e:
        print(f"Error in match_pdf: {e}")
        return jsonify({"error": "server_error"}), 500

@app.route('/authorize')
def authorize():
    session.pop('credentials', None)
    flow = Flow.from_client_secrets_file(
        GOOGLE_CLIENT_SECRETS_FILE,
        scopes=SCOPES,
        redirect_uri=url_for('oauth2callback', _external=True)
    )
    authorization_url, state = flow.authorization_url(
        access_type='offline',
        include_granted_scopes='true',
        prompt='consent'
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
    session['credentials'] = credentials_to_dict(credentials)
    return redirect(url_for('editor_interface'))

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

    sheet_id = request.form.get('sheet_id')
    sheet_name = request.form.get('sheet_name')
    form_data = request.form.to_dict()

    data_to_update = []
    pattern = re.compile(r'col_(\w)_(\d+)')

    for key, value in form_data.items():
        match = pattern.match(key)
        if match:
            col_letter = match.group(1).upper()
            row_number = match.group(2)
            cell_range = f"'{sheet_name}'!{col_letter}{row_number}"
            data_to_update.append({
                'range': cell_range,
                'values': [[value]]
            })

    if data_to_update:
        body = {
            'valueInputOption': 'USER_ENTERED',
            'data': data_to_update
        }
        try:
            sheets_service.spreadsheets().values().batchUpdate(
                spreadsheetId=sheet_id,
                body=body
            ).execute()
            flash("Footnotes updated successfully.")
        except Exception as e:
            flash(f"Error updating sheet: {e}")

    session['credentials'] = credentials_to_dict(credentials)
    return redirect(url_for('editor_interface'))

# ------------- Annotations API (Optional) -------------
@app.route('/api/save_annotation', methods=['POST'])
def save_annotation():
    data = request.get_json()
    pdf_id = data.get('pdf_id')
    page_number = data.get('pageNumber')
    annotation_data = data.copy()

    annotation_data.pop('pdf_id', None)
    annotation_data.pop('pageNumber', None)

    user_id = current_user.id if current_user.is_authenticated else None

    annotation = Annotation(
        pdf_id=pdf_id,
        page_number=page_number,
        user_id=user_id,
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
    for ann in annotations:
        d = json.loads(ann.data)
        d['id'] = ann.id
        d['user_id'] = ann.user_id
        annotations_data.append(d)
    return jsonify({'annotations': annotations_data})

@app.route('/api/update_annotation_comment', methods=['POST'])
def update_annotation_comment():
    data = request.get_json()
    annotation_id = data.get('id')
    comment = data.get('comment')

    annotation = Annotation.query.get(annotation_id)
    if not annotation:
        return jsonify({'status': 'error', 'message': 'Annotation not found'}), 404

    ann_data = json.loads(annotation.data)
    ann_data['comment'] = comment
    annotation.data = json.dumps(ann_data)
    db.session.commit()
    return jsonify({'status': 'success'})

# ------------- If you need to serve S3 PDFs (Optional) -------------
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
        head = s3_client.head_object(Bucket=bucket_name, Key=key)
        file_size = head['ContentLength']
        range_header = request.headers.get('Range', None)
        if not range_header:
            pdf_object = s3_client.get_object(Bucket=bucket_name, Key=key)
            data = pdf_object['Body'].read()
            response = Response(data, mimetype='application/pdf')
            response.headers['Content-Length'] = str(file_size)
            response.headers['Accept-Ranges'] = 'bytes'
            return response
        else:
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

            range_header = f'bytes={byte1}-{byte2 if byte2 is not None else ""}'
            pdf_object = s3_client.get_object(Bucket=bucket_name, Key=key, Range=range_header)
            data = pdf_object['Body'].read()

            rv = Response(data, 206, mimetype='application/pdf', content_type='application/pdf', direct_passthrough=True)
            rv.headers.add('Content-Range', f'bytes {byte1}-{byte1 + len(data) - 1}/{file_size}')
            rv.headers.add('Accept-Ranges', 'bytes')
            rv.headers.add('Content-Length', str(len(data)))
            return rv

    except Exception as e:
        return f"An error occurred while fetching the PDF: {e}", 500

@app.shell_context_processor
def make_shell_context():
    return {
        'db': db,
        'User': User,
        'Annotation': Annotation
    }

if __name__ == '__main__':
    # db.create_all()  # If you need to create the DB tables
    app.run(debug=True)
