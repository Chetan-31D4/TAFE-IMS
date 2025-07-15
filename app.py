import os
import json
import time
import pandas as pd
from flask     import Flask, render_template, request, redirect, url_for, session, flash, send_file, send_from_directory
from io        import BytesIO
from datetime  import datetime
from zoneinfo  import ZoneInfo
from datetime import datetime
import psycopg2
import psycopg2.extras
from flask_mail import Mail, Message
from werkzeug.utils import secure_filename
from flask import Flask, render_template, session, redirect, url_for
from datetime import datetime, timedelta
from zoneinfo import ZoneInfo
from dotenv import load_dotenv  
from werkzeug.utils import secure_filename
from flask import request, session, redirect, url_for
from datetime import date, timedelta
from flask import redirect, abort
import boto3
from boto3 import client
from botocore.exceptions import ClientError
from werkzeug.security import generate_password_hash, check_password_hash


ALLOWED_INVOICE_EXT = {'pdf'}

load_dotenv()

# === Cloudflare R2 client ===
R2_KEY    = os.getenv("R2_ACCESS_KEY_ID")
R2_SECRET = os.getenv("R2_SECRET_ACCESS_KEY")
R2_ACC    = os.getenv("R2_ACCOUNT_ID")
R2_BUCKET = os.getenv("R2_BUCKET")

r2 = boto3.client(
    "s3",
    endpoint_url=f"https://{R2_ACC}.r2.cloudflarestorage.com",
    aws_access_key_id=R2_KEY,
    aws_secret_access_key=R2_SECRET,
    region_name="auto",
)

app = Flask(__name__)

from datetime import timedelta

# enforce a 15-minute inactivity timeout
app.config['PERMANENT_SESSION_LIFETIME'] = timedelta(minutes=15)
app.secret_key = os.urandom(24)

app.config['MAIL_SERVER']        = 'smtp.gmail.com'
app.config['MAIL_PORT']          = 587
app.config['MAIL_USE_TLS']       = True
app.config['MAIL_USERNAME']      = 'tafe.inventory@gmail.com'
app.config['MAIL_PASSWORD']      = 'vjvg yuhl vbbd jaac'
app.config['MAIL_DEFAULT_SENDER']= ('Inventory Systems', 'no-reply@mydomain.com')

mail = Mail(app)

# PostgreSQL connection parameters (adjust as needed or via environment variables)
# DB_USER = os.environ.get('PG_USER', 'inv_user')
# DB_PASS = os.environ.get('PG_PASS', 'inv_pass123')
# DB_HOST = os.environ.get('PG_HOST', 'localhost')
# DB_PORT = os.environ.get('PG_PORT', '5432')
# DB_NAME = os.environ.get('PG_DB',   'inventorydb')

# DATABASE_URL = f"postgresql://{DB_USER}:{DB_PASS}@{DB_HOST}:{DB_PORT}/{DB_NAME}"

DATABASE_URL = os.environ['DATABASE_URL']

UPLOAD_FOLDER = os.path.join(os.getcwd(), 'uploads')
os.makedirs(UPLOAD_FOLDER, exist_ok=True)
ALLOWED_EXT = {'png','jpg','jpeg','pdf','docx'}

app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER


BUCKET = os.getenv('R2_BUCKET')

@app.route('/download/<path:key>')
def download_r2_object(key):
    """Redirect to a pre-signed R2 URL for the given object key."""
    try:
        url = r2.generate_presigned_url(
            ClientMethod="get_object",
            Params={"Bucket": BUCKET, "Key": key},
            ExpiresIn=300,  # URL valid for 5 minutes
        )
    except ClientError as e:
        # e.response['Error']['Code'] == 'NoSuchKey', etc.
        return abort(404)
    return redirect(url)

def get_db():
    """
    Opens a new connection to PostgreSQL (using DATABASE_URL) and returns it.
    The cursor_factory is set to RealDictCursor, so row fetches return dict-like objects.
    """
    conn = psycopg2.connect(DATABASE_URL)
    # Ensure that subsequent .cursor() calls return RealDictCursor by default:
    conn.cursor_factory = psycopg2.extras.RealDictCursor
    return conn


# ────────────────────────────────────────────────────────────────────
# 2.b) get_db_cursor(): convenience function to get (conn, cur) at once
#                      with RealDictCursor
# ────────────────────────────────────────────────────────────────────
def get_db_cursor():
    """
    Returns a tuple (conn, cur) where:
      - conn is a new psycopg2 connection (RealDictCursor by default)
      - cur  is conn.cursor(), so it yields rows as dictionaries.
    Caller is responsible for conn.commit() and conn.close() when done.
    """
    conn = get_db()
    cur  = conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
    return conn, cur


from flask import session
# … your other imports …


@app.context_processor
def inject_unread_comments():
    if 'username' not in session:
        return {}
    conn, cur = get_db_cursor()
    cur.execute("""
      SELECT
        rc.request_id,
        COUNT(*) AS cnt
      FROM request_comments rc
      LEFT JOIN discussion_read dr
        ON dr.request_id = rc.request_id
       AND dr.username   = %s
      WHERE rc.commented_at > COALESCE(dr.last_read_at, '1970-01-01')
        AND rc.commenter  != %s
      GROUP BY rc.request_id
    """, (session['username'], session['username']))
    rows = cur.fetchall()
    conn.close()

    unread_per_request = { r['request_id']: r['cnt'] for r in rows }
    total_unread       = sum(unread_per_request.values())

    return {
      'unread_comments':      total_unread,
      'unread_per_request':   unread_per_request
    }

@app.before_request
def check_session_timeout():
    # Flask clears session when it’s expired, so if they had a username before...
    if 'username' in session:
        # do nothing—still valid
        return
    # but if they *were* on an auth-protected page and now no longer are:
    if request.endpoint not in ('login', 'static'):
        flash("⏰ Session expired; please log in again.", "info")


@app.route('/contact')
def contact_us():
    # Only viewers should see it:
    if 'username' not in session or session.get('role') != 'viewer':
        return "Unauthorized", 403

    last_updated = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    return render_template('contact_us.html', last_updated=last_updated)

# @app.route('/')
# def dashboard():
#     if 'username' not in session:
#         return redirect(url_for('login'))

#     conn = get_db()
#     c = conn.cursor()
#     c.execute("SELECT * FROM products")
#     products = c.fetchall()

#     edit_requests = []
#     if session.get('role') == 'admin':
#         # OLD:
#         # c.execute("SELECT * FROM edit_requests WHERE status='pending'")
#         # edit_requests = c.fetchall()

#         # NEW:
#         c.execute("SELECT * FROM request_history WHERE status='pending' ORDER BY requested_at DESC")
#         edit_requests = c.fetchall()

#     conn.close()
#     return render_template('dashboard.html', products=products, role=session.get('role'), edit_requests=edit_requests)


# inside app.py (or wherever you defined dashboard)
from flask import request  # make sure this is already imported

@app.route('/')
def dashboard():
    if 'username' not in session:
        return redirect(url_for('login'))

    # 1) grab the 'search' parameter (GET)
    search_term = request.args.get('search', '').strip()

    conn, cur = get_db_cursor()
    if search_term:
        # Use ILIKE for case‐insensitive match in PostgreSQL
        cur.execute("""
            SELECT *
              FROM products
             WHERE name ILIKE %s
             ORDER BY id
        """, (f'%{search_term}%',))
    else:
        cur.execute("SELECT * FROM products ORDER BY id")
    products = cur.fetchall()
    conn.close()

    # 2) If admin, fetch pending requests exactly as before
    edit_requests = []
    if session.get('role') == 'admin':
        conn2, cur2 = get_db_cursor()
        cur2.execute("""
            SELECT *
              FROM request_history
             WHERE status = 'pending'
             ORDER BY requested_at DESC
        """)
        edit_requests = cur2.fetchall()
        conn2.close()

    # 3) Count open jobs for the badge / summary
    conn3, cur3 = get_db_cursor()
    if session.get('role') == 'admin':
        cur3.execute("SELECT COUNT(*) AS cnt FROM job_assignment WHERE status='pending'")
    else:
        cur3.execute(
            "SELECT COUNT(*) AS cnt FROM job_assignment "
            "WHERE assigned_to = %s AND status != 'completed'",
            (session['username'],)
        )
    pending_jobs = cur3.fetchone()['cnt']
    conn3.close()

    # 4) Pass everything into dashboard.html
    return render_template(
        'dashboard.html',
        products      = products,
        role          = session.get('role'),
        edit_requests = edit_requests,
        search        = search_term,
        pending_jobs  = pending_jobs
        )


@app.route('/add', methods=['POST'])
def add_product():
    if session.get('role') != 'admin':
        return "Unauthorized", 403
    name = request.form['name']
    type_ = request.form['type']
    quantity = request.form['quantity']
    conn = get_db()
    c = conn.cursor()
    c.execute('INSERT INTO products (name, type, quantity) VALUES (%s,%s,%s)', (name,type_,quantity))
    conn.commit()
    conn.close()
    return redirect(url_for('dashboard'))

def send_low_stock_alert_if_needed(product_id, new_quantity):
    """
    If new_quantity < reorder_level, fetch all admin emails and send an alert.
    """
    conn, cur = get_db_cursor()
    # 1) Fetch reorder_level and name
    cur.execute(
        "SELECT name, reorder_level FROM products WHERE id = %s",
        (product_id,)
    )
    row = cur.fetchone()
    conn.close()
    if not row:
        return

    name         = row['name']
    reorder_lvl  = row['reorder_level']

    if new_quantity < reorder_lvl:
        # 2) Fetch all admin emails
        conn, cur = get_db_cursor()
        cur.execute("SELECT email FROM users WHERE role = 'admin' AND email IS NOT NULL")
        admins = cur.fetchall()
        conn.close()

        admin_emails = [r['email'] for r in admins if r.get('email')]
        if not admin_emails:
            return

        # 3) Compose and send the email
        msg = Message(
            subject=f"[ALERT] Low stock: {name}",
            recipients=admin_emails
        )
        msg.body = (
            f"Attention Inventory Admins,\n\n"
            f"The product “{name}” (ID {product_id}) has fallen below its reorder level ({reorder_lvl}).\n"
            f"Current quantity is {new_quantity}.\n\n"
            "Please consider re‐ordering soon.\n\n"
            "– Inventory System"
        )
        mail.send(msg)


@app.route('/edit/<int:id>', methods=['POST'])
def edit_product(id):
    if session.get('role') != 'admin':
        return "Unauthorized", 403

    name = request.form['name']
    type_ = request.form['type']
    new_quantity = int(request.form['quantity'])

    conn = get_db()
    c = conn.cursor()

    c.execute("SELECT * FROM products WHERE id = %s", (id,))
    product = c.fetchone()

    if not product:
        conn.close()
        flash("Product not found.", "error")
        return redirect(url_for('dashboard'))

    old_quantity = product['quantity']
    change_amount = new_quantity - old_quantity

    # Update product
    c.execute('UPDATE products SET name = %s, type = %s, quantity = %s WHERE id = %s', 
              (name, type_, new_quantity, id))

    # Log to stock_history
    from datetime import datetime
    from zoneinfo import ZoneInfo
    changed_at = datetime.now(ZoneInfo("Asia/Kolkata")).strftime('%Y-%m-%d %H:%M:%S')

    c.execute('''
        INSERT INTO stock_history (
            product_id, product_name, changed_by, old_quantity, new_quantity, change_amount, changed_at
        ) VALUES (%s, %s, %s, %s, %s, %s, %s)
    ''', (id, name, session['username'], old_quantity, new_quantity, change_amount, changed_at))

    conn.commit()
    conn.close()
    flash("Product updated and change logged.", "success")
    return redirect(url_for('dashboard'))


from flask import (
    Flask, render_template, request, session,
    redirect, url_for, flash
)
from werkzeug.security import check_password_hash
import json

from datetime import timedelta
import os, time
from werkzeug.security import check_password_hash
from werkzeug.utils   import secure_filename
from flask           import (
    session, request, redirect, url_for, flash
)

# -- configure your session timeout once at app startup:
import time
import os
from flask import (
    flash, request, redirect, url_for, session, render_template
)
from werkzeug.utils import secure_filename
from werkzeug.security import check_password_hash

ALLOWED_IMAGE_EXT = {'png', 'jpg', 'jpeg'}

@app.route('/login', methods=['GET','POST'])
def login():
    if request.method == 'POST':
        username = request.form['username'].strip()
        password = request.form['password']
        lat      = request.form.get('latitude')
        lng      = request.form.get('longitude')
        snap     = request.files.get('snapshot')

        # require geo + camera
        if not (lat and lng and snap and snap.filename):
            flash("📍 & 📷 access are required to log in.", "error")
            return redirect(url_for('login'))

        ext = snap.filename.rsplit('.',1)[-1].lower()
        if ext not in ALLOWED_IMAGE_EXT:
            flash("Snapshot must be PNG/JPG.", "error")
            return redirect(url_for('login'))

        conn, cur = get_db_cursor()
        cur.execute("""
          SELECT id, password, role
            FROM users
           WHERE username = %s
             AND is_active = TRUE
        """, (username,))
        user = cur.fetchone()

        if user and check_password_hash(user['password'], password):
            # mark attendance & record geo
            mark_attendance(user['id'])
            cur.execute(
              "INSERT INTO user_locations (username, latitude, longitude) VALUES (%s,%s,%s)",
              (username, lat, lng)
            )

            # upload snapshot directly to R2
            timestamp     = int(time.time())
            safe_fname    = secure_filename(f"{user['id']}_{timestamp}.{ext}")
            snapshot_key  = f"login_snapshots/{safe_fname}"
            # rewind the file stream
            snap.stream.seek(0)
            r2.upload_fileobj(snap.stream, R2_BUCKET, snapshot_key)

            # record snapshot in DB
            cur.execute("""
              INSERT INTO user_login_snapshots
                (user_id, snapshot_key, captured_at)
              VALUES (%s, %s, NOW())
            """, (user['id'], snapshot_key))

            conn.commit()
            conn.close()

            # start session
            session.permanent   = True
            session['user_id']  = user['id']
            session['username'] = username
            session['role']     = user['role']
            return redirect(url_for('dashboard'))

        conn.close()
        flash("Invalid credentials or disabled account.", "error")
        return redirect(url_for('login'))

    return render_template('login.html')



@app.route('/tasks/cleanup_snapshots')
def cleanup_snapshots():
    # you can secure this behind a secret or automations IP check
    conn, cur = get_db_cursor()
    # find keys older than 7 days
    cur.execute("""
      SELECT snapshot_key
        FROM login_snapshots
       WHERE captured_at < now() - INTERVAL '7 days'
    """)
    old = [r['snapshot_key'] for r in cur.fetchall()]

    # delete from R2
    for key in old:
        r2.delete_object(R2_BUCKET, key)

    # delete DB rows
    cur.execute("""
      DELETE FROM login_snapshots
       WHERE captured_at < now() - INTERVAL '7 days'
    """)
    conn.commit(); conn.close()
    return '',204


from functools import wraps
from flask import session, redirect, url_for

def login_required(f):
    @wraps(f)
    def wrapper(*args, **kwargs):
        if 'username' not in session:
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return wrapper


from datetime import datetime
from zoneinfo import ZoneInfo  # Requires Python 3.9+

@app.route('/request_edit/<int:id>', methods=['POST'])
def request_edit(id):
    if session.get('role') != 'viewer':
        return "Unauthorized", 403

    requested_quantity = int(request.form['requested_quantity'])
    requested_by = session['username']

    conn = get_db()
    c = conn.cursor()

    c.execute("SELECT * FROM products WHERE id = %s", (id,))
    product = c.fetchone()

    if product is None:
        conn.close()
        flash("Product not found.", "error")
        return redirect(url_for('dashboard'))

    if requested_quantity > product['quantity']:
        conn.close()
        flash("Requested quantity exceeds available stock.", "error")
        return redirect(url_for('dashboard'))

    # Get current time in desired timezone (e.g., Asia/Kolkata)
    requested_at = datetime.now(ZoneInfo("Asia/Kolkata")).strftime('%Y-%m-%d %H:%M:%S')

    # Insert into request_history with requested_at
    c.execute('''
        INSERT INTO request_history (
            product_id, product_name, requested_quantity, requested_by, status, requested_at
        ) VALUES (%s, %s, %s, %s, 'pending', %s)
    ''', (id, product['name'], requested_quantity, requested_by, requested_at))

    conn.commit()
    conn.close()

    flash("Item request submitted to admin.", "info")
    return redirect(url_for('dashboard'))

from datetime import datetime
from zoneinfo import ZoneInfo  # Python 3.9+

from datetime import datetime
from zoneinfo import ZoneInfo


@app.route('/approve_request/<int:request_id>', methods=['GET', 'POST'])
def approve_request(request_id):
    if session.get('role') != 'admin':
        return "Unauthorized", 403

    # 1) Load the pending request
    conn, cur = get_db_cursor()
    cur.execute("SELECT * FROM request_history WHERE id = %s", (request_id,))
    req = cur.fetchone()
    if not req or req['status'] != 'pending':
        conn.close()
        flash("Request not found or already handled.", "error")
        return redirect(url_for('dashboard'))

    # ─── GET: show approval form ──────────────────────────────────────────────
    if request.method == 'GET':
        conn.close()
        return render_template(
            'approve_request.html',
            req_id          = request_id,
            product_name    = req['product_name'],
            requested_qty   = req['quantity'],
            current_comment = req.get('comment', '')  # ← use `comment` here
        )

    # ─── POST: process approval ─────────────────────────────────────────────
    admin_comment = request.form.get('admin_comment', '').strip()

    # 2) Re-fetch product to check/modify stock
    cur.execute("SELECT * FROM products WHERE id = %s", (req['product_id'],))
    product = cur.fetchone()
    if not product or product['quantity'] < req['quantity']:
        conn.close()
        flash("Insufficient stock to approve this request.", "error")
        return redirect(url_for('dashboard'))

    # 3) Deduct inventory
    old_qty       = product['quantity']
    approved_qty  = req['quantity']
    new_qty       = old_qty - approved_qty
    cur.execute(
        "UPDATE products SET quantity = %s WHERE id = %s",
        (new_qty, product['id'])
    )

    # 4) Log into stock_history (stock‐out for this approval)
    decision_at  = datetime.now(ZoneInfo("Asia/Kolkata"))\
                       .strftime('%Y-%m-%d %H:%M:%S')
    stock_remark = f"Issued for request #{request_id}"
    cur.execute("""
      INSERT INTO stock_history
        (product_id, product_name, changed_by,
         old_quantity, new_quantity, change_amount,
         changed_at, remark)
      VALUES (%s,%s,%s,%s,%s,%s,%s,%s)
    """, (
      product['id'],
      product['name'],
      session['username'],
      old_qty,
      new_qty,
      -approved_qty,
      decision_at,
      stock_remark
    ))

    # 5) Compute GST & total cost on the approved quantity
    price_per_item  = product['price']
    gst_exclusive   = price_per_item * approved_qty
    total_inclusive = round(gst_exclusive * 1.05, 2)

    # 6) Update request_history so that all approved items
    #    immediately count as “used” and none as “remaining”
    cur.execute("""
      UPDATE request_history
      SET 
        status          = 'approved',
        decision_at     = %s,
        decided_by      = %s,
        used            = quantity,   -- move everything into used
        remaining       = 0,          -- nothing left remaining
        gst_exclusive   = %s,
        total_inclusive = %s,
        comment         = %s
      WHERE id = %s
    """, (
      decision_at,
      session['username'],
      gst_exclusive,
      total_inclusive,
      admin_comment,
      request_id
    ))

    conn.commit()
    conn.close()

    # 7) Notify the viewer by email (including cost breakdown)
    try:
        conn, cur = get_db_cursor()
        cur.execute("SELECT email FROM users WHERE username = %s", (req['username'],))
        row = cur.fetchone()
        conn.close()

        if row and row.get('email'):
            msg = Message(
                subject=f"[Inventory] Request #{request_id} APPROVED",
                recipients=[row['email']]
            )
            msg.body = (
                f"Hello {req['username']},\n\n"
                f"Your request for {approved_qty} × {req['product_name']} has been APPROVED.\n\n"
                f" • Approved quantity: {approved_qty}\n"
                f" • Admin comment: {admin_comment or '—'}\n\n"
                "Thank you,\nInventory Team,\nTAFE"
            )
            mail.send(msg)
    except Exception as e:
        flash(f"Could not send approval email: {e}", "warning")

    flash(
      f"Request approved. Stock updated (–{approved_qty}), "
      f"GST excl: ₹{gst_exclusive:.2f}, incl: ₹{total_inclusive:.2f}.",
      "success"
    )
    return redirect(url_for('dashboard'))

@app.route('/reject_request/<int:request_id>', methods=['GET', 'POST'])
def reject_request(request_id):
    if session.get('role') != 'admin':
        return "Unauthorized", 403

    # 1) Fetch the pending request
    conn, cur = get_db_cursor()
    cur.execute("SELECT * FROM request_history WHERE id = %s", (request_id,))
    req = cur.fetchone()
    conn.close()

    if not req or req['status'] != 'pending':
        flash("Request not found or already handled.", "error")
        return redirect(url_for('dashboard'))

    # ─────────────── GET: Show the "Reject" form with comment box ───────────────
    if request.method == 'GET':
        return render_template(
            'reject_request.html',
            req_id          = request_id,
            product_name    = req['product_name'],
            requested_qty   = req['quantity'],
            current_comment = req.get('comment', '') or ''
        )

    # ─────────────── POST: Process the rejection ───────────────
    admin_comment   = request.form.get('admin_comment', '').strip()
    decision_at_str = datetime.now(ZoneInfo("Asia/Kolkata")).strftime('%Y-%m-%d %H:%M:%S')

    conn, cur = get_db_cursor()
    cur.execute(
        """
        UPDATE request_history
        SET 
            status      = 'rejected',
            decision_at = %s,
            decided_by  = %s,
            comment     = %s
        WHERE id = %s
        """,
        (
            decision_at_str,
            session['username'],  # admin’s username
            admin_comment,
            request_id
        )
    )
    conn.commit()
    conn.close()

    # Send rejection email to the viewer, if available
    try:
        conn, cur = get_db_cursor()
        viewer_username = req['username']
        cur.execute("SELECT email FROM users WHERE username = %s", (viewer_username,))
        viewer_row = cur.fetchone()
        conn.close()

        if viewer_row and viewer_row.get('email'):
            viewer_email = viewer_row['email']
            msg = Message(
                subject=f"Your request #{request_id} has been REJECTED",
                recipients=[viewer_email]
            )
            msg.body = (
                f"Hello {viewer_username},\n\n"
                f"Your request for {req['quantity']} × {req['product_name']} has been *REJECTED*.\n"
                f"  • Admin comment: {admin_comment or '—'}\n\n"
                "Please contact the inventory team if you have questions.\n\n"
                "Regards,\nInventory System,\nTAFE"
            )
            mail.send(msg)
    except Exception as e:
        flash(f"⚠️ Could not send rejection email to {viewer_username}: {e}", "warning")

    flash("Request rejected, comment saved, and email sent to viewer.", "info")
    return redirect(url_for('dashboard'))



@app.route('/logout')
def logout():
    session.clear()
    flash('Logged out successfully!', 'info')
    return redirect(url_for('login'))

# @app.route('/history')
# def viewer_history():
#     if 'username' not in session:
#         return redirect(url_for('login'))

#     conn, cur = get_db_cursor()
#     if session['role'] == 'viewer':
#         cur.execute('''
#             SELECT *
#             FROM request_history
#             WHERE username = %s
#             ORDER BY requested_at DESC
#         ''', (session['username'],))
#     else:
#         cur.execute('''
#             SELECT *
#             FROM request_history
#             ORDER BY requested_at DESC
#         ''')

#     history_rows = cur.fetchall()
#     conn.close()
#     return render_template('history.html', history=history_rows)


@app.route('/history')
def viewer_history():
    if 'username' not in session:
        return redirect(url_for('login'))

    conn, cur = get_db_cursor()

    # 1) Fetch the history rows
    if session['role'] == 'viewer':
        cur.execute(
            '''
            SELECT *
            FROM request_history
            WHERE username = %s
            ORDER BY requested_at DESC
            ''',
            (session['username'],)
        )
    else:
        cur.execute(
            '''
            SELECT *
            FROM request_history
            ORDER BY requested_at DESC
            '''
        )
    history = cur.fetchall()

    # 2) Build an attachments map: { request_id: [<attachment rows>] }
    attach_map = {}
    for row in history:
        cur.execute(
            "SELECT * FROM attachments WHERE request_id = %s ORDER BY uploaded_at",
            (row['id'],)
        )
        attach_map[row['id']] = cur.fetchall()

    conn.close()

    # 3) Pass both history *and* attachments into the template
    return render_template(
        'history.html',
        history=history,
        attachments=attach_map
    )



@app.route('/api/pending_requests')
def get_pending_requests():
    if session.get('role') != 'admin':
        return "Forbidden", 403

    conn, cur = get_db_cursor()
    cur.execute('''
        SELECT
          id,
          product_id,
          product_name,
          quantity,
          reason,
          sub_reason,
          drone_number,
          username AS requested_by,
          requested_at
        FROM request_history
        WHERE status = 'pending'
        ORDER BY requested_at DESC
    ''')
    rows = cur.fetchall()
    conn.close()

    result = []
    for r in rows:
        # r['requested_at'] is a datetime, convert to string
        requested_at_str = r['requested_at'].strftime('%Y-%m-%d %H:%M:%S')
        result.append({
            "id":                 r["id"],
            "product_id":         r["product_id"],
            "product_name":       r["product_name"],
            "requested_quantity": r["quantity"],       # ← changed key from "quantity" to "requested_quantity"
            "reason":             r["reason"],
            "sub_reason":         r["sub_reason"],
            "drone_number":       r["drone_number"],
            "requested_by":       r["requested_by"],
            "requested_at":       requested_at_str
        })
    return {"requests": result}


@app.route('/api/download-filtered-excel', methods=['POST'])
def download_filtered_excel():
    if 'username' not in session or session.get('role') != 'admin':
        return "Unauthorized", 403

    data = request.json.get('data', [])

    if not data:
        return "No data provided", 400

    # Define column names matching the 13‐column order sent from JS:
    columns = [
        'ID',
        'Product',
        'Qty',
        'Reason',
        'Sub Reason',
        'Drone No.',
        'Status',
        'Requested At',
        'Decision At',
        'Admin',
        'Requested By',
        'Used',
        'Remaining'
    ]

    # Create DataFrame with those columns
    df = pd.DataFrame(data, columns=columns)

    output = BytesIO()
    with pd.ExcelWriter(output, engine='xlsxwriter') as writer:
        df.to_excel(writer, index=False, sheet_name='Filtered History')

    output.seek(0)
    return send_file(
        output,
        download_name="filtered_request_history.xlsx",
        as_attachment=True,
        mimetype='application/vnd.openxmlformats-officedocument.spreadsheetml.sheet'
    )


@app.route('/stock_history')
def stock_history():
    if session.get('role') != 'admin':
        return "Unauthorized", 403

    conn = get_db()
    c = conn.cursor()
    c.execute("SELECT * FROM stock_history ORDER BY changed_at DESC")
    history = c.fetchall()
    conn.close()
    return render_template('stock_history.html', history=history)


@app.route('/download_stock_history')
def download_stock_history():
    if session.get('role') != 'admin':
        return "Unauthorized", 403

    keyword = request.args.get('q', '').strip()

    conn = get_db()
    c = conn.cursor()

    if keyword:
        c.execute('''
            SELECT * FROM stock_history
            WHERE product_name LIKE %s
            ORDER BY changed_at DESC
        ''', (f'%{keyword}%',))
    else:
        c.execute("SELECT * FROM stock_history ORDER BY changed_at DESC")

    rows = c.fetchall()
    conn.close()

    df = pd.DataFrame(rows, columns=[desc[0] for desc in c.description])

    output = BytesIO()
    df.to_excel(output, index=False)
    output.seek(0)

    return send_file(output, as_attachment=True, download_name="stock_history.xlsx", mimetype='application/vnd.openxmlformats-officedocument.spreadsheetml.sheet')

@app.route('/add_to_cart', methods=['POST'])
def add_to_cart():
    if session.get('role') != 'viewer':
        return "Unauthorized", 403

    # 1. Read the new quantity field from the form:
    try:
        requested_qty = int(request.form['quantity'])
        if requested_qty < 1:
            raise ValueError()
    except (KeyError, ValueError):
        flash("Please provide a valid quantity (1 or more).", "error")
        return redirect(url_for('dashboard'))

    product_id = int(request.form['product_id'])
    reason = request.form['reason']
    sub_reason = request.form.get('sub_reason', '')
    drone_number = request.form['drone_number']

    if not reason or not drone_number:
        flash("Reason and Drone Number are required.", "error")
        return redirect(url_for('dashboard'))

    # Initialize cart
    if 'cart' not in session:
        session['cart'] = []

    # Prevent duplicates (same product_id) – you could also allow duplicates if you prefer
    for item in session['cart']:
        if item['product_id'] == product_id:
            flash("This item is already in your cart.", "warning")
            return redirect(url_for('dashboard'))

    conn = get_db()
    c = conn.cursor()
    c.execute("SELECT name FROM products WHERE id = %s", (product_id,))
    result = c.fetchone()
    conn.close()

    if not result:
        flash("Product not found.", "error")
        return redirect(url_for('dashboard'))

    product_name = result['name']

    # Add to cart, including the quantity
    session['cart'].append({
        'product_id': product_id,
        'product_name': product_name,
        'quantity': requested_qty,      # <— NEW FIELD
        'reason': reason,
        'sub_reason': sub_reason,
        'drone_number': drone_number
    })

    session.modified = True
    flash("Item added to cart.", "success")
    return redirect(url_for('dashboard'))


import io
from flask import flash, redirect, request, session, url_for
from werkzeug.utils import secure_filename
from datetime import datetime
from zoneinfo import ZoneInfo

ALLOWED_EXT = {'png','jpg','jpeg','pdf','docx'}

@app.route('/submit_cart', methods=['POST'])
def submit_cart():
    if 'username' not in session or session.get('role') != 'viewer':
        return "Unauthorized", 403

    cart = session.get('cart', [])
    if not cart:
        flash("Your cart is empty.", "error")
        return redirect(url_for('view_cart'))

    username  = session['username']
    timestamp = datetime.now(ZoneInfo("Asia/Kolkata")).strftime("%Y-%m-%d %H:%M:%S")

    # 1) Persist the cart items into request_history
    conn, cur = get_db_cursor()
    request_ids = []
    for item in cart:
        cur.execute('''
            INSERT INTO request_history
              (username, product_id, product_name, quantity,
               reason, sub_reason, drone_number, status, requested_at, comment)
            VALUES (%s, %s, %s, %s, %s, %s, %s, 'pending', %s, '')
            RETURNING id
        ''', (
            username,
            item['product_id'],
            item['product_name'],
            item['quantity'],
            item['reason'],
            item['sub_reason'],
            item['drone_number'],
            timestamp
        ))
        request_ids.append(cur.fetchone()['id'])

    # 2) Read & buffer every uploaded file once
    raw_files = []
    for f in request.files.getlist('attachments'):
        filename = secure_filename(f.filename or "")
        ext = filename.rsplit('.', 1)[-1].lower()
        if filename and ext in ALLOWED_EXT:
            data = f.read()             # consume it now
            raw_files.append((filename, data))

    # 3) For each new request row, re-create a fresh BytesIO for each file
    for req_id in request_ids:
        for filename, data in raw_files:
            key = f"{req_id}/{filename}"
            bio = io.BytesIO(data)
            # rewind just in case
            bio.seek(0)
            # upload to your R2 bucket
            r2.upload_fileobj(bio, R2_BUCKET, key)
            cur.execute('''
                INSERT INTO attachments
                  (request_id, filename, stored_path, uploaded_by)
                VALUES (%s, %s, %s, %s)
            ''', (req_id, filename, key, username))

    conn.commit()
    conn.close()

    # 4) Notify admins
    try:
        conn2, cur2 = get_db_cursor()
        cur2.execute("SELECT email FROM users WHERE role = 'admin'")
        admins = [r['email'] for r in cur2.fetchall() if r['email']]
        conn2.close()

        if admins:
            lines = [f"User {username} submitted:"]
            for item in cart:
                lines.append(
                    f" • {item['quantity']}×{item['product_name']} "
                    f"(Reason: {item['reason']}, Drone: {item['drone_number']})"
                )
            msg = Message(
                subject=f"New Inventory Request from {username}",
                recipients=admins
            )
            msg.body = "\n".join(lines)
            mail.send(msg)
    except Exception as e:
        flash(f"⚠️ Could not email admins: {e}", "warning")

    # 5) Clear cart & done
    session['cart'] = []
    flash("Requests submitted and attachments uploaded! Admins notified.", "success")
    return redirect(url_for('dashboard'))


@app.route('/view_cart')
def view_cart():
    if 'username' not in session or session.get('role') != 'viewer':
        return "Unauthorized", 403

    cart = session.get('cart', [])
    return render_template('view_cart.html', cart=cart)



# @app.route('/edit_usage/<int:request_id>', methods=['GET', 'POST'])
# def edit_usage(request_id):
#     # 1) Only logged-in viewers can access this
#     if 'username' not in session or session.get('role') != 'viewer':
#         return "Unauthorized", 403

#     conn = get_db()
#     c = conn.cursor()

#     # 2) Fetch that specific request row
#     c.execute("SELECT * FROM request_history WHERE id = %s", (request_id,))
#     req = c.fetchone()

#     # 3) Validate that it exists, belongs to the current viewer, and is approved
#     if not req or req['username'] != session['username'] or req['status'] != 'approved':
#         conn.close()
#         flash("You cannot update usage for this request.", "error")
#         return redirect(url_for('viewer_history'))  # or 'history'

#     # If it’s a GET request, show the form
#     if request.method == 'GET':
#         conn.close()
#         return render_template(
#             'edit_usage.html',
#             req_id=req['id'],
#             used=req['used'],
#             remaining=req['remaining'],
#             approved_qty=req['quantity']
#         )

#     # Otherwise, it’s a POST → process the form submission
#     try:
#         used = int(request.form['used'])
#         remaining = int(request.form['remaining'])
#     except (KeyError, ValueError):
#         flash("Please enter valid integer values.", "error")
#         conn.close()
#         return redirect(url_for('edit_usage', request_id=request_id))

#     # Enforce that used + remaining === approved quantity
#     approved_qty = req['quantity']
#     if used < 0 or remaining < 0 or (used + remaining) != approved_qty:
#         flash("Used + Remaining must exactly equal the approved quantity.", "error")
#         conn.close()
#         return redirect(url_for('edit_usage', request_id=request_id))

#     # Update the row
#     c.execute(
#         "UPDATE request_history SET used = %s, remaining = %s WHERE id = %s",
#         (used, remaining, request_id)
#     )
#     conn.commit()
#     conn.close()

#     flash("Usage updated successfully.", "success")
#     return redirect(url_for('viewer_history'))

@app.route('/edit_usage/<int:request_id>', methods=['GET','POST'])
def edit_usage(request_id):
    if 'username' not in session or session.get('role')!='viewer':
        return "Unauthorized", 403

    conn, cur = get_db_cursor()
    cur.execute("SELECT * FROM request_history WHERE id=%s", (request_id,))
    req = cur.fetchone()

    # must exist, belong to this user, and already approved
    if not req or req['username']!=session['username'] or req['status']!='approved':
        conn.close()
        flash("You cannot update usage for this request.", "error")
        return redirect(url_for('viewer_history'))

    # how many items the user actually holds right now
    total_on_hand = req['used'] + req['remaining']

    # if they’ve already returned everything, there’s nothing to update
    if total_on_hand == 0:
        conn.close()
        flash("You have no items on hand to update usage for.", "warning")
        return redirect(url_for('viewer_history'))

    if request.method == 'GET':
        # seed the form so that ALL of their on-hand quantity is in “Used”
        used      = total_on_hand
        remaining = 0
        remark    = req.get('usage_remark','')   or ''
        location  = req.get('usage_location','') or ''
        conn.close()
        return render_template('edit_usage.html',
                               req_id       = request_id,
                               used         = used,
                               remaining    = remaining,
                               approved_qty = total_on_hand,
                               remark       = remark,
                               location     = location)

    # ─── POST ───
    try:
        used      = int(request.form['used'])
        remaining = int(request.form['remaining'])
        remark    = request.form.get('remark','').strip()
        location  = request.form.get('location','').strip()
    except ValueError:
        flash("Please enter valid numeric values.", "error")
        conn.close()
        return redirect(url_for('edit_usage', request_id=request_id))

    # must sum to what they actually hold
    if used < 0 or remaining < 0 or (used + remaining) != total_on_hand:
        flash(f"Used + Remaining must equal the {total_on_hand} items you have on hand.", "error")
        conn.close()
        return redirect(url_for('edit_usage', request_id=request_id))

    cur.execute("""
      UPDATE request_history
         SET used           = %s,
             remaining      = %s,
             usage_remark   = %s,
             usage_location = %s
       WHERE id = %s
    """, (used, remaining, remark, location, request_id))

    conn.commit()
    conn.close()

    flash("Usage, remark and location updated successfully.", "success")
    return redirect(url_for('viewer_history'))




@app.route('/test-email')
def test_email():
    """
    A quick route to verify your SMTP setup. Visit /test-email in browser.
    """
    try:
        msg = Message(
            subject    = "Test Email from Flask",
            recipients = ["chetanaggarwal21123@gmail.com"]
        )
        msg.body = "If you see this, SMTP is working!"
        mail.send(msg)
        return "✓ Email sent (check your inbox)."
    except Exception as e:
        return f"Error sending email: {e}"

# @app.route('/analytics')
# def analytics():
#     # Only admins can view analytics
#     if 'username' not in session or session.get('role') != 'admin':
#         return redirect(url_for('dashboard'))

#     # ─── 1) Top 10 Most Requested Items (Last 30 days) ───
#     conn, cur = get_db_cursor()

#     # Compute the "30 days ago" cutoff in Asia/Kolkata
#     thirty_days_ago = (datetime.now(ZoneInfo("Asia/Kolkata")) - timedelta(days=45)).strftime('%Y-%m-%d %H:%M:%S')

#     # Sum up approved quantities per product_name in the last 30 days
#     cur.execute("""
#         SELECT
#           product_name,
#           SUM(quantity) AS total_requested
#         FROM request_history
#         WHERE status = 'approved'
#           AND decision_at::timestamp >= %s
#         GROUP BY product_name
#         ORDER BY total_requested DESC
#         LIMIT 10
#     """, (thirty_days_ago,))
#     top_rows = cur.fetchall()
#     conn.close()

#     top_requested = [
#         { 'product_name': r['product_name'], 'total_requested': int(r['total_requested']) }
#         for r in top_rows
#     ]

#     # ─── 2) Daily Approved Quantity (Last 30 days) ───
#     # First initialize a dict for each of the last 30 calendar dates (YYYY-MM-DD) → 0
#     daily_counts = {}
#     today_date = datetime.now(ZoneInfo("Asia/Kolkata")).date()
#     for i in range(45):
#         day = today_date - timedelta(days=44 - i)
#         daily_counts[day.isoformat()] = 0

#     # Now fetch actual sums, grouping by the “date” portion of decision_at (shifted into Asia/Kolkata)
#     conn, cur = get_db_cursor()
#     cur.execute("""
#         SELECT
#           DATE( (decision_at::timestamp) AT TIME ZONE 'Asia/Kolkata' ) AS day_date,
#           SUM(quantity) AS daily_approved
#         FROM request_history
#         WHERE status = 'approved'
#           AND decision_at::timestamp >= %s
#         GROUP BY day_date
#         ORDER BY day_date
#     """, (thirty_days_ago,))
#     trend_rows = cur.fetchall()
#     conn.close()

#     for tr in trend_rows:
#         day_str = tr['day_date'].isoformat()        # e.g. '2025-05-10'
#         if day_str in daily_counts:
#             daily_counts[day_str] = int(tr['daily_approved'])

#     # Build a list of dicts in date order:
#     usage_trend = [
#         { 'day_date': date_str, 'daily_approved': qty }
#         for date_str, qty in daily_counts.items()
#     ]

#     # ─── 3) Render template with both lists ───
#     return render_template(
#         'analytics.html',
#         top_requested=top_requested,
#         usage_trend=usage_trend
#     )


from flask import request, session, redirect, url_for, render_template
from datetime import date, timedelta, datetime
from zoneinfo import ZoneInfo

@app.route('/analytics')
def analytics():
    # only admins
    if session.get('role') != 'admin':
        return redirect(url_for('dashboard'))

    conn, cur = get_db_cursor()

    # 1) product dropdown
    cur.execute("SELECT name FROM products ORDER BY name")
    product_list = [r['name'] for r in cur.fetchall()]

    # 2) which product?
    selected = request.args.get('product', 'All')

    # 3) last 45 days window
    today = date.today()
    start = today - timedelta(days=44)

    # 4) Top‐10 bar data (always “All”)
    cur.execute("""
      SELECT product_name, SUM(quantity) AS total_requested
      FROM request_history
      WHERE status='approved'
        AND decision_at::timestamp >= %s
      GROUP BY product_name
      ORDER BY total_requested DESC
      LIMIT 10
    """, (start,))
    top_requested = [
      {'product_name': r['product_name'], 'total_requested': int(r['total_requested'])}
      for r in cur.fetchall()
    ]

    # 5) Line data
    if selected == 'All':
        # daily approved
        cur.execute("""
          SELECT
            DATE(decision_at::timestamp AT TIME ZONE 'Asia/Kolkata') AS day,
            SUM(quantity) AS level
          FROM request_history
          WHERE status='approved'
            AND decision_at::timestamp >= %s
          GROUP BY day
          ORDER BY day
        """, (start,))
        usage_trend = [
          {'day': r['day'].strftime('%Y-%m-%d'), 'level': int(r['level'])}
          for r in cur.fetchall()
        ]

    else:
        # per‐product net change, then cumulative
        cur.execute("""
          WITH used AS (
            SELECT
              DATE(decision_at::timestamp AT TIME ZONE 'Asia/Kolkata') AS day,
              SUM(quantity) AS u
            FROM request_history
            WHERE status='approved'
              AND product_name = %s
              AND decision_at::timestamp >= %s
            GROUP BY 1
          ), rec AS (
            SELECT
              DATE(changed_at::timestamp AT TIME ZONE 'Asia/Kolkata') AS day,
              SUM(change_amount) AS r
            FROM stock_history
            WHERE product_name = %s
              AND changed_at::timestamp >= %s
            GROUP BY 1
          ), days AS (
            SELECT generate_series(%s::date, %s::date, '1 day') AS day
          )
          SELECT
            days.day,
            COALESCE(rec.r,0) - COALESCE(used.u,0) AS net_change
          FROM days
          LEFT JOIN used ON used.day = days.day
          LEFT JOIN rec  ON rec.day  = days.day
          ORDER BY days.day
        """, (selected, start, selected, start, start, today))
        rows = cur.fetchall()

        # fetch “current” and back‐compute
        cur.execute("SELECT quantity FROM products WHERE name=%s", (selected,))
        current = cur.fetchone()['quantity']

        # cumulative
        level = current - sum(r['net_change'] for r in rows)
        usage_trend = []
        for r in rows:
            level += r['net_change']
            usage_trend.append({
              'day':   r['day'].strftime('%Y-%m-%d'),
              'level': level
            })

    conn.close()

    return render_template('analytics.html',
                           product_list  = product_list,
                           selected      = selected,
                           top_requested = top_requested,
                           usage_trend   = usage_trend)


# @app.route('/request/<int:request_id>/comments', methods=['GET','POST'])
# def comment_thread(request_id):
#     user = session.get('username')
#     if not user:
#         return redirect(url_for('login'))

#     conn, cur = get_db_cursor()

#     if request.method == 'POST':
#         text = request.form.get('comment', '').strip()
#         if text:
#             cur.execute('''
#               INSERT INTO request_comments
#                 (request_id, commenter, comment_text)
#               VALUES (%s, %s, %s)
#             ''', (request_id, user, text))
#             conn.commit()
#         conn.close()

#         # ← Redirect *after* handling POST to clear the form
#         return redirect(url_for('comment_thread', request_id=request_id))

#     # GET branch: render the page
#     cur.execute("SELECT * FROM request_history WHERE id = %s", (request_id,))
#     req = cur.fetchone()

#     cur.execute("""
#       SELECT * 
#       FROM request_comments 
#       WHERE request_id = %s
#       ORDER BY commented_at
#     """, (request_id,))
#     comments = cur.fetchall()
#     conn.close()

#     return render_template(
#         'comment_thread.html',
#         req=req,
#         comments=comments
#     )



# @app.route('/request/<int:request_id>/comments', methods=['GET','POST'])
# def comment_thread(request_id):
#     user = session.get('username')
#     if not user:
#         return redirect(url_for('login'))

#     conn, cur = get_db_cursor()

#     if request.method == 'POST':
#         text = request.form['comment'].strip()
#         if text:
#             cur.execute(
#               "INSERT INTO request_comments (request_id, commenter, comment_text) VALUES (%s,%s,%s)",
#               (request_id, user, text)
#             )
#             conn.commit()
#         conn.close()
#         return redirect(url_for('comment_thread', request_id=request_id))

#     # — GET: fetch the request & its comments
#     cur.execute("SELECT * FROM request_history WHERE id = %s", (request_id,))
#     req = cur.fetchone()
#     cur.execute("SELECT * FROM request_comments WHERE request_id = %s ORDER BY commented_at", (request_id,))
#     comments = cur.fetchall()

#     # — mark it as read
#     now = datetime.now(ZoneInfo("Asia/Kolkata"))
#     cur.execute("""
#       INSERT INTO discussion_read (request_id, username, last_read_at)
#       VALUES (%s,%s,%s)
#       ON CONFLICT (request_id, username)
#       DO UPDATE SET last_read_at = EXCLUDED.last_read_at
#     """, (request_id, user, now))
#     conn.commit()
#     conn.close()

#     return render_template('comment_thread.html', req=req, comments=comments)


from werkzeug.utils import secure_filename

ALLOWED_EXT = {'png','jpg','jpeg','pdf','docx'}

@app.route('/request/<int:request_id>/comments', methods=['GET','POST'])
def comment_thread(request_id):
    user = session.get('username')
    if not user:
        return redirect(url_for('login'))

    conn, cur = get_db_cursor()

    if request.method == 'POST':
        # 1) Insert the comment and get its new ID
        text = request.form.get('comment','').strip()
        cur.execute(
            """
            INSERT INTO request_comments
              (request_id, commenter, comment_text)
            VALUES (%s, %s, %s)
            RETURNING id
            """,
            (request_id, user, text)
        )
        comment_id = cur.fetchone()['id']

        # 2) Handle uploaded files
        files = request.files.getlist('files')
        for f in files:
            if not f or not f.filename:
                continue
            fn  = secure_filename(f.filename)
            ext = fn.rsplit('.',1)[-1].lower()
            if ext in ALLOWED_EXT:
                key = f"comments/{comment_id}/{fn}"
                r2.upload_fileobj(f,R2_BUCKET,key)
                cur.execute(
                    """
                    INSERT INTO comment_attachments
                      (comment_id, filename, stored_path, uploaded_by)
                    VALUES (%s, %s, %s, %s)
                    """,
                    (comment_id, fn, key, user)
                )

        conn.commit()
        conn.close()

        # Post-redirect-get so refresh won’t repost files/comments
        return redirect(url_for('comment_thread', request_id=request_id))

    # ── GET branch ──
    # fetch the original request
    cur.execute(
        "SELECT * FROM request_history WHERE id = %s",
        (request_id,)
    )
    req = cur.fetchone()

    # fetch all comments
    cur.execute(
        """
        SELECT * 
          FROM request_comments 
         WHERE request_id = %s
         ORDER BY commented_at
        """,
        (request_id,)
    )
    comments = cur.fetchall()

    # for each comment, fetch its attachments
    attach_map = {}
    for c in comments:
        cur.execute(
            """
            SELECT * 
              FROM comment_attachments
             WHERE comment_id = %s
             ORDER BY uploaded_at
            """,
            (c['id'],)
        )
        attach_map[c['id']] = cur.fetchall()

    # mark discussion as read
    now = datetime.now(ZoneInfo("Asia/Kolkata"))
    cur.execute(
        """
        INSERT INTO discussion_read (request_id, username, last_read_at)
        VALUES (%s, %s, %s)
        ON CONFLICT (request_id, username)
        DO UPDATE SET last_read_at = EXCLUDED.last_read_at
        """,
        (request_id, user, now)
    )
    conn.commit()
    conn.close()

    # render with both comments and attachments map
    return render_template(
        'comment_thread.html',
        req=req,
        comments=comments,
        attachments=attach_map
    )


@app.route('/uploads/<filename>')
def uploaded_file(filename):
    return send_from_directory(app.config['UPLOAD_FOLDER'], filename)



@app.route('/request/<int:request_id>/attachments')
def view_attachments(request_id):
    # Only logged-in users can view (adjust role logic if needed)
    if 'username' not in session:
        return redirect(url_for('login'))

    conn, cur = get_db_cursor()
    # Fetch the request itself (optional, if you want to show product name)
    cur.execute("SELECT * FROM request_history WHERE id = %s", (request_id,))
    req = cur.fetchone()

    # Fetch all attachments
    cur.execute("""
      SELECT id, filename, stored_path, uploaded_by, uploaded_at
      FROM attachments
      WHERE request_id = %s
      ORDER BY uploaded_at
    """, (request_id,))
    files = cur.fetchall()
    conn.close()

    # generate presigned URLs for each file
    for f in files:
      f['url'] = r2.generate_presigned_url(
        'get_object',
        Params={'Bucket': R2_BUCKET, 'Key': f['stored_path']},
        ExpiresIn=3600
      )
    return render_template(
        'view_attachments.html',
        req=req,
        files=files
    )

# @app.route('/return_remaining/<int:request_id>', methods=['POST'])
# def return_remaining(request_id):
#     if session.get('role') != 'admin':
#         return "Unauthorized", 403

#     conn, cur = get_db_cursor()

#     # 1) Look up the pending request
#     cur.execute("SELECT remaining, product_id, product_name FROM request_history WHERE id = %s", (request_id,))
#     req = cur.fetchone()
#     if not req or req['remaining'] <= 0:
#         conn.close()
#         flash("Nothing to return on that request.", "warning")
#         return redirect(url_for('viewer_history'))

#     returned_qty = req['remaining']
#     prod_id      = req['product_id']
#     prod_name    = req['product_name']

#     # 2) Fetch old stock level
#     cur.execute("SELECT quantity FROM products WHERE id = %s", (prod_id,))
#     prod = cur.fetchone()
#     old_qty = prod['quantity'] if prod else 0

#     # 3) Update products table
#     new_qty = old_qty + returned_qty
#     cur.execute(
#         "UPDATE products SET quantity = %s WHERE id = %s",
#         (new_qty, prod_id)
#     )

#     # 4) Zero‐out the “remaining” in the request_history
#     cur.execute(
#         "UPDATE request_history SET remaining = 0 WHERE id = %s",
#         (request_id,)
#     )

#     # 5) Log it in stock_history
#     changed_at = datetime.now(ZoneInfo("Asia/Kolkata")).strftime('%Y-%m-%d %H:%M:%S')
#     cur.execute('''
#         INSERT INTO stock_history (
#           product_id, product_name, changed_by,
#           old_quantity, new_quantity, change_amount, changed_at
#         ) VALUES (%s, %s, %s, %s, %s, %s, %s)
#     ''', (
#         prod_id,
#         prod_name,
#         session['username'],
#         old_qty,
#         new_qty,
#         returned_qty,
#         changed_at
#     ))

#     conn.commit()
#     conn.close()

#     flash(f"Returned {returned_qty} unit(s) of “{prod_name}” back to stock.", "success")
#     return redirect(url_for('viewer_history'))

from datetime import datetime
from zoneinfo import ZoneInfo
from flask import session, flash, redirect, url_for

from datetime import datetime
from zoneinfo import ZoneInfo
from flask import session, flash, redirect, url_for

@app.route('/return_remaining/<int:request_id>', methods=['POST'])
def return_remaining(request_id):
    if session.get('role') != 'admin':
        return "Unauthorized", 403

    conn, cur = get_db_cursor()

    # 1) Fetch the request + usage + price
    cur.execute("""
      SELECT 
        rh.quantity      AS requested_qty,
        rh.used          AS used_qty,
        rh.remaining     AS remaining_qty,
        rh.product_id    AS prod_id,
        rh.product_name  AS prod_name,
        p.price          AS price_per_item
      FROM request_history rh
      JOIN products p ON p.id = rh.product_id
      WHERE rh.id = %s
    """, (request_id,))
    req = cur.fetchone()

    if not req or req['remaining_qty'] <= 0:
        conn.close()
        flash("Nothing left to return.", "warning")
        return redirect(url_for('dashboard'))

    returned_qty   = req['remaining_qty']
    used_qty       = req['used_qty']
    price_per_item = req['price_per_item']
    prod_id        = req['prod_id']
    prod_name      = req['prod_name']

    # 2) Put returned items back into inventory
    cur.execute("SELECT quantity FROM products WHERE id = %s", (prod_id,))
    old_stock = cur.fetchone()['quantity']
    new_stock = old_stock + returned_qty
    cur.execute(
      "UPDATE products SET quantity = %s WHERE id = %s",
      (new_stock, prod_id)
    )

    # 3) Compute costs only on what was actually used
    billable_qty    = used_qty
    gst_exclusive   = billable_qty * price_per_item
    total_inclusive = round(gst_exclusive * 1.18, 2)

    # 4) Zero out remaining & save costs + comment
    comment = f"Returned {returned_qty} item(s) to stock for request id #{request_id}"
    cur.execute("""
      UPDATE request_history
         SET remaining        = 0,
             return_comment   = %s,
             gst_exclusive    = %s,
             total_inclusive  = %s
       WHERE id = %s
    """, (
      comment,
      gst_exclusive,
      total_inclusive,
      request_id
    ))

    # 5) Log into stock_history
    changed_at = datetime.now(ZoneInfo("Asia/Kolkata"))\
                       .strftime('%Y-%m-%d %H:%M:%S')
    cur.execute("""
      INSERT INTO stock_history
        (product_id, product_name, changed_by,
         old_quantity, new_quantity, change_amount,
         changed_at, remark)
      VALUES (%s,%s,%s,%s,%s,%s,%s,%s)
    """, (
      prod_id,
      prod_name,
      session['username'],
      old_stock,
      new_stock,
      returned_qty,
      changed_at,
      comment
    ))

    conn.commit()
    conn.close()

    flash(
      f"{comment}  GST excl: ₹{gst_exclusive:.2f},  Total incl: ₹{total_inclusive:.2f}",
      "success"
    )
    return redirect(url_for('dashboard'))




@app.route('/remove_from_cart/<int:product_id>', methods=['POST'])
def remove_from_cart(product_id):
    if 'username' not in session or session.get('role') != 'viewer':
        return "Unauthorized", 403

    cart = session.get('cart', [])
    new_cart = [i for i in cart if i['product_id'] != product_id]
    session['cart'] = new_cart
    session.modified = True
    flash("Item removed from cart.", "info")
    return redirect(url_for('view_cart'))

from datetime import datetime
from zoneinfo import ZoneInfo
import time
from werkzeug.utils import secure_filename
from flask import (
    abort, flash, redirect, render_template,
    request, session, url_for
)

ALLOWED_INVOICE_EXT = {'pdf'}

@app.route('/receive_stock', methods=['GET','POST'])
def receive_stock():
    if session.get('role') != 'admin':
        return "Forbidden", 403

    conn, cur = get_db_cursor()

    if request.method == 'POST':
        # ── 1) handle invoice upload ─────────────────────────────
        f = request.files.get('invoice')
        if not f or f.filename == '':
            flash("Please upload an invoice PDF.", "error")
            conn.close()
            return redirect(url_for('receive_stock'))

        ext = f.filename.rsplit('.',1)[-1].lower()
        if ext not in ALLOWED_INVOICE_EXT:
            flash("Only PDF invoices are allowed.", "error")
            conn.close()
            return redirect(url_for('receive_stock'))

        invoice_fn     = secure_filename(f.filename)
        invoice_stored = f"{int(time.time())}_{invoice_fn}"
        invoice_key    = f"invoices/{invoice_stored}"
        r2.upload_fileobj(f, R2_BUCKET, invoice_key)

        # ── 2) compute next purchase_id ─────────────────────────
        cur.execute("SELECT COALESCE(MAX(purchase_id),0) + 1 AS next_batch FROM stock_history")
        next_batch = cur.fetchone()['next_batch']

        # ── 3) loop through each qty_<id> field and pick up quality_<id> too ───
        for field, val in request.form.items():
            if not field.startswith('qty_'):
                continue

            product_id   = int(field.split('_',1)[1])
            try:
                received_qty = int(val)
            except ValueError:
                continue
            if received_qty <= 0:
                continue

            # fetch old quantity
            cur.execute("SELECT name, quantity FROM products WHERE id=%s", (product_id,))
            prod = cur.fetchone()
            if not prod:
                continue

            old_q = prod['quantity']
            new_q = old_q + received_qty

            # 4) update products table
            cur.execute(
                "UPDATE products SET quantity=%s WHERE id=%s",
                (new_q, product_id)
            )

            # 5) get the per-row quality (default to genuine)
            qual = request.form.get(f"quality_{product_id}", "genuine")

            # 6) insert into stock_history with purchase_id & quality
            now_ts = datetime.now(ZoneInfo("Asia/Kolkata"))
            cur.execute("""
              INSERT INTO stock_history
                (product_id,  product_name, changed_by,
                 old_quantity, new_quantity, change_amount,
                 changed_at,   invoice_filename, invoice_path,
                 purchase_id,  quality)
              VALUES (
                %(pid)s, %(name)s, %(user)s,
                %(old)s, %(new)s, %(amt)s,
                %(ts)s,  %(invfn)s, %(invpath)s,
                %(batch)s, %(qual)s
              )
            """, {
                "pid":       product_id,
                "name":      prod['name'],
                "user":      session['username'],
                "old":       old_q,
                "new":       new_q,
                "amt":       received_qty,
                "ts":        now_ts,
                "invfn":     invoice_fn,
                "invpath":   invoice_key,
                "batch":     next_batch,
                "qual":      qual,
            })

        conn.commit()
        conn.close()
        flash(f"✅ Received batch #{next_batch} ({next_batch} items).", "success")
        return redirect(url_for('stock_history'))

    # GET: render the form with existing products
    cur.execute("SELECT id, name, quantity FROM products ORDER BY name")
    products = cur.fetchall()
    conn.close()
    return render_template('receive_stock.html', products=products)


from datetime import date, timedelta
from flask import request

@app.route('/spend_budget', methods=['GET'])
def spend_budget():
    if session.get('role') != 'admin':
        return "Unauthorized", 403

    # read days (default to 30)
    days       = int(request.args.get('days', 30))
    # read date-range overrides
    start_date = request.args.get('start_date')
    end_date   = request.args.get('end_date')
    search     = request.args.get('search','').strip()

    # if someone didn't enter explicit dates, fall back to last N days
    if days > 0 and not (start_date and end_date):
        today      = date.today()
        start_date = (today - timedelta(days=days)).isoformat()
        end_date   = today.isoformat()
    else:
        # you could default to all‐time if days==0
        start_date = start_date or '1900-01-01'
        end_date   = end_date   or date.today().isoformat()

    conn, cur = get_db_cursor()
    cur.execute("""
      SELECT
        p.name                AS product_name,
        COALESCE(SUM(rh.used),     0) AS total_used,
        COALESCE(SUM(rh.quantity), 0) AS total_issued,
        COALESCE(SUM(rh.gst_exclusive),   0) AS gst_spend,
        COALESCE(SUM(rh.total_inclusive), 0) AS total_spend
      FROM products p
      LEFT JOIN request_history rh
        ON rh.product_id = p.id
       AND rh.status = 'approved'
       AND rh.decision_at::date BETWEEN %s AND %s
      WHERE p.name ILIKE %s
      GROUP BY p.name
      ORDER BY p.name;
    """, (start_date, end_date, f"%{search}%"))
    rows = cur.fetchall()
    conn.close()

    total_gst   = sum(r['gst_spend']   for r in rows)
    total_total = sum(r['total_spend'] for r in rows)

    return render_template('spend_budget.html',
                           rows=rows,
                           days=days,
                           start_date=start_date,
                           end_date=end_date,
                           search=search,
                           total_gst=total_gst,
                           total_total=total_total)


from flask import send_file
import pandas as pd
from io import BytesIO

@app.route('/spend_budget/download', methods=['GET'])
def download_spend_budget():
    if session.get('role') != 'admin':
        return "Unauthorized", 403

    days       = int(request.args.get('days', 30))
    start_date = request.args.get('start_date')
    end_date   = request.args.get('end_date')
    search     = request.args.get('search','').strip()

    if days > 0 and not (start_date and end_date):
        today = date.today()
        start_date = (today - timedelta(days=days)).isoformat()
        end_date   = today.isoformat()
    else:
        start_date = start_date or '1900-01-01'
        end_date   = end_date   or date.today().isoformat()

    conn, cur = get_db_cursor()
    cur.execute("""
      SELECT
        p.name                AS product_name,
        COALESCE(SUM(rh.used),     0) AS total_used,
        COALESCE(SUM(rh.quantity), 0) AS total_issued,
        COALESCE(SUM(rh.gst_exclusive),   0) AS gst_spend,
        COALESCE(SUM(rh.total_inclusive), 0) AS total_spend
      FROM products p
      LEFT JOIN request_history rh
        ON rh.product_id = p.id
       AND rh.status = 'approved'
       AND rh.decision_at::date BETWEEN %s AND %s
      WHERE p.name ILIKE %s
      GROUP BY p.name
      ORDER BY p.name;
    """, (start_date, end_date, f"%{search}%"))
    rows = cur.fetchall()
    conn.close()

    # Convert to DataFrame
    df = pd.DataFrame(rows)

    # Create in-memory Excel file
    output = BytesIO()
    with pd.ExcelWriter(output, engine='openpyxl') as writer:
        df.to_excel(writer, index=False, sheet_name='SpendBudget')
    output.seek(0)

    return send_file(output,
                     download_name='spend_budget.xlsx',
                     as_attachment=True,
                     mimetype='application/vnd.openxmlformats-officedocument.spreadsheetml.sheet')


@app.route('/spend/<product>')
def spend_detail(product):
    days     = int(request.args.get('days', 30))
    interval = days > 0 and f"{days} days"

    conn, cur = get_db_cursor()
    if interval:
        cur.execute("""
          SELECT
            DATE(decision_at::timestamp)    AS day,
            SUM(used)                       AS units,
            SUM(total_inclusive)            AS spend
          FROM request_history
          WHERE status = 'approved'
            AND product_name = %s
            AND decision_at::timestamp >= NOW() - INTERVAL %s
          GROUP BY DATE(decision_at::timestamp)
          ORDER BY day
        """, (product, interval))
    else:
        cur.execute("""
          SELECT
            DATE(decision_at::timestamp)    AS day,
            SUM(used)                       AS units,
            SUM(total_inclusive)            AS spend
          FROM request_history
          WHERE status = 'approved'
            AND product_name = %s
          GROUP BY DATE(decision_at::timestamp)
          ORDER BY day
        """, (product,))
    trend = cur.fetchall()
    conn.close()

    return render_template('spend_detail.html',
                           product=product,
                           days=days,
                           trend=trend)


# ─── Job Assign ───────────────────────────────────────────────────────────────

from datetime import date
from flask import (
    abort, flash, redirect, render_template, request, session, url_for
)

ALLOWED_TITLES = {'Planned Maintenance', 'Predective Maintenance', 'Full Overhaul'}

@app.route('/jobs', methods=['GET', 'POST'])
def jobs():
    if 'username' not in session:
        return redirect(url_for('login'))

    conn, cur = get_db_cursor()

    # ── 1) Handle creation (admin only) ─────────────────────────────
    if request.method == 'POST':
        if session.get('role') != 'admin':
            abort(403)

        # pull form
        title        = request.form['title']
        description  = request.form.get('description','').strip()
        assigned_to  = request.form['assigned_to']
        due_date     = request.form.get('due_date') or None
        priority     = request.form['priority']
        reason       = request.form['reason']
        sub_reason   = request.form['sub_reason']
        drone_number = request.form['drone_number']

        if title not in ALLOWED_TITLES:
            flash("⚠️ Invalid job title.", "error")
            conn.close()
            return redirect(url_for('jobs'))

        # insert
        cur.execute("""
          INSERT INTO job_assignment
            (title, description, assigned_to, due_date, priority,
             reason, sub_reason, drone_number)
          VALUES (%s,%s,%s,%s,%s,%s,%s,%s)
          RETURNING id
        """, (
          title, description, assigned_to, due_date, priority,
          reason, sub_reason, drone_number
        ))
        job_id = cur.fetchone()['id']
        conn.commit()

        # email notify
        cur.execute("SELECT email FROM users WHERE username=%s", (assigned_to,))
        u = cur.fetchone()
        if u and u.get('email'):
            msg = Message(
              subject=f"[Inventory] New Job Assigned: {title}",
              recipients=[u['email']]
            )
            msg.body = (
              f"Hi {assigned_to},\n\n"
              f"A new job has been assigned to you:\n"
              f"  • Title: {title}\n"
              f"  • Due:   {due_date or 'No due date'}\n\n"
              f"{description}\n\n"
              "Please log in to mark it completed."
            )
            mail.send(msg)

        flash("✅ Job created and notified.", "success")
        conn.close()
        return redirect(url_for('jobs'))

    # ── 2) GET: filters + listing ────────────────────────────────────
    if session.get('role') == 'admin':
        # pull filter params
        search   = request.args.get('q','').strip()
        status_f = request.args.get('status','All')
        assignee = request.args.get('assigned_to','All')

        filters, params = [], []
        if search:
            filters.append("(title ILIKE %s OR description ILIKE %s)")
            params += [f"%{search}%", f"%{search}%"]
        if status_f != 'All':
            filters.append("status = %s");    params.append(status_f)
        if assignee != 'All':
            filters.append("assigned_to = %s"); params.append(assignee)

        sql = "SELECT * FROM job_assignment"
        if filters:
            sql += " WHERE " + " AND ".join(filters)
        sql += " ORDER BY created_at DESC"
        cur.execute(sql, params)
        jobs = cur.fetchall()

        # viewer dropdown
        cur.execute("SELECT username FROM users WHERE role='viewer' ORDER BY username")
        viewers = [r['username'] for r in cur.fetchall()]

    else:
        # viewer: only theirs + days_remaining
        cur.execute("""
          SELECT * FROM job_assignment
           WHERE assigned_to = %s
           ORDER BY created_at DESC
        """, (session['username'],))
        rows = cur.fetchall()
        today = date.today()
        jobs = []
        for r in rows:
            job = dict(r)
            due = job.get('due_date')
            job['days_remaining'] = (due - today).days if due else None
            jobs.append(job)
        viewers = []
        search = status_f = assignee = None

    conn.close()
    return render_template('jobs.html',
        jobs=jobs,
        viewers=viewers,
        search=search, status_f=status_f, assignee=assignee
    )



@app.route('/jobs/<int:job_id>/complete', methods=['POST'])
def complete_job(job_id):
    if 'username' not in session or session.get('role') != 'viewer':
        return redirect(url_for('login'))

    conn, cur = get_db_cursor()
    # ensure ownership
    cur.execute("SELECT assigned_to FROM job_assignment WHERE id = %s", (job_id,))
    row = cur.fetchone()
    if not row or row['assigned_to'] != session['username']:
        conn.close()
        flash("❌ You can’t complete this job.", "error")
        return redirect(url_for('jobs'))

    # mark done
    cur.execute("UPDATE job_assignment SET status='completed' WHERE id=%s", (job_id,))
    conn.commit()
    conn.close()

    flash("✅ Job marked completed!", "success")
    return redirect(url_for('jobs'))


# # … your other imports …

# import json
# from flask import abort, flash, redirect, render_template, request, session, url_for

# # reuse your existing CHECKLIST
# CHECKLIST = [
#     ("Outside Checks", [
#         "Lights", "Steps/Hand Rails", "Tires/Tracks",
#         "Exhaust", "Fenders", "Bucket", "Cutting Edge/Teeth",
#         "Lifting Mechanism", "Hoses", "Fittings Greased",
#         "Hitch/Coupler", "Wipers",
#     ]),
#     ("Engine Compartment", [
#         "Battery Cable", "Fan Belt", "Hoses",
#         "Air Filter", "Guards",
#     ]),
#     ("Inside Cab", [
#         "Brakes, Service", "Brakes, Parking",
#         "Backup Alarm", "Fire Extinguisher",
#         "Gauges", "Horn", "Hydraulic Controls",
#     ]),
#     ("Fluids", [
#         "Visible Leaks", "Oil Level/Pressure",
#         "Coolant Level", "Hydraulic Oil Level",
#         "Transmission Fluid Level", "Fuel Level",
#     ]),
# ]

# # Top-level fields we want to display before the checklist:
# TOP_FIELDS = [
#     ("Date",                    "date"),
#     ("Inspector",               "inspector"),
#     ("Explanation of Defects",  "defects"),
#     ("Operator Signature",      "operator_signature"),
#     ("Mechanic Signature",      "mechanic_signature"),
# ]

# @app.route('/jobs/<int:job_id>/fill', methods=['GET','POST'])
# def fill_job(job_id):
#     if 'username' not in session:
#         return redirect(url_for('login'))

#     conn, cur = get_db_cursor()
#     cur.execute("SELECT * FROM job_assignment WHERE id=%s", (job_id,))
#     job = cur.fetchone()
#     conn.close()

#     # only assigned user, only once
#     if not job or job['assigned_to'] != session['username']:
#         abort(403)
#     if job['status'] != 'pending':
#         flash("You already submitted this job.", "info")
#         return redirect(url_for('jobs'))

#     # pick the correct form template
#     mapping = {
#       'Planned Maintenance':   'maintenance_form.html',
#       'Predective Maintenance': 'maintenance_form.html',
#       'Inspection':            'inspection_form.html',
#       'Repair':                'repair_form.html',
#       'Full OverAll':          'repair_form.html',
#     }
#     tmpl = mapping.get(job['title'])
#     if not tmpl:
#         abort(400, "Unknown job type")

#     if request.method == 'GET':
#         return render_template(tmpl, job=job, checklist=CHECKLIST)

#     # POST: gather everything
#     data = request.form.to_dict()

#     conn, cur = get_db_cursor()
#     # insert the submission
#     cur.execute("""
#       INSERT INTO job_submissions
#         (job_id, submitted_by, data, submitted_at)
#       VALUES (%s, %s, %s, NOW())
#     """, (
#       job_id,
#       session['username'],
#       json.dumps(data),
#     ))
#     # mark job done
#     cur.execute("UPDATE job_assignment SET status='completed' WHERE id=%s", (job_id,))
#     conn.commit()
#     conn.close()

#     flash("✅ Submission recorded and job marked completed.", "success")
#     return redirect(url_for('jobs'))

# @app.route('/jobs/<int:job_id>/submissions')
# def view_submissions(job_id):
#     if session.get('role') != 'admin':
#         abort(403)

#     conn, cur = get_db_cursor()
#     # fetch the job for title/ID
#     cur.execute("SELECT * FROM job_assignment WHERE id=%s", (job_id,))
#     job = cur.fetchone()

#     # fetch all submissions
#     cur.execute("""
#       SELECT submitted_by, submitted_at, data
#       FROM job_submissions
#       WHERE job_id=%s
#       ORDER BY submitted_at DESC
#     """, (job_id,))
#     subs = cur.fetchall()
#     conn.close()

#     # ensure each data is a dict
#     for s in subs:
#         if isinstance(s['data'], (str, bytes)):
#             s['data'] = json.loads(s['data'])

#     return render_template(
#       'job_submissions.html',
#       job=job,
#       submissions=subs,
#       checklist=CHECKLIST,
#       top_fields=TOP_FIELDS
#     )


from flask_mail import Message

@app.route('/update_stock', methods=['GET', 'POST'])
def update_stock():
    # only admins may adjust
    if session.get('role') != 'admin':
        abort(403)

    conn, cur = get_db_cursor()
    # fetch all products
    cur.execute("SELECT id, name, quantity FROM products ORDER BY id")
    products = cur.fetchall()

    if request.method == 'GET':
        conn.close()
        return render_template('update_stock.html', products=products)

    # POST: apply removal
    remark = request.form.get('remark','').strip()
    if not remark:
        flash("Remark is required.", "error")
        return redirect(url_for('update_stock'))

    any_removed = False
    changes = []  # collect for email
    for p in products:
        field = f"remove_{p['id']}"
        try:
            remove_amt = int(request.form.get(field, 0))
        except ValueError:
            remove_amt = 0

        if remove_amt > 0:
            any_removed = True
            old_qty = p['quantity']
            new_qty = old_qty - remove_amt
            if new_qty < 0:
                flash(f"Cannot remove {remove_amt} from {p['name']} (only {old_qty} in stock).", "error")
                conn.close()
                return redirect(url_for('update_stock'))

            # 1) update products table
            cur.execute(
                "UPDATE products SET quantity=%s WHERE id=%s",
                (new_qty, p['id'])
            )

            # 2) log into stock_history
            now = datetime.now(ZoneInfo("Asia/Kolkata")).strftime('%Y-%m-%d %H:%M:%S')
            cur.execute("""
                INSERT INTO stock_history
                  (product_id, product_name, changed_by,
                   old_quantity, new_quantity, change_amount,
                   changed_at, remark)
                VALUES (%s,%s,%s,%s,%s,%s,%s,%s)
            """, (
                p['id'],
                p['name'],
                session['username'],
                old_qty,
                new_qty,
                -remove_amt,
                now,
                remark
            ))

            changes.append(f"{p['name']}: {old_qty}→{new_qty} ({-remove_amt})")

    if not any_removed:
        flash("No units were removed.", "warning")
        conn.close()
        return redirect(url_for('update_stock'))

    conn.commit()

    # — Send notification email to all active admins —
    cur.execute("SELECT email FROM users WHERE role='admin' AND is_active=TRUE")
    admin_emails = [r['email'] for r in cur.fetchall()]
    conn.close()

    if admin_emails:
        msg = Message(
            subject="⚠️ Stock Adjustment Notification",
            recipients=admin_emails,
        )
        body_lines = [
            f"User {session['username']} removed stock at {now}.",
            "",
            "Changes:",
        ]
        body_lines += [ f"- {c}" for c in changes ]
        body_lines += ["", f"Remark: {remark}"]
        msg.body = "\n".join(body_lines)
        mail.send(msg)

    flash("Stock updated successfully.", "success")
    return redirect(url_for('dashboard'))


import csv
from io import StringIO
from flask import Response

@app.route('/download_current_stock')
def download_current_stock():
    if session.get('role') != 'admin':
        abort(403)

    conn, cur = get_db_cursor()
    cur.execute("SELECT name, quantity FROM products ORDER BY name")
    products = cur.fetchall()
    conn.close()

    # build CSV in-memory
    si = StringIO()
    writer = csv.writer(si)
    # header
    writer.writerow(['Product', 'Current Quantity'])
    # rows
    for p in products:
        writer.writerow([p['name'], p['quantity']])

    output = si.getvalue()
    si.close()

    # send as downloadable attachment
    return Response(
        output,
        mimetype='text/csv',
        headers={
            'Content-Disposition': 'attachment; filename=current_stock.csv'
        }
    )

from werkzeug.security import generate_password_hash

import json
from flask import (
    abort, flash, redirect, render_template, request, session, url_for
)
from werkzeug.security import generate_password_hash, check_password_hash

# … your existing imports & get_db_cursor, etc …

from flask import abort, flash, redirect, render_template, request, session, url_for
from werkzeug.security import generate_password_hash

def get_current_user_id():
    return session.get('user_id')

@app.route('/users', methods=['GET', 'POST'])
def manage_users():
    if session.get('role') != 'admin':
        abort(403)

    # POST = create new user
    if request.method == 'POST':
        username = request.form['username'].strip()
        password = request.form['password']
        role     = request.form['role']
        email    = request.form['email'].strip()

        if not username or not password or role not in ('admin','viewer') or not email:
            flash("Please fill in all fields correctly.", "error")
            return redirect(url_for('manage_users'))

        pw_hash = generate_password_hash(password)
        conn, cur = get_db_cursor()
        try:
            cur.execute("""
                INSERT INTO users (username, password, role, email, is_active)
                VALUES (%s, %s, %s, %s, TRUE)
            """, (username, pw_hash, role, email))
            conn.commit()
            flash(f"User “{username}” created.", "success")
        except Exception as e:
            conn.rollback()
            flash(f"Could not create user: {e}", "error")
        finally:
            conn.close()

        return redirect(url_for('manage_users'))

    # GET = list users
    conn, cur = get_db_cursor()
    cur.execute("""
      SELECT id, username, role, email, is_active
        FROM users
    ORDER BY username
    """)
    users = cur.fetchall()
    conn.close()

    return render_template('manage_users.html', users=users)

@app.route('/users/<int:user_id>/deactivate', methods=['POST'])
def deactivate_user(user_id):
    if session.get('role')!='admin':
        abort(403)
    if user_id == get_current_user_id():
        flash("❌ You cannot disable your own account.", "warning")
        return redirect(url_for('manage_users'))

    conn, cur = get_db_cursor()
    cur.execute("UPDATE users SET is_active=FALSE WHERE id=%s", (user_id,))
    conn.commit(); conn.close()
    flash("User disabled successfully.", "success")
    return redirect(url_for('manage_users'))

@app.route('/users/<int:user_id>/activate', methods=['POST'])
def activate_user(user_id):
    if session.get('role')!='admin':
        abort(403)
    conn, cur = get_db_cursor()
    cur.execute("UPDATE users SET is_active=TRUE WHERE id=%s", (user_id,))
    conn.commit(); conn.close()
    flash("User re-activated successfully.", "success")
    return redirect(url_for('manage_users'))


@app.route('/users/<int:user_id>/edit', methods=['GET', 'POST'])
def edit_user(user_id):
    if session.get('role')!='admin':
        abort(403)

    conn, cur = get_db_cursor()
    cur.execute("SELECT id, username, role, email FROM users WHERE id = %s", (user_id,))
    user = cur.fetchone()
    if not user:
        conn.close()
        abort(404)

    if request.method == 'POST':
        new_email = request.form['email'].strip()
        new_pass  = request.form.get('password','').strip()

        try:
            if new_pass:
                pw_hash = generate_password_hash(new_pass)
                cur.execute("""
                  UPDATE users
                    SET email = %s,
                        password = %s
                  WHERE id = %s
                """, (new_email, pw_hash, user_id))
            else:
                cur.execute("""
                  UPDATE users
                    SET email = %s
                  WHERE id = %s
                """, (new_email, user_id))

            conn.commit()
            flash(f"Updated “{user['username']}”.", "success")
        except Exception as e:
            conn.rollback()
            flash(f"Could not update user: {e}", "error")

        conn.close()
        return redirect(url_for('manage_users'))

    conn.close()
    return render_template('edit_user.html', user=user)


@app.route('/admin/users/<int:user_id>/change_password', methods=['GET','POST'])
def change_password(user_id):
    if session.get('role') != 'admin':
        abort(403)

    conn, cur = get_db_cursor()
    cur.execute("SELECT id, username, role, email FROM users WHERE id=%s", (user_id,))
    user = cur.fetchone()
    if not user:
        conn.close()
        abort(404)

    if request.method == 'POST':
        new_pw = request.form.get('new_password','').strip()
        confirm = request.form.get('confirm_password','').strip()
        if not new_pw:
            flash("Password cannot be blank.", "error")
        elif new_pw != confirm:
            flash("Passwords do not match.", "error")
        else:
            hashed = generate_password_hash(new_pw)
            cur.execute("UPDATE users SET password=%s WHERE id=%s",
                        (hashed, user_id))
            conn.commit()
            conn.close()
            flash(f"Password for {user['username']} updated.", "success")
            return redirect(url_for('manage_users'))

    conn.close()
    return render_template('change_password.html', user=user)


from datetime import date, timedelta
from flask import abort, flash, redirect, render_template, request, session, url_for


@app.route('/users/<username>/locations')
@login_required
def view_user_locations(username):
    if session.get('role') != 'admin':
        abort(403)

    # 1) determine which date to show
    today = date.today()
    # allow ?date=YYYY-MM-DD; if missing or invalid, default to today
    ds = request.args.get('date')
    try:
        selected = date.fromisoformat(ds) if ds else today
    except ValueError:
        return redirect(url_for('view_user_locations', username=username))

    # restrict to only the last 10 days
    if not (today - timedelta(days=29) <= selected <= today):
        return redirect(url_for('view_user_locations', username=username))

    # 2) pull only that day’s points
    conn, cur = get_db_cursor()
    cur.execute("""
      SELECT latitude, longitude, logged_at
        FROM user_locations
       WHERE username = %s
         AND DATE(logged_at) = %s
       ORDER BY logged_at DESC
    """, (username, selected))
    points = cur.fetchall()
    conn.close()

    # 3) compute date‐picker bounds
    mind = (today - timedelta(days=29)).isoformat()
    maxd = today.isoformat()

    return render_template(
      'user_locations.html',
      username=username,
      points=points,
      selected_date=selected.isoformat(),
      min_date=mind,
      max_date=maxd
    )

from flask import request, jsonify

@app.route('/api/location', methods=['POST'])
@login_required
def save_location():
    # NOTE: make sure your user_locations table has columns:
    #   username (text), latitude (float), longitude (float), logged_at (timestamp default now())
    data = request.get_json()
    lat = data.get('latitude')
    lon = data.get('longitude')
    if lat is None or lon is None:
        return jsonify({"error":"bad payload"}), 400

    conn, cur = get_db_cursor()
    cur.execute("""
      INSERT INTO user_locations(username, latitude, longitude, logged_at)
      VALUES (%s,%s,%s,NOW())
    """, (session['username'], lat, lon))
    conn.commit()
    conn.close()
    return jsonify({"status":"ok"}), 201

def mark_attendance(user_id):
    """Record today’s attendance for this user (once only)."""
    conn, cur = get_db_cursor()
    today = date.today()
    cur.execute("""
      INSERT INTO user_attendance(user_id, att_date)
      VALUES (%s, %s)
      ON CONFLICT (user_id, att_date) DO NOTHING
    """, (user_id, today))
    conn.commit()
    conn.close()


from datetime import date, timedelta, datetime
from collections import defaultdict
from flask import (
    abort, render_template, request, session, url_for, redirect
)

from datetime import date, datetime, timedelta
from collections import defaultdict
from flask import (
    request, abort, render_template, session
)

from datetime import date, datetime, timedelta
from collections import defaultdict
from flask import (
    request, abort, render_template, session,
    url_for
)

# at the top of your file, so you can see the logs in the console
import logging
from datetime import date, datetime, timedelta
from collections import defaultdict
from flask import request, abort, render_template, session

# wherever your R2 helper is:
# from yourapp.storage import s3_signed_url  

from datetime import date, datetime, timedelta
from collections import defaultdict
from flask import request, abort, render_template, session
import logging

from collections import defaultdict
from datetime import date, datetime, timedelta
from flask import request, abort, render_template, session, url_for, redirect

@app.route('/attendance_summary')
@login_required
def attendance_summary():
    if session.get('role') != 'admin':
        abort(403)

    today        = date.today()
    one_year_ago = today - timedelta(days=365)
    default_to   = today
    default_from = today - timedelta(days=6)

    def parse_or_default(key, default):
        s = request.args.get(key, '')
        try:
            return datetime.strptime(s, "%Y-%m-%d").date()
        except:
            return default

    start = parse_or_default('start', default_from)
    end   = parse_or_default('end',   default_to)
    # clamp into [one_year_ago … today]
    start = max(start, one_year_ago)
    end   = min(end,   today)
    if start > end:
        start, end = end, start

    dates = [ start + timedelta(days=i) for i in range((end - start).days + 1) ]

    conn, cur = get_db_cursor()
    # fetch users
    cur.execute("SELECT id, username FROM users ORDER BY username")
    users = cur.fetchall()

    # fetch attendance
    cur.execute("""
      SELECT user_id, att_date
        FROM user_attendance
       WHERE att_date BETWEEN %s AND %s
    """, (start, end))
    attendance_rows = cur.fetchall()

    # fetch snapshots
    cur.execute("""
      SELECT user_id,
             DATE(captured_at) AS att_date,
             snapshot_key
        FROM user_login_snapshots
       WHERE DATE(captured_at) BETWEEN %s AND %s
    """, (start, end))
    snap_rows = cur.fetchall()
    conn.close()

    # build maps
    attendance_map = defaultdict(set)
    for r in attendance_rows:
        attendance_map[r['user_id']].add(r['att_date'])

    # *store the raw key* here
    snapshot_map = defaultdict(dict)
    for r in snap_rows:
        snapshot_map[r['user_id']][r['att_date']] = r['snapshot_key']

    return render_template('attendance_summary.html',
      users          = users,
      dates          = dates,
      attendance_map = attendance_map,
      snapshot_map   = snapshot_map,
      start_date     = start.isoformat(),
      end_date       = end.isoformat(),
      min_date       = one_year_ago.isoformat(),
      max_date       = today.isoformat(),
    )



from datetime import timedelta

@app.route('/attendance/<username>')
@login_required
def attendance_detail(username):
    # only admin OR the user themself
    if not (session['role']=='admin' or session['username']==username):
        abort(403)

    # look up user_id
    conn, cur = get_db_cursor()
    cur.execute("SELECT id FROM users WHERE username=%s", (username,))
    u = cur.fetchone() or abort(404)
    user_id = u['id']

    # fetch all attendance dates in last 365 days
    today = date.today()
    start = today - timedelta(days=364)
    cur.execute("""
      SELECT att_date
        FROM user_attendance
       WHERE user_id=%s
         AND att_date BETWEEN %s AND %s
    """, (user_id, start, today))
    present = { r['att_date'] for r in cur.fetchall() }
    conn.close()

    # build a list of { date, present? } for each of the 365 days
    days = []
    for i in range(365):
        d = start + timedelta(days=i)
        days.append({
          'date': d,
          'present': (d in present)
        })

    return render_template('attendance_detail.html',
                           username=username,
                           days=days)



if __name__ == '__main__':
    # Render (and other PaaS) will set the PORT env var
    port = int(os.environ.get('PORT', 5000))
    app.run(host='0.0.0.0', port=port, debug=True)