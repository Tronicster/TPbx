#!/usr/bin/env python3

import os
import signal
import subprocess
import tempfile
import time

from flask import (
    Flask,
    request,
    render_template_string,
    send_file,
)

APP_DIR = "/opt/my-pbx"
APP_FILE = os.path.join(APP_DIR, "app.py")

PORT = 8081

app = Flask(__name__)


# ============================================================
# HTML
# ============================================================

HTML = """
<!DOCTYPE html>
<html>

<head>

    <title>PBX Web Interface Updater</title>

    <meta name="viewport" content="width=device-width, initial-scale=1">

    <style>

        * {
            box-sizing: border-box;
        }

        body {
            background: #0f172a;
            color: #e5e7eb;
            font-family:
                system-ui,
                -apple-system,
                BlinkMacSystemFont,
                "Segoe UI",
                sans-serif;

            margin: 0;
            padding: 40px;
        }

        .box {
            max-width: 750px;
            margin: auto;

            background: #182235;

            border: 1px solid #334155;

            border-radius: 12px;

            padding: 30px;
        }

        h1 {
            margin-top: 0;
            margin-bottom: 8px;
        }

        .subtitle {
            color: #94a3b8;
            margin-bottom: 25px;
        }

        .info {
            background: #0f172a;

            border: 1px solid #293548;

            padding: 16px;

            border-radius: 8px;

            margin: 20px 0;
        }

        .info div {
            margin-bottom: 8px;
        }

        .info div:last-child {
            margin-bottom: 0;
        }

        code {
            background: #020617;

            padding: 3px 6px;

            border-radius: 4px;

            color: #e2e8f0;
        }

        input[type=file] {
            width: 100%;

            padding: 12px;

            margin: 15px 0;

            background: #0f172a;

            color: white;

            border: 1px solid #374151;

            border-radius: 7px;
        }

        button,
        .button {
            display: inline-block;

            background: #2563eb;

            color: white;

            border: 0;

            border-radius: 7px;

            padding: 12px 18px;

            cursor: pointer;

            font-size: 15px;

            text-decoration: none;
        }

        button:hover,
        .button:hover {
            background: #1d4ed8;
        }

        .download {
            background: #334155;
        }

        .download:hover {
            background: #475569;
        }

        .success {
            color: #34d399;

            background: #052e1b;

            border: 1px solid #166534;

            padding: 15px;

            border-radius: 8px;
        }

        .error {
            color: #f87171;

            background: #3f1010;

            border: 1px solid #991b1b;

            padding: 15px;

            border-radius: 8px;
        }

        hr {
            border: 0;

            border-top: 1px solid #334155;

            margin: 30px 0;
        }

        pre {
            white-space: pre-wrap;

            overflow-x: auto;
        }

        .warning {
            color: #fbbf24;

            margin-top: 25px;

            font-size: 13px;
        }

    </style>

</head>


<body>

<div class="box">

    <h1>PBX Web Interface Updater</h1>

    <div class="subtitle">
        Manage the running Asterisk web interface
    </div>


    <div class="info">

        <div>
            Current file:
            <code>{{ app_file }}</code>
        </div>

        <div>
            Updater port:
            <code>8081</code>
        </div>

        <div>
            Web interface:
            <code>8080</code>
        </div>

    </div>


    {% if message %}

        <div class="{{ 'success' if success else 'error' }}">

            {{ message|safe }}

        </div>

    {% endif %}


    <h2>Upload New Version</h2>

    <p>
        Upload a new <code>app.py</code>.
        The updater will check the Python syntax before replacing
        the currently installed version.
    </p>


    <form
        method="post"
        enctype="multipart/form-data"
    >

        <input
            type="file"
            name="file"
            accept=".py"
            required
        >

        <br>

        <button type="submit">
            Update PBX Web Interface
        </button>

    </form>


    <hr>


    <h2>Current Version</h2>

    <p>
        Download the currently installed <code>app.py</code>
        before making changes.
    </p>


    <a
        class="button download"
        href="/download"
    >
        Download Current app.py
    </a>


    <hr>


    <h2>Backup</h2>

    <p>
        The previous version is saved as:
    </p>

    <code>
        /opt/my-pbx/app.py.backup
    </code>


    <div class="warning">

        ⚠ Keep port 8081 restricted to your trusted network.
        This page can replace and execute the PBX web application.

    </div>

</div>

</body>

</html>
"""


# ============================================================
# FIND RUNNING APP
# ============================================================

def find_app_processes():

    result = subprocess.run(
        [
            "pgrep",
            "-af",
            f"python.*{APP_FILE}"
        ],

        capture_output=True,

        text=True
    )

    pids = []

    for line in result.stdout.splitlines():

        parts = line.split(None, 1)

        if not parts:
            continue

        try:
            pid = int(parts[0])

        except ValueError:
            continue

        # Never kill this updater.
        if pid == os.getpid():
            continue

        pids.append(pid)

    return pids


# ============================================================
# STOP APP
# ============================================================

def stop_app():

    pids = find_app_processes()

    print("app.py processes:", pids)

    if not pids:
        print("No running app.py process found.")

        return


    # First try a normal shutdown.

    for pid in pids:

        try:

            print(
                "Stopping app.py PID:",
                pid
            )

            os.kill(
                pid,
                signal.SIGTERM
            )

        except ProcessLookupError:

            pass


    # Give Flask time to shut down.

    time.sleep(2)


    # Kill anything still running.

    for pid in pids:

        try:

            os.kill(
                pid,
                0
            )

            print(
                "Force stopping PID:",
                pid
            )

            os.kill(
                pid,
                signal.SIGKILL
            )

        except ProcessLookupError:

            pass


# ============================================================
# START APP
# ============================================================

def start_app():

    log_file = os.path.join(
        APP_DIR,
        "app.log"
    )

    print(
        "Starting:",
        APP_FILE
    )

    log = open(
        log_file,
        "a"
    )

    subprocess.Popen(
        [
            "python3",
            APP_FILE
        ],

        cwd=APP_DIR,

        stdin=subprocess.DEVNULL,

        stdout=log,

        stderr=subprocess.STDOUT,

        start_new_session=True
    )


# ============================================================
# DOWNLOAD CURRENT APP
# ============================================================

@app.route("/download")
def download_current_app():

    if not os.path.isfile(APP_FILE):

        return (
            "app.py not found.",
            404
        )

    return send_file(

        APP_FILE,

        as_attachment=True,

        download_name="app.py",

        mimetype="text/x-python"
    )


# ============================================================
# UPDATE PAGE
# ============================================================

@app.route(
    "/",
    methods=["GET", "POST"]
)
def update():

    message = None

    success = False


    if request.method == "POST":

        uploaded = request.files.get(
            "file"
        )


        # ----------------------------------------------------
        # Check upload
        # ----------------------------------------------------

        if (
            not uploaded
            or not uploaded.filename
        ):

            message = (
                "No file was uploaded."
            )

            return render_template_string(

                HTML,

                app_file=APP_FILE,

                message=message,

                success=False
            )


        # Only accept app.py.

        if uploaded.filename.lower() != "app.py":

            message = (
                "Please upload a file named "
                "<code>app.py</code>."
            )

            return render_template_string(

                HTML,

                app_file=APP_FILE,

                message=message,

                success=False
            )


        # ----------------------------------------------------
        # Temporary file
        # ----------------------------------------------------

        fd, temp_path = tempfile.mkstemp(

            prefix="app_update_",

            suffix=".py",

            dir=APP_DIR
        )


        try:

            # Save upload.

            with os.fdopen(
                fd,
                "wb"
            ) as temp:

                uploaded.save(temp)


            # ------------------------------------------------
            # Check Python syntax
            # ------------------------------------------------

            print(
                "Checking uploaded app.py..."
            )

            check = subprocess.run(

                [
                    "python3",
                    "-m",
                    "py_compile",
                    temp_path
                ],

                capture_output=True,

                text=True
            )


            if check.returncode != 0:

                os.unlink(
                    temp_path
                )

                message = (

                    "Update rejected because "
                    "the uploaded Python file has "
                    "a syntax error:"
                    "<br><br>"
                    "<pre>"
                    + check.stderr
                    + "</pre>"
                )

                return render_template_string(

                    HTML,

                    app_file=APP_FILE,

                    message=message,

                    success=False
                )


            # ------------------------------------------------
            # Stop existing app
            # ------------------------------------------------

            stop_app()


            # ------------------------------------------------
            # Backup current app
            # ------------------------------------------------

            backup_file = (
                APP_FILE
                + ".backup"
            )


            if os.path.exists(APP_FILE):

                print(
                    "Creating backup:",
                    backup_file
                )


                if os.path.exists(
                    backup_file
                ):

                    os.remove(
                        backup_file
                    )


                os.replace(

                    APP_FILE,

                    backup_file
                )


            # ------------------------------------------------
            # Install new app
            # ------------------------------------------------

            print(
                "Installing new app.py..."
            )

            os.replace(

                temp_path,

                APP_FILE
            )


            os.chmod(

                APP_FILE,

                0o755
            )


            # ------------------------------------------------
            # Start new app
            # ------------------------------------------------

            start_app()


            success = True


            message = (

                "PBX web interface updated "
                "successfully!"
                "<br><br>"
                "The new <code>app.py</code> "
                "has been started."
                "<br><br>"
                "The previous version is available "
                "as <code>app.py.backup</code>."
            )


        except Exception as exc:

            print(
                "UPDATE ERROR:",
                exc
            )


            if os.path.exists(
                temp_path
            ):

                os.unlink(
                    temp_path
                )


            message = (

                "Update failed:"
                "<br><br>"
                "<pre>"
                + str(exc)
                + "</pre>"
            )


        return render_template_string(

            HTML,

            app_file=APP_FILE,

            message=message,

            success=success
        )


    # --------------------------------------------------------
    # Normal GET
    # --------------------------------------------------------

    return render_template_string(

        HTML,

        app_file=APP_FILE,

        message=message,

        success=success
    )


# ============================================================
# START
# ============================================================

if __name__ == "__main__":

    print()
    print(
        "======================================"
    )

    print(
        " PBX WEB INTERFACE UPDATER"
    )

    print(
        "======================================"
    )

    print(
        "App:",
        APP_FILE
    )

    print(
        "Listening on: 0.0.0.0:8081"
    )

    print(
        "======================================"
    )

    print()


    app.run(

        host="0.0.0.0",

        port=PORT,

        debug=False,

        use_reloader=False
    )
