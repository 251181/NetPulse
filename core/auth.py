from flask import request, session, jsonify, redirect

PROTECTED = ("/devices", "/metrics", "/logs", "/events")

def auth_guard():
    path = request.path

    if path.startswith("/auth"):
        return

    if path == "/":
        if not session.get("authenticated", False):
            return redirect("/auth/login")
        return

    if path.startswith(PROTECTED):
        if not session.get("authenticated", False):
            return jsonify({"error": "unauthorized"}), 401