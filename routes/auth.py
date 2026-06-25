from flask import Blueprint, request, session, jsonify, send_from_directory, redirect

auth_bp = Blueprint("auth", __name__)

PASSWORD = "@NetPulseAdmin"


@auth_bp.route("/auth/login", methods=["GET"])
def login_page():
    if session.get("authenticated"):
        return redirect("/")

    return send_from_directory("static", "login.html")


@auth_bp.route("/auth/login", methods=["POST"])
def login():
    data = request.get_json()
    password = data.get("password")

    if password == PASSWORD:
        session["authenticated"] = True
        return jsonify({"ok": True})

    return jsonify({"ok": False}), 401


# @auth_bp.route("/auth/logout", methods=["GET"])
# def logout():
#     session.clear()
#     return jsonify({"ok": True, "message": "logged out"})


@auth_bp.route("/auth/logout", methods=["POST"])
def logout():
    session.clear()
    response = jsonify({"ok": True})
    response.delete_cookie("session")
    return response


@auth_bp.route("/auth/whoami")
def whoami():
    return jsonify({
        "authenticated": session.get("authenticated", False)
    })
