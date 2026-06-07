from flask import Blueprint, request, jsonify, current_app
import bcrypt

auth_bp = Blueprint("auth", __name__)


# @auth_bp.route("/logowanie", methods=["POST"])
# def login():
#     db = current_app.mongo.db
#
#     data = request.json
#
#     user = db.users.find_one({
#         "login": data["login"]
#     })
#
#     if not user:
#         return jsonify({
#             "message": "Invalid credentials"
#         }), 401
#
#     valid = bcrypt.checkpw(
#         data["password"].encode("utf-8"),
#         user["password"].encode("utf-8")
#     )
#
#     if not valid:
#         return jsonify({
#             "message": "Invalid credentials"
#         }), 401
#
#     return jsonify({
#         "message": "Login success",
#         "role": user["role"],
#         "userId": str(user["_id"])
#     })
