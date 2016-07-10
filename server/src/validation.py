from flask import jsonify, make_response
from jsonschema import validate, ValidationError
from models import db_session

# Keep all error responses in one place to maintain consistency across endpoints

error_codes = {
    "bad_credentials": 401,
    "not_admin": 401,
    "insufficient_permissions": 401,
    "input_validation_fail": 400,
    "no_request_data": 400,
    "already_exists": 409,
    "item_not_found": 404,
    "corrupt_account": 500,
}

def error_response(error, message=""):
    db_session.rollback()
    return make_response(jsonify(error=error, message=message),
        error_codes[error])

def validate_schema(data, schema):
    if not data:
        return error_response("no_request_data")
    try:
        validate(data, schema)
    except ValidationError as e:
        return error_response("input_validation_fail", message=str(e))

    return None
