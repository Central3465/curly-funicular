from flask import Blueprint

auth_bp = Blueprint('auth', __name__)
admin_bp = Blueprint('admin', __name__)
cipher_bp = Blueprint('cipher', __name__)
conversion_bp = Blueprint('conversion', __name__)
account_bp = Blueprint('account', __name__)
csrf_bp = Blueprint('csrf', __name__)
usage_bp = Blueprint('usage', __name__)

from api.auth import *  # noqa
from api.admin import *  # noqa
from api.cipher import *  # noqa
from api.conversion import *  # noqa
from api.account import *  # noqa
from api.csrf import *  # noqa
from api.usage import *  # noqa
