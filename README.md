# Cipher Encoder & Decoder

> [!WARNING]
> Running your own "instance" is **not recommended or supported**.
>
> Of course, there is a `README.md` file; however, not everything is documented. **Support will not be provided if you run into any issues.**

## What's this?

A Flask-based web application for encoding and decoding text using various cipher algorithms. It features user accounts, a REST API, and security protections including CSRF protection and rate limiting.

The structure is organized as follows:

module   | concern
---------|------------------
api      | REST API endpoints for cipher operations
cipher   | cipher algorithm implementations
app.py   | main Flask application and route handlers
utils.py | utility functions
templates| Jinja2 HTML templates
static   | CSS, JavaScript, and other static assets
tests    | test suite

I try to document things for "future me", but invariably this documentation will be incomplete and out of date in parts.

## Requirements

These need to be available:

- Python 3.8 or higher
- pip (Python package manager)
- MongoDB for user data storage
- Redis 6.2+ for rate limiting and security tracking

## Installation

1. Clone the repository:
```bash
git clone <repository-url>
cd curly-funicular
```

2. Create a virtual environment:
```bash
python -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate
```

3. Install dependencies:
```bash
pip install -r requirements.txt
```

4. Set up environment variables:
```bash
cp .env.example .env
# Edit .env with your MongoDB and Redis URLs
```

5. Start the application:
```bash
python app.py
```

The application will be available at `http://localhost:5000`.

## Environment Variables

- `SECRET_KEY` - Flask secret key for session management
- `DATABASE_URL` - MongoDB connection string (e.g., `mongodb://localhost:27017/`)
- `REDIS_URL` - Redis connection string (e.g., `redis://localhost:6379`)

## Running Tests

```bash
pytest tests/
```

## Security

This project includes security features documented in [SECURITY.md](SECURITY.md).

## License

See [LICENSE](LICENSE) file for details.
