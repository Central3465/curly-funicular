# Cipher Encoder & Decoder

A Flask-based web application for encoding and decoding messages using custom substitution ciphers with decoy characters.

## Features

- 🔐 **Custom Cipher Generation**: Create random substitution ciphers or use your own
- 🔑 **Secret Key Protection**: Messages are protected with a secret key that determines decoy placement
- 📝 **Encode Messages**: Encrypt plain text using your cipher and key
- 🔍 **Decode Messages**: Decrypt encoded messages with the correct cipher and key
- 🎨 **Modern UI**: Clean, responsive interface with smooth animations
- 📋 **Copy to Clipboard**: Easily copy generated ciphers and messages

## How It Works

This application uses a substitution cipher where each letter of the alphabet is mapped to a different letter. Additionally, it employs a decoy system based on SHA-256 hashing of the secret key to add extra characters at pseudo-random positions, making the encrypted message harder to crack without the key.

### Encoding Process
1. Each letter in the message is substituted according to the cipher
2. Based on the secret key and position, decoy letters may be inserted
3. The result is an encrypted message with hidden decoys

### Decoding Process
1. The decoder uses the same key to determine which characters are decoys
2. Decoy characters are skipped
3. Remaining characters are mapped back using the inverse cipher

## Installation

### Prerequisites
- Python 3.8 or higher
- pip (Python package manager)

### Setup

1. Clone the repository:
```bash
git clone <repository-url>
cd curly-funicular
```

2. Install dependencies:
```bash
pip install flask
```

3. Run the application:
```bash
python app.py
```

4. Open your browser and navigate to:
```
http://localhost:5000
```

## Usage

### Encoding a Message

1. Select the **Encoder** tab
2. Enter a secret key (remember this for decoding!)
3. Either generate a random cipher or enter your own (26 unique letters)
4. Click "Start Encoding"
5. Enter your message and click "Encode Message"
6. Copy the encrypted result

### Decoding a Message

1. Select the **Decoder** tab
2. Enter the same cipher used for encoding
3. Enter the same secret key used for encoding
4. Click "Set Up Decoder"
5. Paste the encrypted message and click "Decode Message"
6. View the decoded result

## API Endpoints

The application provides the following REST API endpoints:

### POST `/api/generate-cipher`
Generate a random cipher.

**Response:**
```json
{
    "cipher": ["b", "c", "a", ...],
    "success": true
}
```

### POST `/api/validate-cipher`
Validate a cipher format.

**Request:**
```json
{
    "cipher": "['b', 'c', 'a', ...]"
}
```

**Response:**
```json
{
    "valid": true,
    "cipher": ["b", "c", "a", ...]
}
```

### POST `/api/encode`
Encode a message.

**Request:**
```json
{
    "cipher": ["b", "c", "a", ...],
    "message": "Hello World",
    "key": "mysecretkey"
}
```

**Response:**
```json
{
    "encrypted": "Xmqqo Wprqf"
}
```

### POST `/api/decode`
Decode a message.

**Request:**
```json
{
    "cipher": ["b", "c", "a", ...],
    "message": "Xmqqo Wprqf",
    "key": "mysecretkey"
}
```

**Response:**
```json
{
    "decoded": "Hello World"
}
```

## Project Structure

```
curly-funicular/
├── app.py                 # Flask application and API routes
├── cipher/
│   ├── __init__.py        # Package exports
│   ├── decoder.py         # Decoding logic and cipher validation
│   └── encoder.py         # Encoding logic and cipher generation
├── static/
│   └── style.css          # Stylesheet
├── templates/
│   └── index.html         # Main HTML template with JavaScript
├── README.md              # This file
└── LICENSE                # MIT License
```

## Security Notes

- The secret key is never stored on the server
- All encryption/decryption happens server-side per request
- Use HTTPS in production to protect data in transit
- The cipher and key must both be kept secret for security

## Performance Optimizations

This application includes several performance optimizations:

- **Lookup Tables**: Uses dictionaries for O(1) character mapping instead of O(n) list searches
- **Cached Hash Computations**: Minimizes redundant SHA-256 hash calculations
- **Efficient String Building**: Uses list comprehension and join for string concatenation

## License

This project is licensed under the GNU General Public License
v3.0 (GPL-3.0).

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

## Acknowledgments

- Built with [Flask](https://flask.palletsprojects.com/)
- Frontend uses vanilla JavaScript and CSS
