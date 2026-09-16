# Security Policy

## Supported Versions

We recommend always using the latest version of this project to ensure you have all security updates and bug fixes.

| Version | Supported          |
| ------- | ------------------ |
| Latest  | :white_check_mark: |
| Others  | :x:                |

## Security Considerations

This project implements a custom cipher encoding/decoding system. Please be aware of the following security considerations:

### Important Security Notes

1. **Not Cryptographically Secure**: This cipher is designed for educational and recreational purposes. It should **NOT** be used for protecting sensitive or confidential information. For serious encryption needs, use established cryptographic libraries.

2. **Secret Key Protection**: 
   - The secret key is never stored on the server
   - All encryption/decryption happens server-side per request
   - Users are responsible for keeping their keys secure
   - If your key is compromised, messages can be decoded

3. **Cipher Security**: 
   - Both the cipher and key must be kept secret for security
   - Use a unique cipher for each communication partner
   - Change ciphers periodically

4. **Production Deployment**:
   - Always use HTTPS in production to protect data in transit
   - Consider implementing rate limiting to prevent abuse
   - Deploy behind a reverse proxy with proper security headers
   - Keep Flask and dependencies up to date

## Reporting a Vulnerability

We take security vulnerabilities seriously. If you discover a security issue, please follow these steps:

### How to Report

1. **DO NOT** disclose the vulnerability publicly until it has been addressed
2. Send an email to the project maintainer or open a private security advisory on GitHub
3. Include as much detail as possible:
   - Description of the vulnerability
   - Steps to reproduce the issue
   - Potential impact
   - Suggested fix (if you have one)
   - Your contact information for follow-up

### What to Expect

- **Initial Response**: We will acknowledge receipt of your report within 48 hours
- **Investigation**: We will investigate the issue and determine its severity
- **Resolution Timeline**: Depending on complexity, we aim to resolve critical issues within 7 days
- **Updates**: We will keep you informed of our progress
- **Disclosure**: Once fixed, we may coordinate a public disclosure with credit (if you wish)

### Security Advisory Process

1. Reporter submits vulnerability details privately
2. Maintainer acknowledges and investigates
3. Fix is developed and tested
4. Patch is released
5. Public disclosure (coordinated with reporter if desired)

## Security Best Practices for Contributors

When contributing to this project, please follow these security guidelines:

- Never commit secrets, API keys, or credentials
- Validate all user inputs on both client and server side
- Follow secure coding practices (OWASP guidelines)
- Keep dependencies updated and monitor for known vulnerabilities
- Review code for potential security issues before submitting PRs

## AI-Generated Code Security

As part of our AI disclosure policy, contributors must:

- Verify and test all AI-generated code for security vulnerabilities
- Not rely solely on AI suggestions for security-critical code
- Ensure AI-assisted contributions follow security best practices
- Disclose AI assistance so reviewers can perform additional scrutiny

## Contact

For security-related inquiries, please use GitHub's private vulnerability reporting feature or contact the maintainers directly through the repository.

---

**Disclaimer**: This software is provided "as is" without warranty of any kind. The authors are not responsible for any damages or losses resulting from the use of this software. For production environments handling sensitive data, consult with security professionals and use industry-standard encryption solutions.
