# 🗺️ Roadmap

This document outlines the planned features and improvements for the next update of **curly-funicular**.

> **Status:** 🚧 In development
> **Target:** Next update

---

## 📋 Planned Features

### ✉️ Email Verification

Add email verification functionality to improve account security and ensure that users have access to the email addresses associated with their accounts.

* [ ] Add email verification when creating an account
* [ ] Generate secure, time-limited verification links
* [ ] Add a verification status to user accounts
* [ ] Prevent or restrict certain account functionality until verification is complete
* [ ] Add the ability to resend verification emails
* [ ] Handle expired and invalid verification links

---

### 👤 Account User Editing Features

Introduce account-management functionality allowing users to manage and update their account information.

* [ ] Add an account settings page
* [ ] Allow users to update their account information
* [ ] Allow users to change their email address
* [ ] Add password-change functionality
* [ ] Require appropriate authentication for sensitive account changes
* [ ] Improve account-management error handling
* [ ] Add confirmation prompts for potentially destructive actions

---

### 💬 Live Private Chat Interface

Introduce a private, real-time chat interface for authenticated users.

* [ ] Design the private chat interface
* [ ] Implement private one-to-one conversations
* [ ] Add real-time message delivery
* [ ] Add message timestamps
* [ ] Display chat participants clearly
* [ ] Add message history
* [ ] Ensure private conversations cannot be accessed by unauthorised users
* [ ] Handle connection and delivery failures gracefully

---

### 🎨 UI Overhaul

Refresh the application's user interface to provide a cleaner and more consistent experience.

* [ ] Redesign the main application interface
* [ ] Improve navigation
* [ ] Improve account settings and user-management pages
* [ ] Improve chat interface styling
* [ ] Standardise buttons, forms, spacing, and typography
* [ ] Improve responsive behaviour
* [ ] Improve accessibility
* [ ] Remove outdated or inconsistent UI elements

---

### 🔐 Security Improvements

Strengthen the application's security across authentication, accounts, messaging, and cipher functionality.

* [ ] Review authentication and session handling
* [ ] Improve password security
* [ ] Strengthen account-access controls
* [ ] Review input validation and sanitisation
* [ ] Protect sensitive endpoints against unauthorised access
* [ ] Review CSRF protection
* [ ] Improve rate limiting where appropriate
* [ ] Review security-related error handling
* [ ] Audit dependencies for known vulnerabilities
* [ ] Review private-chat authorisation and data handling

---

## 🔮 Future Considerations

The following features are not currently part of the next update but may be considered for future releases.

* Improved user profiles
* Additional account-management options
* Further messaging features
* Additional cipher functionality
* Performance improvements
* More comprehensive automated testing
* Additional accessibility improvements

---

## 📌 Notes

The roadmap is subject to change as development progresses. Features may be modified, postponed, or removed depending on technical requirements and project priorities.

Contributions, suggestions, and bug reports are welcome through the repository's issue tracker and pull requests.

---

**curly-funicular** — A Flask-based web application for encoding and decoding messages using custom substitution ciphers with decoy characters.
