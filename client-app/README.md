## OAuth 2.0 Client Application

A Node.js web application that demonstrates the Authorization Code Flow with PKCE (Proof Key for Code Exchange). This app handles user redirection, token exchange, and authenticated API consumption.

### Overview

The Client App is the user-facing portion of the architecture. It never sees the user's password; instead, it securely requests permission to access the user's data on the Resource Server by obtaining a **JWT Access Token**.

### Key Features

    -   PKCE Implementation: Generates a `code_verifier` and `code_challenge` to secure the exchange process against interception.

    -   State Management: Uses a `state` parameter and cookies to prevent Cross-site Request Forgery (CSRF) attacks.

    -   Token Lifecycle Management:

        - Exchange: Swaps an authorization code for access/refresh tokens.
        - Storage: Securely stores tokens in `httpOnly` cookies (preventing XSS access).
        - Refresh: Uses the Refresh Token to get new Access Tokens without interrupting the user.

    -   Authenticating Requests: Communicates with the Resource Server using the `Authorization: Bearer` header.

### The PKCE Flow in Action

When a user clicks "login", the following sequence occurs:

    1. Preparation: The client generates a random string (`verifier`) and hashes it (`challenge`).

    2. Redirection: The user is sent to the Auth Server with the `challenge`.

    3. Callback: After login, the user returns with a `code`.

    4. Verification: The client sends the `code` + the original `verifier` back to the Auth Server.

    5. Success: The Auth Server confirms the math matches and sends back the tokens.

### Application Routes

Route Description

`/` The landing page with login link.

`/login`  
Initializes PKCE, sets security cookies, and redirects to the Auth Server.

`/callback` The redirect URI. Validates state, exchanges the code for tokens, and sets session cookies.

`/profile` Fetches and displays protected data from the Resource Server.

`/refresh` Demonstrates silent token renewal using the `refresh_token`.

### Technical Setup

`npm install express cookie-parser axios`

#### Configuration

Ensure your Auth Server is configured to accept `https://localhost:4000/callback` as a valid redirect URI, otherwise, the flow will be blocked.

### Security Best Practices Implemented

    -   httpOnly Cookies: Tokens are stored in a way that JavaScript cannot access them, protecting against XSS-based token theft.

    -   State Validation: Prevents attackers from tricking the client into accepting an authorization code they didn't request.

    -   PKCE: Essential for public clients (like browsers or mobile apps) where a 'Client Secret' cannot be stored safely.
