## OAuth 2.0 Authorization server (OIDC)

A lightweight, custom implementation of an OAuth 2.0 Authorization server built with Node.js and Express. This server handles user authentication, authorization codes, and JWT (JSON Web Token) issuance.

### Overview

This server acts as the "Identity Provider". It allows third party applications (clients) to securely verify a user's identity and obtain access tokens without the user ever sharing their password with the client.

### Key Features

    -   Authorization Code Grant: The most secure flow for web and mobile apps.
    -   PKCE (Proof Key for Code Exchange): Protects against code injection attacks by requiring a `code_verifier` and `code_challenge`.
    -   JWT Issuance: Generates signed RS256 Access Tokens containing user claims (name, email, etc).
    -   Refresh Tokens: Allows clients to obtain new access tokens without re-authenticating the user.
    -   JWKS Endpoint: A ´.well-known/jwks.json` endpoint so Resource Servers can automatically discover the public key needed to verify tokens.

### Architecture and Data Flow

    1.  Authorization: The client redirects the user to `/authorize`. The server validates the client and records the PKCE Challenge.

    2.  Code Exchange: The user is redirected back to the client with a temporary `code`.

    3.  Token Issuance: The client sends the `code`and the original `code_verifier`to `/token`.

    4.  Verification: The server hashes the verifier; if it matches the challenge, it issues a JWT Access Token and a Refresh Token.

#### API Endpoints

Endpoint Method Description
`/authorize` `GET` Starts with login flow; validates Client ID & PKCE.
`/Token` `POST` Exchanges codes for Access Tokens or uses Refresh Tokens.
`/.well-known/jwks.json`
`GET` Provides the Public Key for Token signature verification.

### Setup & Security Note

1. Dependencies
   This project uses `jose` for modern JWT/JWS operations and `crypto` for hashing.

`npm init`
`npm install express body-parser cookie-parser jose`

2. RSA Keys
   The server signs tokens using **RS256**. For production, you must replace the `PRIVATE_KEY_PEM` with a real key generated via OpenSSL:

`openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:2048 -out private.pem`

[!WARNING] Security Warning: This implementation uses a dummy private key and an in-memory Map for storage. For production use, integrate a persistent database (PostgreSQL/MongoDB) and store your private keys in a Secure Vault or Environment Variable.
