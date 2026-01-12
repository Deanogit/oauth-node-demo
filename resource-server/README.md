## OAuth 2.0 Resource Server

A secure API server that acts as a protected resource provider. It validates incoming JWT (JSON Web Tokens) against a remote Authorization Server using the JWKS(JSON Web Key Set) standard.

### Overview

The Resource Server protects sensitive data (like user profiles). Instead of checking passwords, it validates a Bearer Token sent in the request header. It trusts the Authorization Server by fetching its public keys and verifying the cryptographic signature of the token.

### Key Features

    - Remote Key Discovery: Uses `createRemoteJWKSet` to fetch public keys from the Auth Server's `.well-known` endpoint.
    - JWT Validation: Automatically checks the token's signature, issuer (`iss`), audience (`aud`), and expiration (`exp`).
    - Scoped Access Control: Implements fine-grained permissions using a `requiredScope` middleware.
    - Request Enrichment: Decodes the JWT payload and attaches the user's identity (`req.user`) to the request object for use in routes.

### Architecture: How Validation Works

When a request hits a protected route like `/api/profile`:

    1. Extraction: The `requireAuth` middleware pulls the token from the `Authorization: Bearer <token>`header.

    2. Signature Check: The server uses the public keys from `https://localhost:3000` to ensure the token hasn't been tampered with.

    3. Claims Verification: It ensures the token was actually issued for this specific client (`demo-client`).

    4. Scope Check: The `requiredScope` middleware verifies the user has the specific permission (e.g, `api.read`) required for that endpoint.

#### API Endpoints

Endpoint Method Required Scope Description
`/api/profile` `GET` `api.read` Returns the authenticated user's profile details.

### Technical Implementation

Middleware: `requireAuth`
This is the primary security gate. It uses the `jose`library to perform high-speed cryptographic verification.

```JavaScript

// Example of how to protect any route:
app.post('/api/reflections', requireAuth, (req,res) => {
    const userId = req.user.sub; // The user's unique ID from the token
    // Save logic here...
});
```

#### Dependencies

`npm install express jose``

#### Requirements for Operation

For this server to function, the Authorization Server (Port 3000) must be running so that the `JWKS` can be fetched at startup.
