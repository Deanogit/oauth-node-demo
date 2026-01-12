## OAuth 2.0 System

A distributed architecture designed for security. This system splits responsibilites across three independent services to ensure maximum security and scalability

### The Three Pillars

Server Port Role Responsibility
Authorization `3000` Identity Provider Manages users, logins, and issues JWT keys.

Client `4000` UI User Interface

Resource `5000` API Protects the database and validates access keys.

### The Authentication Journey

To understand how a user goes from 'Logged Out' to 'Sending data':

    1. The Request: The user visits the Client App and clicks 'Login'.
    2. The PKCE Handshake: The Client creates a secret 'verifier' and sends a 'challenge' to the Auth Server.
    3. The Identity Check: The Auth Server asks for credentials. Once verified, it sends a `code` back to the Client.
    4. The Exchange: The Client sends the `code` and the original `verifier` to the Auth Server. Since the math matches, the Auth Server issues a JWT Access Token.
    5. The Protected Access: When the user saves, the Client sends data the JWT to the Resource Server. The Resource Server verifies the signature and saves the data

#### Project Structure

system/
|-- auth-server/ #Port 3000 (OIDC Provider)
|-- client-app/ #Port 4000 (User Interface)
|-- resource-api/ #Port 5000 (API)

### How to Start the System

To run the full suite, you must open three terminal windows and start each server in order:

    1. Start Auth Server: `node auth-server/index.js` (Must be first for JWKS discovery)
    2. Start Resource Server: `node resource-server/index.js` (Fetches public keys from Auth)
    3. Start Client App: `node client-app/index.js` (The entry point for users).

### Why this architecture?

    - Seperation of Concerns: Your API doesn't need to know how to handle passwords, and your UI doesn't need to know how to handle database queries.

    - Security: By using PKCE and httpOnly cookies, the system is resilient against common attacks like Man-in-the-Middle (MitM) and Cross-Site Scripting (XSS).

    - Scalability: You could eventually replace the Client App with a Mobile App(iOS/Android), and it would use the exact same Auth and Resource servers.
