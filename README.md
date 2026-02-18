# Passwordless Authentication Backend

Spring Boot backend implementing WebAuthn/FIDO2 passwordless authentication.

## Technology Stack

- Java 21
- Spring Boot 3.x
- Yubico WebAuthn Server Library
- PostgreSQL
- Hibernate/JPA
- JWT for session management

## Architecture

### Clean Architecture Layers

```
controller → service → repository → entity
```

### Key Components

- **WebAuthnController**: REST endpoints for registration and authentication
- **WebAuthnService**: Core business logic for WebAuthn flows
- **CredentialRepository**: Bridge between Yubico library and database
- **JwtService**: Token generation and validation
- **GlobalExceptionHandler**: Centralized error handling

## API Endpoints

### Registration

**POST /webauthn/register/start**
```json
{
  "username": "john.doe",
  "email": "john@example.com",
  "displayName": "John Doe"
}
```

**POST /webauthn/register/finish**
```json
{
  "username": "john.doe",
  "credential": { /* PublicKeyCredential from browser */ }
}
```

### Authentication

**POST /webauthn/authenticate/start**
```json
{
  "username": "john.doe"  // optional
}
```

**POST /webauthn/authenticate/finish**
```json
{
  "credential": { /* PublicKeyCredential from browser */ }
}
```

## Database Schema

### users
- id (PK)
- username (unique)
- email (unique)
- user_handle (unique, WebAuthn user.id)
- display_name
- created_at
- updated_at

### passkey_credentials
- id (PK)
- credential_id (unique, base64url)
- public_key (base64url COSE key)
- signature_counter
- transports
- aaguid
- user_id (FK)
- created_at
- last_used_at
- device_name

## Configuration

Edit `src/main/resources/application.yml`:

```yaml
webauthn:
  rp:
    id: localhost
    name: Passwordless Auth Sandbox
  origin: http://localhost:3000
```

## Running Locally

```bash
# With Docker
docker-compose up

# Without Docker
./gradlew bootRun
```

## Security Features

- HTTPS enforcement (configure in production)
- Challenge expiration
- RP ID validation
- Origin validation
- Signature counter verification
- Rate limiting (add in production)
