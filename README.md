# OAuth Server

A secure OAuth 2.0 server implementation using ASP.NET Core and OpenIddict.

## Features

- OAuth 2.0 compliant authentication server
- Password grant flow support
- User registration and management
- Token-based authentication
- User information endpoint
- Secure token generation and validation

## Prerequisites

- .NET 7.0 or later
- PostgreSQL database
- Redis (for session management)

## Getting Started

1. Clone the repository:
```bash
git clone https://github.com/yourusername/OAuthServer.git
```

2. Update the connection strings in `appsettings.json`:
```json
{
  "ConnectionStrings": {
    "DefaultConnection": "your-postgresql-connection-string",
    "Redis": "your-redis-connection-string"
  }
}
```

3. Run the migrations:
```bash
dotnet ef database update
```

4. Run the application:
```bash
dotnet run
```

## API Endpoints

### Authentication
- `POST /account/register` - Register a new user
- `POST /connect/token` - Get access token (OAuth2 password grant)
- `GET /account/me` - Get current user information

## Configuration

The application uses the following configuration settings:

- Database connection string
- Redis connection string
- Token configuration
- CORS settings

## Security

This project follows OAuth 2.0 security best practices:
- Secure token generation
- Password hashing
- HTTPS enforcement
- Token expiration
- Refresh token rotation

## Contributing

1. Fork the repository
2. Create your feature branch (`git checkout -b feature/amazing-feature`)
3. Commit your changes (`git commit -m 'Add some amazing feature'`)
4. Push to the branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request

## License

This project is licensed under the MIT License - see the LICENSE file for details
