# Notes App Backend API Documentation

## Base URL
```
http://localhost:5000
```

## Authentication
The API uses JWT tokens stored in HTTP-only cookies for authentication. Include credentials in requests.

---

## Authentication Endpoints

### Register User
**POST** `/auth/register`

**Body:**
```json
{
  "name": "John Doe",
  "email": "john@example.com",
  "password": "password123"
}
```

**Response:**
```json
{
  "message": "User created successfully.",
  "user": {
    "id": 1,
    "name": "John Doe",
    "email": "john@example.com"
  }
}
```

**Validation:**
- All fields required
- Email must be valid format
- Password must be at least 6 characters
- Email must be unique

---

### Login User
**POST** `/auth/login`

**Body:**
```json
{
  "email": "john@example.com",
  "password": "password123"
}
```

**Response:**
```json
{
  "message": "Login successful",
  "user": {
    "id": 1,
    "name": "John Doe",
    "email": "john@example.com"
  }
}
```

**Notes:**
- Sets HTTP-only cookie with JWT token
- Token expires in 24 hours

---

### Logout User
**POST** `/auth/logout`

**Response:**
```json
{
  "message": "logout successful"
}
```

---

### Get Current User
**GET** `/auth/me`

**Response:**
```json
{
  "user": {
    "id": 1,
    "name": "John Doe",
    "email": "john@example.com",
    "created_at": "2025-10-29T09:00:00.000Z"
  }
}
```

**Notes:**
- Returns `{"user": null}` if not authenticated

---

### Google OAuth
**GET** `/auth/google`

Redirects to Google OAuth consent screen.

**GET** `/auth/google/callback`

OAuth callback endpoint. Redirects to frontend on success/failure.

---

### Forgot Password
**POST** `/auth/forgot-password`

**Body:**
```json
{
  "email": "john@example.com"
}
```

**Response:**
```json
{
  "message": "If an account with that email exists, a password reset link has been sent.",
  "emailSent": false
}
```

**Notes:**
- Always returns success message for security
- Generates reset token valid for 1 hour
- Requires SMTP configuration for email sending

---

### Reset Password
**POST** `/auth/reset-password`

**Body:**
```json
{
  "token": "uuid-reset-token",
  "newPassword": "newpassword123"
}
```

**Response:**
```json
{
  "message": "Password reset successfully"
}
```

**Validation:**
- Token must be valid and not expired
- New password must be at least 6 characters

---

### Email Verification
**POST** `/auth/verify-email`

**Body:**
```json
{
  "token": "uuid-verification-token"
}
```

**Response:**
```json
{
  "message": "Email verified successfully"
}
```

---

## Notes Endpoints (Authenticated)

### Get User's Notes
**GET** `/notes`

**Query Parameters:**
- `page` (optional): Page number (default: 1)
- `limit` (optional): Items per page (default: 10, max: 100)
- `search` (optional): Search in note titles and content
- `visibility` (optional): "all", "public", "private" (default: "all")
- `sortBy` (optional): "created_at", "updated_at", "title" (default: "updated_at")
- `sortOrder` (optional): "asc", "desc" (default: "desc")

**Response:**
```json
{
  "notes": [
    {
      "id": 1,
      "title": "My Note",
      "content": "Note content here",
      "user_id": 1,
      "is_public": false,
      "is_draft": false,
      "created_at": "2025-10-29T09:00:00.000Z",
      "updated_at": "2025-10-29T09:00:00.000Z"
    }
  ],
  "totalNotes": 1,
  "totalPages": 1,
  "currentPage": 1,
  "filters": {
    "search": "",
    "visibility": "all",
    "sortBy": "updated_at",
    "sortOrder": "desc"
  }
}
```

---

### Get Single Note
**GET** `/notes/:id`

**Response:**
```json
{
  "note": {
    "id": 1,
    "title": "My Note",
    "content": "Note content here",
    "user_id": 1,
    "created_at": "2025-10-29T09:00:00.000Z",
    "updated_at": "2025-10-29T09:00:00.000Z"
  }
}
```

---

### Create Note
**POST** `/notes`

**Body:**
```json
{
  "title": "New Note",
  "content": "Note content here",
  "isPublic": false,
  "isDraft": false
}
```

**Response:**
```json
{
  "message": "Note created successfully",
  "note": {
    "id": 1,
    "title": "New Note",
    "content": "Note content here",
    "user_id": 1,
    "created_at": "2025-10-29T09:00:00.000Z",
    "updated_at": "2025-10-29T09:00:00.000Z"
  }
}
```

**Notes:**
- Content is automatically encrypted for security
- Both title and content are required

---

### Update Note
**PUT** `/notes/:id`

**Body:**
```json
{
  "title": "Updated Note",
  "content": "Updated content here",
  "isPublic": false,
  "isDraft": false
}
```

**Response:**
```json
{
  "message": "Note updated successfully",
  "note": {
    "id": 1,
    "title": "Updated Note",
    "content": "Updated content here",
    "user_id": 1,
    "created_at": "2025-10-29T09:00:00.000Z",
    "updated_at": "2025-10-29T09:01:00.000Z"
  }
}
```

---

### Delete Note
**DELETE** `/notes/:id`

**Response:**
```json
{
  "message": "Note deleted successfully",
  "note": {
    "id": 1,
    "title": "Deleted Note",
    "user_id": 1
  }
}
```

---

### Auto-save Note
**POST** `/notes/:id/autosave`

**Body:**
```json
{
  "title": "Auto-saved title",
  "content": "Auto-saved content"
}
```

**Response:**
```json
{
  "message": "Note auto-saved successfully"
}
```

**Notes:**
- For draft functionality
- Updates existing note without changing public/draft status

---

## Public Endpoints (No Authentication)

### Get Public Notes
**GET** `/notes/public`

**Query Parameters:**
- `page` (optional): Page number (default: 1)
- `limit` (optional): Items per page (default: 10, max: 100)
- `search` (optional): Search in note titles

**Response:**
```json
{
  "notes": [
    {
      "id": 1,
      "title": "Public Note",
      "content": "Public content here",
      "created_at": "2025-10-29T09:00:00.000Z",
      "user_id": 1,
      "Users": {
        "name": "John Doe"
      }
    }
  ],
  "totalNotes": 1,
  "totalPages": 1,
  "currentPage": 1
}
```

---

### Get Feature Status
**GET** `/features`

**Response:**
```json
{
  "available": {
    "basicNotes": true,
    "noteEncryption": true,
    "userAuthentication": true,
    "passwordReset": true,
    "googleOAuth": true,
    "sorting": true,
    "basicFiltering": true,
    "pagination": true
  },
  "requiresDatabaseUpdate": {
    "categories": true,
    "labels": true,
    "advancedFiltering": true,
    "notePriority": true,
    "noteArchiving": true,
    "fullTextSearch": true,
    "bulkOperations": true
  },
  "message": "Run the SQL script in simple-database-updates.sql to enable advanced features.",
  "databaseUpdateScript": "simple-database-updates.sql"
}
```

---

## Currently Working Features

### ✅ **Fully Functional:**
- **User Authentication**: Registration, login, logout, password reset
- **Google OAuth**: Complete OAuth flow
- **Basic Notes CRUD**: Create, read, update, delete notes
- **Search**: Search in note titles and content
- **Sorting**: Sort by created_at, updated_at, or title (asc/desc)
- **Pagination**: Page-based pagination with configurable limits
- **Content Encryption**: Automatic encryption/decryption of note content
- **Public/Private Notes**: Basic visibility control
- **Draft Support**: Mark notes as drafts

### 🔄 **Requires Database Update:**
- **Categories**: Organize notes into categories
- **Labels**: Tag notes with multiple labels
- **Priority Levels**: Set note priorities (0-5)
- **Archive Functionality**: Archive/unarchive notes
- **Advanced Filtering**: Filter by category, labels, priority
- **Full-Text Search**: Enhanced search capabilities
- **Bulk Operations**: Perform actions on multiple notes

---

## Error Responses

### 400 Bad Request
```json
{
  "message": "Validation error message"
}
```

### 401 Unauthorized
```json
{
  "message": "Invalid or no token found"
}
```

### 404 Not Found
```json
{
  "message": "Resource not found"
}
```

### 500 Internal Server Error
```json
{
  "message": "Internal server error"
}
```

---

## Security Features

1. **Password Hashing**: Bcrypt with salt rounds
2. **JWT Authentication**: Secure token-based auth
3. **HTTP-Only Cookies**: Prevents XSS attacks
4. **Content Encryption**: Note content is encrypted at rest
5. **Input Validation**: All inputs are validated and sanitized
6. **CORS Configuration**: Properly configured for frontend
7. **Rate Limiting**: Consider implementing for production

---

## Environment Variables Required

```env
SUPABASE_URL=your_supabase_url
SUPABASE_KEY=your_supabase_anon_key
JWT_SECRET=your_jwt_secret
SESSION_SECRET=your_session_secret
COOKIE_NAME=token
PORT=5000
FRONTEND_URL=http://localhost:3000
BACKEND_URL=http://localhost:5000

# Google OAuth
GOOGLE_CLIENT_ID=your_google_client_id
GOOGLE_CLIENT_SECRET=your_google_client_secret

# Email (for password reset)
EMAIL_HOST=smtp.gmail.com
EMAIL_PORT=587
EMAIL_USER=your_email@gmail.com
EMAIL_PASS=your_app_password

# Encryption
ENCRYPTION_KEY=your_32_character_encryption_key
```

---

## Database Schema

### Users Table
- `id` (Primary Key)
- `name` (String)
- `email` (String, Unique)
- `password` (String, Hashed)
- `reset_token` (String, Nullable)
- `reset_expires` (Timestamp, Nullable)
- `created_at` (Timestamp)
- `updated_at` (Timestamp)

### Posts Table (Used for Notes)
- `id` (Primary Key)
- `title` (String)
- `body` (Text) - Note content
- `user_id` (Foreign Key to Users)
- `encrypted_content` (Text, Nullable) - Encrypted version
- `is_public` (Boolean, Default: false)
- `is_draft` (Boolean, Default: false)
- `created_at` (Timestamp)
- `updated_at` (Timestamp)