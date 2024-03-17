## EasyAuth.rs

Using the same endpoints with slight variations in every single project felt wasteful, that's why I made **EasyAuth**. A simple library containing some basic endpoints for user authentication in **Actix Web**.

#### Getting Started

Start your **Actix** app with the following.

```rust
App::new().app_data(Data::new(EasyAuthState { pool: pool.clone() })).configure(easy_auth::config);
```

All the information we need is passed from our project into **EasyAuth** through the app data.

---

### is_username_taken

This endpoint checks if a username is already taken in the system.

**Method**: GET

**Path**: /oauth2/is_username_taken

**Query Parameters**:
- username: String (required) - The username to check

**Responses**:
- 200 OK: The username is available
- 409 Conflict: The username is already taken

---

### fetch_account_data

This endpoint fetches the account data associated with the access token.

**Method**: GET

**Path**: /oauth2/fetch_account_data

**Headers**:
- Authorization: Bearer access token

**Responses**:
- 200 OK: Returns the account data in JSON format
- 401 Unauthorized: Access token is missing or invalid

---

### refresh_access_token

This endpoint refreshes the access token using the refresh token.

**Method**: GET

**Path**: /oauth2/refresh_access_token

**Headers**:
- Cookie: refresh token

**Responses**:
- 200 OK: Returns the new access token
- 400 Bad Request: Refresh token not provided
- 401 Unauthorized: Failed to refresh token

---

### google

This endpoint allows users to authenticate using a Google access token.

**Method**: POST

**Path**: /oauth2/google

**Headers**:
- Authorization: Bearer access token

**Request Body**:
- access_token: Required Google access token

**Responses**:
- 200 OK: Returns the new access token and refresh token
- 401 Unauthorized: Invalid Token
- 500 Internal Server Error: Unable to register or login with Google

---

### logout

This endpoint logs the user out by expiring the refresh token.

**Method**: POST

**Path**: /oauth2/logout

**Responses**:
- 200 OK: Logs the user out by expiring the refresh token