## EasyAuth.rs


Using the same endpoints with slight variations in every single project felt wasteful, thats why I made **EasyAuth**. A simple library containing some basic endpoints for user authentication in **Actix Web**.

#### Getting Started

Start your **Actix** app with the following.

```rust
App::new().app_data(Data::new(EasyAuthState { pool: pool.clone() })).configure(easy_auth::config);
```

All the information we need is passed from our project into **EasyAuth** through the app data.

#### Endpoints

**GET** *.../oauth2/refresh_access_token*

---
**Params: **: 'refresh_token' cookie containing a JWT received from registering or logging in.
**Response**: JWT access token in plain text.

---
<br>
**POST** *.../oauth2/google*

---
**Params: **: A JSON body with the fields:
```json
{
	"access_token": A standard google login access jwt,
}
```
---




