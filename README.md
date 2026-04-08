# Microsoft Email Auth API

> Reverse engineered Microsoft OAuth 2.0 authentication flow

## How it works

**Step 1:** IDP Check - Detects if email is Microsoft account
**Step 2:** OAuth Authorize - Gets login form and PPFT token
**Step 3:** Login POST - Submits credentials
**Step 4:** Get Token - Exchanges code for access token
**Step 5:** Get Profile - Fetches name, country, birthdate

## Installation

```bash
pip install requests
```

Usage

```python
from microsoft_email_api import MicrosoftEmailAPI

api = MicrosoftEmailAPI()
result = api.authenticate("email@hotmail.com", "password")

if result.success:
    print(f"✅ Valid")
    print(f"Name: {result.data['name']}")
    print(f"Country: {result.data['country']}")
    print(f"Birthdate: {result.data['birthdate']}")
else:
    print(f"❌ {result.message}")
```

Response

```json
{
  "success": true,
  "email": "user@hotmail.com",
  "data": {
    "access_token": "eyJ0eXAi...",
    "name": "John Doe",
    "country": "US",
    "birthdate": "01-01-1990"
  }
}
```

Status Codes

Code Meaning
200 ✅ Valid credentials
400 ❌ Not a Microsoft account
401 ❌ Invalid password
403 ❌ 2FA required

Telegram

[f](https://t.me/rawapis) - More reversed APIs daily

License

MIT - Educational purposes only
