

import requests
import uuid
import re
import time
import logging
import json
from typing import Dict, Optional, Any, List
from dataclasses import dataclass, asdict, field

logger = logging.getLogger(__name__)


@dataclass
class CheckResult:
    """Response object for email validation checks."""
    success: bool
    email: str
    message: str
    http_status: int = 200
    data: Optional[Dict[str, Any]] = None
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert result to dictionary."""
        result = asdict(self)
        if self.data is None:
            result.pop('data')
        return result


class MicrosoftEmailAPI:
    """Validates Microsoft email credentials via OAuth 2.0 flow."""
    
    def __init__(self, debug: bool = False):
        """
        Initialize the checker.
        
        Args:
            debug: Enable debug logging
        """
        self.session = requests.Session()
        self.uuid = str(uuid.uuid4())
        self.debug = debug
        self._setup_logging()
        
        # Session storage
        self.access_token: Optional[str] = None
        self.refresh_token: Optional[str] = None
        self.id_token: Optional[str] = None
        self.email: Optional[str] = None
        self.cid: Optional[str] = None
        self.cookies: Optional[Dict[str, str]] = None
        
    def _setup_logging(self):
        """Configure logging."""
        if self.debug:
            logging.basicConfig(level=logging.DEBUG)
        else:
            logging.basicConfig(level=logging.INFO)
    
    def _log(self, message: str):
        """Log debug messages."""
        if self.debug:
            logger.debug(message)
    
    def authenticate(self, email: str, password: str) -> CheckResult:
        """
        Validate email credentials via Microsoft OAuth 2.0.
        
        Args:
            email: Microsoft email address
            password: Email password
            
        Returns:
            CheckResult: Validation result with account details
        """
        return self._check_impl(email, password)
    
    def _check_impl(self, email: str, password: str) -> CheckResult:
        """Internal implementation of check."""
        try:
            self._log(f"Starting check: {email}")
            
            # Step 1: IDP check
            self._log("Step 1: IDP check")
            idp_result = self._check_idp(email)
            if not idp_result.success:
                return idp_result
            
            # Step 2: OAuth authorize
            self._log("Step 2: OAuth authorize")
            auth_result = self._oauth_authorize(email)
            if not auth_result.success:
                return auth_result
            post_url, ppft = auth_result.data
            
            # Step 3: Login POST
            self._log("Step 3: Login POST")
            login_result = self._login_post(email, password, post_url, ppft)
            if not login_result.success:
                return login_result
            code, cid = login_result.data
            
            # Step 4: Get token
            self._log("Step 4: Getting token")
            token_result = self._get_token(code)
            if not token_result.success:
                return token_result
            access_token, refresh_token, id_token = token_result.data
            
            # Store session data
            self.access_token = access_token
            self.refresh_token = refresh_token
            self.id_token = id_token
            self.email = email
            self.cid = cid
            self.cookies = dict(self.session.cookies)
            
            # Step 5: Get profile (optional, can be skipped if not needed)
            self._log("Step 5: Getting profile")
            profile_data = self._get_profile(access_token, cid)
            
            self._log(f"✓ Validation successful: {email}")
            return CheckResult(
                success=True,
                email=email,
                message="Account validated successfully",
                http_status=200,
                data={
                    "access_token": access_token,
                    "refresh_token": refresh_token,
                    "id_token": id_token,
                    "cid": cid,
                    "cookies": self.cookies,
                    "name": profile_data.get("name", ""),
                    "country": profile_data.get("country", ""),
                    "birthdate": profile_data.get("birthdate", "")
                }
            )
            
        except requests.exceptions.Timeout:
            self._log("Timeout error")
            return CheckResult(
                success=False,
                email=email,
                message="Request timeout",
                http_status=504
            )
        except Exception as e:
            self._log(f"Exception: {str(e)}")
            return CheckResult(
                success=False,
                email=email,
                message=f"Error: {str(e)}",
                http_status=500
            )
    
    def _check_idp(self, email: str) -> CheckResult:
        """Check if email uses Microsoft identity provider."""
        url = f"https://odc.officeapps.live.com/odc/emailhrd/getidp?hm=1&emailAddress={email}"
        headers = {
            "X-OneAuth-AppName": "Outlook Lite",
            "X-Office-Version": "3.11.0-minApi24",
            "X-CorrelationId": self.uuid,
            "User-Agent": "Dalvik/2.1.0 (Linux; U; Android 9; SM-G975N Build/PQ3B.190801.08041932)",
            "Host": "odc.officeapps.live.com",
            "Connection": "Keep-Alive",
            "Accept-Encoding": "gzip"
        }
        try:
            r = self.session.get(url, headers=headers, timeout=15)
            
            if any(x in r.text for x in ["Neither", "Both", "Placeholder", "OrgId"]):
                return CheckResult(
                    success=False,
                    email=email,
                    message="Account not found or unsupported domain",
                    http_status=400
                )
            
            if "MSAccount" not in r.text:
                return CheckResult(
                    success=False,
                    email=email,
                    message="Not a Microsoft account",
                    http_status=400
                )
            
            self._log("✅ IDP check passed")
            return CheckResult(success=True, email=email, message="IDP check passed", http_status=200)
            
        except Exception as e:
            return CheckResult(
                success=False,
                email=email,
                message=f"IDP check failed: {str(e)}",
                http_status=500
            )
    
    def _oauth_authorize(self, email: str) -> CheckResult:
        """Get OAuth authorize page and extract post_url and PPFT."""
        url = f"https://login.microsoftonline.com/consumers/oauth2/v2.0/authorize?client_info=1&haschrome=1&login_hint={email}&mkt=en&response_type=code&client_id=e9b154d0-7658-433b-bb25-6b8e0a8a7c59&scope=profile%20openid%20offline_access%20https%3A%2F%2Foutlook.office.com%2FM365.Access&redirect_uri=msauth%3A%2F%2Fcom.microsoft.outlooklite%2Ffcg80qvoM1YMKJZibjBwQcDfOno%253D"
        
        headers = {
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
            "Accept-Language": "en-US,en;q=0.9",
            "Connection": "keep-alive"
        }
        
        try:
            r = self.session.get(url, headers=headers, allow_redirects=True, timeout=15)
            
            # Extract post_url
            url_match = re.search(r'urlPost":"([^"]+)"', r.text)
            # Extract PPFT
            ppft_match = re.search(r'name=\\"PPFT\\" id=\\"i0327\\" value=\\"([^"]+)"', r.text)
            
            if not url_match or not ppft_match:
                self._log(f"Could not extract: url_match={url_match is not None}, ppft_match={ppft_match is not None}")
                return CheckResult(False, email, "Failed to extract auth data", 400)
            
            post_url = url_match.group(1).replace("\\/", "/")
            ppft = ppft_match.group(1)
            
            self._log("✅ OAuth page parsed")
            return CheckResult(True, email, "OAuth page parsed", 200, (post_url, ppft))
            
        except Exception as e:
            self._log(f"Authorize error: {str(e)}")
            return CheckResult(False, email, f"Authorize error: {e}", 500)
    
    def _login_post(self, email: str, password: str, post_url: str, ppft: str) -> CheckResult:
        """Submit login credentials."""
        try:
            # Form-encoded data as string
            login_data = f"i13=1&login={email}&loginfmt={email}&type=11&LoginOptions=1&lrt=&lrtPartition=&hisRegion=&hisScaleUnit=&passwd={password}&ps=2&psRNGCDefaultType=&psRNGCEntropy=&psRNGCSLK=&canary=&ctx=&hpgrequestid=&PPFT={ppft}&PPSX=PassportR&NewUser=1&FoundMSAs=&fspost=0&i21=0&CookieDisclosure=0&IsFidoSupported=0&isSignupPost=0&isRecoveryAttemptPost=0&i19=9960"
            
            headers = {
                "Content-Type": "application/x-www-form-urlencoded",
                "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
                "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
                "Origin": "https://login.live.com",
                "Referer": post_url
            }
            
            r = self.session.post(post_url, data=login_data, headers=headers, allow_redirects=False, timeout=15)
            
            self._log(f"Login response status: {r.status_code}")
            
            # Check for incorrect password
            if "account or password is incorrect" in r.text.lower() or "The password you entered isn't correct" in r.text:
                return CheckResult(False, email, "Invalid credentials", 401)
            
            # Check for security challenges
            if "identity/confirm" in r.text:
                return CheckResult(False, email, "2FA required", 403)
            
            if "Abuse" in r.text:
                return CheckResult(False, email, "Account blocked", 403)
            
            # Get redirect location
            location = r.headers.get("Location", "")
            if not location:
                self._log("No redirect location found")
                return CheckResult(False, email, "Login failed (no redirect)", 400)
            
            # Extract authorization code
            code_match = re.search(r'code=([^&]+)', location)
            if not code_match:
                self._log(f"No auth code in location")
                return CheckResult(False, email, "No auth code", 400)
            
            code = code_match.group(1)
            
            # Get CID from cookies
            cid = self.session.cookies.get("MSPCID", "").upper()
            if not cid:
                self._log("MSPCID cookie not found")
                return CheckResult(False, email, "Missing CID", 400)
            
            self._log("✅ Login successful")
            return CheckResult(True, email, "Login success", 200, (code, cid))
            
        except Exception as e:
            self._log(f"Login error: {str(e)}")
            return CheckResult(False, email, f"Login error: {e}", 500)
    
    def _get_token(self, code: str) -> CheckResult:
        """Exchange authorization code for access token."""
        try:
            token_data = f"client_info=1&client_id=e9b154d0-7658-433b-bb25-6b8e0a8a7c59&redirect_uri=msauth%3A%2F%2Fcom.microsoft.outlooklite%2Ffcg80qvoM1YMKJZibjBwQcDfOno%253D&grant_type=authorization_code&code={code}&scope=profile%20openid%20offline_access%20https%3A%2F%2Foutlook.office.com%2FM365.Access"
            
            r = self.session.post(
                "https://login.microsoftonline.com/consumers/oauth2/v2.0/token",
                data=token_data,
                headers={"Content-Type": "application/x-www-form-urlencoded"},
                timeout=15
            )
            
            if r.status_code != 200:
                self._log(f"Token request failed: {r.status_code}")
                return CheckResult(False, "", f"Token request failed: {r.status_code}", r.status_code)
            
            if "access_token" not in r.text:
                self._log(f"No access_token in response")
                return CheckResult(False, "", "Failed to get access token", 400)
            
            token_json = r.json()
            access_token = token_json.get("access_token")
            refresh_token = token_json.get("refresh_token", "")
            id_token = token_json.get("id_token", "")
            
            self._log("✅ Token obtained")
            return CheckResult(True, "", "Token obtained", 200, (access_token, refresh_token, id_token))
            
        except Exception as e:
            self._log(f"Token error: {str(e)}")
            return CheckResult(False, "", f"Token error: {e}", 500)
    
    def _get_profile(self, access_token: str, cid: str) -> Dict[str, str]:
        """Get user profile information."""
        profile_data = {"name": "", "country": "", "birthdate": ""}
        
        try:
            headers = {
                "User-Agent": "Outlook-Android/2.0",
                "Authorization": f"Bearer {access_token}",
                "X-AnchorMailbox": f"CID:{cid}"
            }
            
            # Try V1Profile endpoint
            r = self.session.get(
                "https://substrate.office.com/profileb2/v2.0/me/V1Profile",
                headers=headers,
                timeout=15
            )
            
            if r.status_code == 200:
                profile = r.json()
                
                # Extract name
                if "displayName" in profile and profile["displayName"]:
                    profile_data["name"] = profile["displayName"]
                elif "name" in profile and profile["name"]:
                    profile_data["name"] = profile["name"]
                
                # Extract country
                if "location" in profile:
                    location = profile["location"]
                    if isinstance(location, str):
                        parts = [p.strip() for p in location.split(',')]
                        if parts:
                            profile_data["country"] = parts[-1]
                    elif isinstance(location, dict):
                        profile_data["country"] = location.get("country", "")
                
                # Extract birthdate
                birth_day = profile.get("birthDay", "")
                birth_month = profile.get("birthMonth", "")
                birth_year = profile.get("birthYear", "")
                if birth_day and birth_month:
                    if birth_year:
                        profile_data["birthdate"] = f"{birth_day}-{birth_month}-{birth_year}"
                    else:
                        profile_data["birthdate"] = f"{birth_day}-{birth_month}"
                
                self._log(f"Profile: name={profile_data['name']}, country={profile_data['country']}")
            
            # Fallback to Graph API if needed
            elif r.status_code == 401:
                self._log("V1Profile returned 401, skipping")
                
        except Exception as e:
            self._log(f"Profile retrieval failed: {str(e)}")
        
        return profile_data


if __name__ == "__main__":
    """Example usage of MicrosoftEmailAPI."""
    # Initialize API (set debug=True for verbose logging)
    api = MicrosoftEmailAPI(debug=True)
    
    # Example: Check email credentials
    result = api.authenticate("user@hotmail.com", "password")
    
    # Print result as JSON
    print(json.dumps(result.to_dict(), indent=2))
