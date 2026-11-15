from rest_framework_simplejwt.authentication import JWTAuthentication
from rest_framework import exceptions
from django.middleware.csrf import CsrfViewMiddleware


class _CSRFCheck(CsrfViewMiddleware):
    def _reject(self, request, reason):
        return reason


class CookieJWTAuthentication(JWTAuthentication):
    """
    Custom JWT authentication that reads the access token from an HttpOnly cookie
    or the Authorization header.
    
    Security Hardening (F-013):
    When authenticated via HttpOnly cookie, enforces CSRF validation on unsafe
    HTTP methods (POST, PUT, PATCH, DELETE) to protect against cross-site request forgery.
    Uses defense-in-depth: verifies standard browser Origin/Referer against trusted origins
    (RFC 6454 / OWASP) and falls back to CSRF token verification.
    """

    def enforce_csrf(self, request):
        # 1. OWASP / RFC 6454 Origin header verification defense:
        # Cross-origin scripts (e.g. evil.com) cannot forge the browser's Origin header.
        # If the request originates from an authorized application origin, it is authentic.
        origin = request.META.get('HTTP_ORIGIN') or request.META.get('HTTP_REFERER')
        if origin:
            import re
            import fnmatch
            from django.conf import settings
            trusted_origins = set(getattr(settings, 'CORS_ALLOWED_ORIGINS', [])) | set(getattr(settings, 'CSRF_TRUSTED_ORIGINS', []))
            trusted_origins.update([
                'http://localhost:5173',
                'http://127.0.0.1:5173',
                'http://localhost:3000',
                'http://127.0.0.1:3000',
            ])
            clean_origin = origin.rstrip('/')

            # Direct match or wildcard matching (e.g., https://*.trycloudflare.com)
            for t in trusted_origins:
                if not t:
                    continue
                clean_t = t.rstrip('/')
                if '*' in clean_t:
                    if fnmatch.fnmatch(clean_origin, clean_t):
                        return
                elif clean_origin.startswith(clean_t):
                    return

            # Check CORS_ALLOWED_ORIGIN_REGEXES (e.g. ^https://.*\.trycloudflare\.com$)
            for pattern in getattr(settings, 'CORS_ALLOWED_ORIGIN_REGEXES', []):
                if re.match(pattern, clean_origin):
                    return

        # 2. Enforce standard Django CSRF token check (for requests without Origin or untrusted origins)
        check = _CSRFCheck(lambda req: None)
        check.process_request(request)
        reason = check.process_view(request, None, (), {})
        if reason:
            raise exceptions.PermissionDenied(f"CSRF Failed: {reason}")

    def authenticate(self, request):
        # 1. Check for standard Authorization: Bearer <token> header first
        # Bearer header requests are immune to browser cross-site auto-submission
        header_auth = super().authenticate(request)
        if header_auth is not None:
            return header_auth

        # 2. Fall back to the HttpOnly cookie
        raw_token = request.COOKIES.get('access_token')
        if raw_token:
            try:
                validated_token = self.get_validated_token(raw_token)
                user = self.get_user(validated_token)

                # Enforce CSRF check for state-changing HTTP methods on cookie-based auth
                if request.method not in ('GET', 'HEAD', 'OPTIONS', 'TRACE'):
                    self.enforce_csrf(request)

                return user, validated_token
            except exceptions.PermissionDenied:
                raise
            except Exception:
                pass

        # 3. Fall back to query parameter (e.g. ?token=...) for direct media links/downloads
        query_token = request.query_params.get('token') if hasattr(request, 'query_params') else request.GET.get('token')
        if query_token:
            try:
                validated_token = self.get_validated_token(query_token)
                return self.get_user(validated_token), validated_token
            except Exception:
                pass

        return None
