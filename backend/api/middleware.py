from django.conf import settings


class SecurityHeadersMiddleware:
    """
    Middleware that enforces Content-Security-Policy (CSP), Strict-Transport-Security (HSTS),
    and permissions policies across all HTTP responses (OWASP ASVS / DPA Sec. 20, F-025).
    """

    def __init__(self, get_response):
        self.get_response = get_response

    def __call__(self, request):
        response = self.get_response(request)

        # Content-Security-Policy: restrict origins for scripts, styles, fonts, frames, and connections
        if 'Content-Security-Policy' not in response:
            response['Content-Security-Policy'] = (
                "default-src 'self'; "
                "script-src 'self' 'unsafe-inline' https://cdn.jsdelivr.net; "
                "style-src 'self' 'unsafe-inline' https://fonts.googleapis.com; "
                "font-src 'self' https://fonts.gstatic.com; "
                "img-src 'self' data: https: blob:; "
                "connect-src 'self' https: http: ws: wss:; "
                "frame-ancestors 'none';"
            )

        # Permissions-Policy: disable sensitive browser APIs by default
        if 'Permissions-Policy' not in response:
            response['Permissions-Policy'] = "camera=(), microphone=(), geolocation=()"

        # Strict-Transport-Security (HSTS): Enforce HTTPS connections
        if 'Strict-Transport-Security' not in response:
            if request.is_secure() or getattr(settings, 'SECURE_HSTS_SECONDS', 0) > 0:
                response['Strict-Transport-Security'] = "max-age=31536000; includeSubDomains; preload"

        return response
