#!/usr/bin/env python3
"""Module for basic authentication."""

from api.v1.auth.auth import Auth
from typing import TypeVar
import base64

from models.user import User


class BasicAuth(Auth):
    """Basic Authentication Class."""

    def extract_base64_authorization_header(self,
                                            authorization_header: str) -> str:
        """Extract Base64 of the Authorization Header."""
        if authorization_header is None:
            return None
        if not isinstance(authorization_header, str):
            return None
        if not authorization_header.startswith('Basic '):
            return None

        token_encoded = authorization_header.split(' ')[-1]
        return token_encoded

    def decode_base64_authorization_header(
            self, base64_authorization_header: str) -> str:
        """Decodes the base64-encoded authorization header."""
        if base64_authorization_header is None:
            return None
        if not isinstance(base64_authorization_header, str):
            return None

        try:
            encoded_item = base64_authorization_header.encode('utf-8')
            decoded = base64.b64decode(encoded_item)
            return decoded.decode('utf-8')
        except Exception:
            return None

    def extract_user_credentials(
            self, decoded_base64_authorization_header: str) -> (str, str):
        """Extracts user credentials from a base64-decoded authorization
        header value."""
        if decoded_base64_authorization_header is None:
            return (None, None)
        if not isinstance(decoded_base64_authorization_header, str):
            return (None, None)
        if ':' not in decoded_base64_authorization_header:
            return (None, None)

        Email, Pwd = decoded_base64_authorization_header.split(':')
        return (Email, Pwd)

    def user_object_from_credentials(
            self, user_email: str, user_pwd: str) -> TypeVar('User'):
        """Get a user based on the user's authentication credentials"""
        if user_email is None or not isinstance(user_email, str):
            return None
        if user_pwd is None or not isinstance(user_pwd, str):
            return None

        try:
            users = User.search({"email": user_email})
            if not users or users == []:
                return None
            for user in users:
                if user.is_valid_password(user_pwd):
                    return user
            return None
        except Exception:
            return None

    def current_user(self, request=None) -> TypeVar('User'):
        """Get the user from a request."""
        auth_header = self.authorization_header(request)
        if auth_header is not None:
            token_encoded = self.extract_base64_authorization_header(auth_header)
            if token_encoded is not None:
                decoded = self.decode_base64_authorization_header(token_encoded)
                if decoded is not None:
                    Email, Pwd = self.extract_user_credentials(decoded)
                    if Email is not None:
                        return self.user_object_from_credentials(
                            Email, Pwd)

        return
