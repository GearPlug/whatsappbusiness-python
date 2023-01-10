import hashlib
import hmac
from hashlib import sha256
from urllib.parse import urlencode, urlparse
from uuid import uuid4
import json
import requests

from whatsappbusiness import exceptions
from whatsappbusiness.decorators import access_token_required
from whatsappbusiness.enumerators import ErrorEnum


class Client(object):
    BASE_URL = "https://graph.facebook.com/"

    def __init__(
        self,
        app_id: str,
        app_secret: str,
        version: str = "v15.0",
        requests_hooks: dict = None,
        paginate: bool = True,
        limit: int = 100,
    ) -> None:
        self.app_id = app_id
        self.app_secret = app_secret
        if not version.startswith("v"):
            version = "v" + version
        self.version = version
        self.access_token = None
        self.paginate = paginate
        self.limit = limit
        self.BASE_URL += self.version
        if requests_hooks and not isinstance(requests_hooks, dict):
            raise Exception(
                'requests_hooks must be a dict. e.g. {"response": func}. http://docs.python-requests.org/en/master/user/advanced/#event-hooks'
            )
        self.requests_hooks = requests_hooks

    def set_access_token(self, token: str) -> None:
        """Sets the User Access Token for its use in this library.

        Args:
            token (str): User Access Token.
        """
        self.access_token = token

    def authorization_url(self, redirect_uri: str, state: str, scope: list = None) -> str:
        """Generates an Authorization URL.

        Args:
            redirect_uri (str): A string with the redirect_url set in the app config.
            state (str): A unique code for validation.
            scope (list, optional): A list of strings with the scopes. Defaults to None.

        Raises:
            Exception: Scope argument is not a list.

        Returns:
            str: Url for oauth.
        """
        if scope is None:
            scope = []
        if not isinstance(scope, list):
            raise Exception("scope argument must be a list")

        params = {
            "client_id": self.app_id,
            "redirect_uri": redirect_uri,
            "state": state,
            "scope": " ".join(scope),
            "response_type": "code",
        }
        url = "https://facebook.com/{}/dialog/oauth?".format(self.version) + urlencode(params)
        return url

    def exchange_code(self, redirect_uri: str, code: str) -> dict:
        """Exchanges an oauth code for an user token.

        Args:
            redirect_uri (str): A string with the redirect_url set in the app config.
            code (str): A string containing the code to exchange.

        Returns:
            dict: User token data.
        """
        params = {
            "client_id": self.app_id,
            "redirect_uri": redirect_uri,
            "client_secret": self.app_secret,
            "code": code,
        }
        return self._get("/oauth/access_token", params=params)

    def extend_token(self, token: str) -> dict:
        """Extends a short-lived User Token for a long-lived User Token.

        Args:
            token (str): User token to extend.

        Returns:
            dict: User token data.
        """
        params = {
            "grant_type": "fb_exchange_token",
            "client_id": self.app_id,
            "client_secret": self.app_secret,
            "fb_exchange_token": token,
        }
        return self._get("/oauth/access_token", params=params)

    def inspect_token(self, input_token: str, token: str) -> dict:
        """Inspects an User Access Token.

        Args:
            input_token (str): A string with the User Access Token to inspect.
            token (str): A string with the Developer Token (App Owner) or an Application Token.

        Returns:
            dict: User token data.
        """
        params = {"input_token": input_token, "access_token": token}
        return self._get("/debug_token", params=params)

    @access_token_required
    def get_business_manager_account_list(self) -> dict:
        """

        Returns:
            dict:
        """
        params = self._get_params()
        return self._get("/me/businesses", params=params)

    @access_token_required
    def get_shared_waba_list(self, business_id: str) -> dict:
        """

        Returns:
            dict:
        """
        params = self._get_params()
        return self._get(f"/{business_id}/client_whatsapp_business_accounts", params=params)

    @access_token_required
    def get_owned_waba_list(self, business_id: str) -> dict:
        """

        Returns:
            dict:
        """
        params = self._get_params()
        return self._get(f"/{business_id}/owned_whatsapp_business_accounts", params=params)

    @access_token_required
    def get_phone_mumbers_list(self, waba_id: str) -> dict:
        """

        Returns:
            dict:
        """
        params = self._get_params()
        return self._get(f"/{waba_id}/phone_numbers", params=params)


    @access_token_required
    def get_message_template_list(self, waba_id: str) -> dict:
        """

        Returns:
            dict:
        """
        params = self._get_params()
        return self._get(f"/{waba_id}/message_templates", params=params)

    @access_token_required
    def get_message_template(self, template_id: str) -> dict:
        """

        Returns:
            dict:
        """
        params = self._get_params()
        return self._get(f"/{template_id}", params=params)

    @access_token_required
    def get_template_namespace(self, waba_id: str) -> dict:
        """

        Returns:
            dict:
        """
        params = self._get_params()
        return self._get(f"/{waba_id}?fields=message_template_namespace", params=params)

    @access_token_required
    def send_message(self, phone_number_id: str, to: str) -> dict:
        """

        Returns:
            dict:
        """
        params = self._get_params()
        data = {
        "messaging_product": 'whatsapp',
        "to": to,
        "type": "template",
        "template": json.dumps({
                "name": "sample_purchase_feedback",
                "language": {
                    "code": "en_US",
                    "policy": "deterministic"
                },
                "components": [{
                    "type": "body",
                    "parameters": [
                        {
                            "type": "text",
                            "text": "Miguel, thank you for your purchase! We hope you enjoy your new shirt."
                        },
                        
                    ]
                }]
            })
        }
        return self._post(f"/{phone_number_id}/messages", params=params, data=data)


    def _get_params(self, token: str = None) -> dict:
        """Sets parameters for requests.

        Args:
            token (str, optional): Access token. Defaults to None.

        Returns:
            dict: Access token and hashed access token.
        """
        _token = token if token else self.access_token
        return {"access_token": _token, "appsecret_proof": self._get_app_secret_proof(_token)}

    def _get_app_secret_proof(self, token: str) -> str:
        """Generates app secret proof.

        https://developers.facebook.com/docs/graph-api/security

        Args:
            token (str): Access token to hash.

        Returns:
            str: Hashed access token.
        """
        key = self.app_secret.encode("utf-8")
        msg = token.encode("utf-8")
        h = hmac.new(key, msg=msg, digestmod=hashlib.sha256)
        return h.hexdigest()

    def _paginate_response(self, response: dict, **kwargs) -> dict:
        """Cursor-based Pagination

        https://developers.facebook.com/docs/graph-api/results

        Args:
            response (dict): Graph API Response.

        Returns:
            dict: Graph API Response.
        """
        if not self.paginate:
            return response
        while "paging" in response and "next" in response["paging"]:
            data = response["data"]
            params = kwargs.get("params", {})
            if "limit" in params:
                params.pop("limit")
            response = self._get(response["paging"]["next"].replace(self.BASE_URL, ""), **kwargs)
            response["data"] += data
        return response

    def _get(self, endpoint, **kwargs):
        return self._paginate_response(self._request("GET", endpoint, **kwargs), **kwargs)

    def _post(self, endpoint, **kwargs):
        return self._request("POST", endpoint, **kwargs)

    def _delete(self, endpoint, **kwargs):
        return self._request("DELETE", endpoint, **kwargs)

    def _request(self, method, endpoint, headers=None, **kwargs):
        _headers = {"Accept": "application/json", "Content-Type": "application/json"}
        if headers:
            _headers.update(headers)
        if self.requests_hooks:
            kwargs.update({"hooks": self.requests_hooks})
        return self._parse(requests.request(method, self.BASE_URL + endpoint, headers=_headers, **kwargs))

    def _parse(self, response):
        if "application/json" in response.headers["Content-Type"]:
            r = response.json()
        else:
            return response.text

        if "error" in r:
            error = r["error"]
        elif "data" in r and "error" in r["data"]:
            error = r["data"]["error"]
        else:
            error = None

        if error:
            code = error["code"]
            message = error["message"]
            try:
                error_enum = ErrorEnum(code)
            except Exception:
                raise exceptions.UnexpectedError("Error: {}. Message: {}".format(code, message))
            if error_enum == ErrorEnum.UnknownError:
                raise exceptions.UnknownError(message)
            elif error_enum == ErrorEnum.AppRateLimit:
                raise exceptions.AppRateLimitError(message)
            elif error_enum == ErrorEnum.AppPermissionRequired:
                raise exceptions.AppPermissionRequiredError(message)
            elif error_enum == ErrorEnum.UserRateLimit:
                raise exceptions.UserRateLimitError(message)
            elif error_enum == ErrorEnum.InvalidParameter:
                raise exceptions.InvalidParameterError(message)
            elif error_enum == ErrorEnum.SessionKeyInvalid:
                raise exceptions.SessionKeyInvalidError(message)
            elif error_enum == ErrorEnum.IncorrectPermission:
                raise exceptions.IncorrectPermissionError(message)
            elif error_enum == ErrorEnum.InvalidOauth20AccessToken:
                raise exceptions.PermissionError(message)
            elif error_enum == ErrorEnum.ExtendedPermissionRequired:
                raise exceptions.ExtendedPermissionRequiredError(message)
            else:
                raise exceptions.BaseError("Error: {}. Message {}".format(code, message))

        return r
