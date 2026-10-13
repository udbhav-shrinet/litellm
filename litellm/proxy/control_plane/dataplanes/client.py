"""One HTTP call to one dataplane: credential injection, timeout, bounded retry with jitter, failure as a value."""

import asyncio
import random
from collections.abc import Awaitable, Callable, Mapping
from dataclasses import dataclass
from typing import Final, Literal, Protocol, TypeAlias

import httpx
from pydantic import TypeAdapter

from litellm.proxy.control_plane.dataplanes.credentials import Caller, CredentialKind, CredentialUnavailable
from litellm.proxy.control_plane.dataplanes.registry import Dataplane

Method: TypeAlias = Literal["GET", "POST", "PUT", "PATCH", "DELETE"]
WRITE_METHODS: Final = frozenset({"POST", "PUT", "PATCH", "DELETE"})
Sleeper: TypeAlias = Callable[[float], Awaitable[None]]
RETRYABLE_STATUSES: Final = frozenset({502, 503, 504})
_JSON: Final = TypeAdapter(object)


class HttpTransport(Protocol):
    """The slice of AsyncHTTPHandler the client needs, so tests inject a fake."""

    async def get(
        self,
        url: str,
        *,
        params: dict[str, str] | None = None,  # mutable-ok: AsyncHTTPHandler.get takes dict
        headers: dict[str, str] | None = None,  # mutable-ok: AsyncHTTPHandler.get takes dict
        timeout: float | httpx.Timeout | None = None,
    ) -> httpx.Response: ...

    async def post(
        self,
        url: str,
        *,
        json: dict[str, object] | None = None,  # mutable-ok: AsyncHTTPHandler.post takes dict
        headers: dict[str, str] | None = None,  # mutable-ok: AsyncHTTPHandler.post takes dict
        timeout: float | httpx.Timeout | None = None,
    ) -> httpx.Response: ...

    async def put(
        self,
        url: str,
        *,
        json: dict[str, object] | None = None,  # mutable-ok: AsyncHTTPHandler.put takes dict
        params: dict[str, str] | None = None,  # mutable-ok: AsyncHTTPHandler.put takes dict
        headers: dict[str, str] | None = None,  # mutable-ok: AsyncHTTPHandler.put takes dict
        timeout: float | httpx.Timeout | None = None,
    ) -> httpx.Response: ...

    async def patch(
        self,
        url: str,
        *,
        json: dict[str, object] | None = None,  # mutable-ok: AsyncHTTPHandler.patch takes dict
        params: dict[str, str] | None = None,  # mutable-ok: AsyncHTTPHandler.patch takes dict
        headers: dict[str, str] | None = None,  # mutable-ok: AsyncHTTPHandler.patch takes dict
        timeout: float | httpx.Timeout | None = None,
    ) -> httpx.Response: ...

    async def delete(
        self,
        url: str,
        *,
        json: dict[str, object] | None = None,  # mutable-ok: AsyncHTTPHandler.delete takes dict
        params: dict[str, str] | None = None,  # mutable-ok: AsyncHTTPHandler.delete takes dict
        headers: dict[str, str] | None = None,  # mutable-ok: AsyncHTTPHandler.delete takes dict
        timeout: float | httpx.Timeout | None = None,
    ) -> httpx.Response: ...


@dataclass(frozen=True, slots=True)
class DataplaneReply:
    status: int
    body: object
    credential: CredentialKind


@dataclass(frozen=True, slots=True)
class DataplaneUnreachable:
    detail: str
    attempts: int


CallResult: TypeAlias = DataplaneReply | DataplaneUnreachable | CredentialUnavailable


@dataclass(frozen=True, slots=True)
class _RawReply:
    status: int
    body: object


@dataclass(frozen=True, slots=True)
class RetryPolicy:
    attempts: int = 3
    base_delay_seconds: float = 0.2
    max_delay_seconds: float = 2.0

    def delay(self, attempt: int, jitter: float) -> float:
        capped: Final = min(self.max_delay_seconds, self.base_delay_seconds * (2.0**attempt))
        return capped * (0.5 + jitter / 2)


def _parse_body(response: httpx.Response) -> object:
    try:
        return _JSON.validate_python(response.json())
    except ValueError:
        return response.text


@dataclass(frozen=True, slots=True)
class DataplaneClient:
    transport: HttpTransport
    timeout_seconds: float
    retry: RetryPolicy = RetryPolicy()
    sleep: Sleeper = asyncio.sleep
    jitter: Callable[[], float] = random.random

    async def get(
        self,
        dataplane: Dataplane,
        path: str,
        caller: Caller,
        params: Mapping[str, str] | None = None,
    ) -> CallResult:
        return await self._call("GET", dataplane, path, caller, params=params, json=None)

    async def post(self, dataplane: Dataplane, path: str, caller: Caller, json: Mapping[str, object]) -> CallResult:
        return await self._call("POST", dataplane, path, caller, params=None, json=json)

    async def request(
        self,
        method: Method,
        dataplane: Dataplane,
        path: str,
        caller: Caller,
        params: Mapping[str, str] | None = None,
        json: Mapping[str, object] | None = None,
    ) -> CallResult:
        """Any management verb. Only GET is retried, every write goes out exactly once."""
        return await self._call(method, dataplane, path, caller, params=params, json=json)

    async def _call(
        self,
        method: Method,
        dataplane: Dataplane,
        path: str,
        caller: Caller,
        params: Mapping[str, str] | None,
        json: Mapping[str, object] | None,
    ) -> CallResult:
        credential: Final = await dataplane.credential.headers(caller)
        if isinstance(credential, CredentialUnavailable):
            return credential
        url: Final = f"{dataplane.url}/{path.lstrip('/')}"
        attempts: Final = self.retry.attempts if method == "GET" else 1
        outcome: Final = await self._attempt(
            method, url, credential.headers, params, json, attempt=0, attempts=attempts
        )
        return (
            outcome
            if isinstance(outcome, DataplaneUnreachable)
            else DataplaneReply(outcome.status, outcome.body, credential.kind)
        )

    async def _attempt(
        self,
        method: Method,
        url: str,
        headers: Mapping[str, str],
        params: Mapping[str, str] | None,
        json: Mapping[str, object] | None,
        attempt: int,
        attempts: int,
    ) -> _RawReply | DataplaneUnreachable:
        outcome: Final = await self._send(method, url, headers, params, json)
        last: Final = attempt + 1 >= attempts
        if last or not _retryable(outcome):
            return outcome if isinstance(outcome, _RawReply) else DataplaneUnreachable(outcome.detail, attempt + 1)
        await self.sleep(self.retry.delay(attempt, self.jitter()))
        return await self._attempt(method, url, headers, params, json, attempt + 1, attempts)

    async def _send(
        self,
        method: Method,
        url: str,
        headers: Mapping[str, str],
        params: Mapping[str, str] | None,
        json: Mapping[str, object] | None,
    ) -> _RawReply | DataplaneUnreachable:
        try:
            response: Final = await self._dispatch(method, url, dict(headers), params, json)
        except httpx.HTTPStatusError as error:
            return _RawReply(error.response.status_code, _parse_body(error.response))
        except httpx.HTTPError as error:
            return DataplaneUnreachable(f"{type(error).__name__}: {error}", attempts=1)
        return _RawReply(response.status_code, _parse_body(response))

    async def _dispatch(
        self,
        method: Method,
        url: str,
        headers: dict[str, str],  # mutable-ok: the transport takes dict
        params: Mapping[str, str] | None,
        json: Mapping[str, object] | None,
    ) -> httpx.Response:
        query: Final = None if params is None else dict(params)
        body: Final = None if json is None else dict(json)
        timeout: Final = self.timeout_seconds
        match method:
            case "GET":
                return await self.transport.get(url, params=query, headers=headers, timeout=timeout)
            case "POST":
                return await self.transport.post(url, json=body, headers=headers, timeout=timeout)
            case "PUT":
                return await self.transport.put(url, json=body, params=query, headers=headers, timeout=timeout)
            case "PATCH":
                return await self.transport.patch(url, json=body, params=query, headers=headers, timeout=timeout)
            case "DELETE":
                return await self.transport.delete(url, json=body, params=query, headers=headers, timeout=timeout)


def _retryable(outcome: _RawReply | DataplaneUnreachable) -> bool:
    return isinstance(outcome, DataplaneUnreachable) or outcome.status in RETRYABLE_STATUSES
