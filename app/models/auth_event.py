"""Authentication event schema."""

from datetime import datetime
from typing import Annotated, Literal

from pydantic import BaseModel, ConfigDict, IPvAnyAddress, StringConstraints


NonEmptyString = Annotated[str, StringConstraints(strip_whitespace=True, min_length=1)]


class AuthenticationEvent(BaseModel):
    """A single authentication attempt."""

    model_config = ConfigDict(extra="forbid")

    timestamp: datetime
    user_id: NonEmptyString
    source_ip: IPvAnyAddress
    result: Literal["success", "failure"]
    service: NonEmptyString
