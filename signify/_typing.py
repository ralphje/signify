import hashlib
from typing import Callable

from typing_extensions import TypeAlias

HashObject: TypeAlias = "hashlib._Hash"
HashFunction: TypeAlias = Callable[[], HashObject]
