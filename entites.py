
import datetime
from itertools import chain
from typing import Iterator, Optional, Self

from pydantic import BaseModel, RootModel


class ServerIdentity(BaseModel):
    id: int
    country: str
    origin: str
    ip_v4: Optional[str] = None
    ip_v6: Optional[str] = None

    def __eq__(self, other):
        return other and self.id == other.id and self.origin == other.origin

    def __ne__(self, other):
        return not self.__eq__(other)

    def __hash__(self):
      return hash((self.id, self.origin))
    
class Servers(RootModel):
    root: set[ServerIdentity] = set()

    def add(self, object): self.root.add(object)
    def __len__(self): return len(self.root)

class Measure(BaseModel):
    id: int
    origin: str
    ground_truth: str 
    guess: Optional[str] = None
    ip_v4: Optional[str] = None
    ip_v6: Optional[str] = None
    latency: float
    hops: float
    count: int
    date_time: datetime.datetime = datetime.datetime.now()

class Measures(RootModel):
    root: list[Measure] = []

    def __iter__(self) -> Iterator[Measure]: # type: ignore
        return iter(self.root)

    def __getitem__(self, item):
        return self.root[item]
    
    def __add__(self, other: Self | list):
        if isinstance(other, Measures):
            return Measures(root=self.root + other.root)
        elif isinstance(other, list):
            return Measures(root=self.root + list(chain.from_iterable(other)))
    
    def append(self, measure: Measure):
        self.root.append(measure)