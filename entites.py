
import datetime
from typing import Optional

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
    root: list[ServerIdentity] = []

    def add(self, object): self.root.append(object)
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