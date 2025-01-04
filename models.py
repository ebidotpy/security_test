from sqlalchemy import Boolean, Integer, String, Column
from database import Base

class Vuln(Base):
    __tablename__ = 'vuln'

    id = Column(Integer, primary_key=True, index=True)
    title = Column(String)
    description = Column(String)
    severity = Column(String)
    cve = Column(String)
    sensor = Column(String)
    endpoint = Column(String)






