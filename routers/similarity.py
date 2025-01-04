
# Import necessary liberaries
import sys
sys.path.append("..")

from fastapi import Depends, HTTPException, APIRouter
import models
from database import engine, SessionLocal
from sqlalchemy.orm import Session
from utils.nltk_similarity import title_similarity

router = APIRouter(
    prefix="/similarity", 
    tags=["similarity"], 
    responses={404: {"description": "Not found"}}
)

# This code create database if doesn't exists
models.Base.metadata.create_all(bind=engine)

def get_db():
    try:
        db = SessionLocal()
        yield db
    except Exception as e:
        print(f"Error connecting to database: {e}")
        raise HTTPException(status_code=500, detail="Database connection error")
    finally:
        db.close()

# This router return all data in database table vuln
@router.get("/get_all_database")
async def read_all(db: Session = Depends(get_db)):
    return db.query(models.Vuln).all()


def similarity(alerts):
    """
        This function take all information of a table in database and group similar
        rows and return back the table in json format.

    Args:
        alerts (json): All information of special table in database.


    Returns:
        List[Dict]: It return a list contain all grouped column in dictionary format
    """
    try:
        titles = {} # "id": "title"
        cves = {} # "cve": "id"
        endpoints = {} # "endpoint": "id"
        tags = {} # "id": "tag"
        # Create a empty list for all grouped alerts
        grouped_alerts = [] # List[Dict]
        # Create a iteraror for group number
        i = 1

        for alert in alerts:
            try:
                tag = "group_1"
                if alert.endpoint in endpoints:
                    existing_id = endpoints[alert.endpoint]
                    if alert.cve is not None and existing_id in cves and cves[alert.cve] == existing_id:
                        tag = tags[existing_id]
                    elif title_similarity(titles.get(existing_id), alert.title) > 0.3:
                        tag = tags[existing_id]
                    else:
                        i += 1
                        tag = f"group_{i}"
                else:
                    i += 1
                    tag = f"group_{i}"

                titles[alert.id] = alert.title
                cves[alert.cve] = alert.id
                endpoints[alert.endpoint] = alert.id
                tags[alert.id] = tag

                grouped_alert = {
                    "title": alert.title,
                    "endpoint": alert.endpoint,
                    "tag": tag,
                    "cve": alert.cve,
                    "id": alert.id,
                    "description": alert.description,
                    "severity": alert.severity,
                    "sensor": alert.sensor,
                }
                grouped_alerts.append(grouped_alert)
            except Exception as e:
                print(f"Error processing alert: {e}")

        return grouped_alerts
    except Exception as e:
        print(f"Error in similarity function: {e}")
        raise HTTPException(status_code=500, detail="Error processing alerts")

@router.get("/vulnerabilities")
async def find_similarity(db: Session = Depends(get_db)):
    try:
        alerts = db.query(models.Vuln).all()
        return similarity(alerts=alerts)
    except Exception as e:
        print(f"Error fetching vulnerabilities: {e}")
        raise HTTPException(status_code=500, detail="Error fetching vulnerabilities from database")


