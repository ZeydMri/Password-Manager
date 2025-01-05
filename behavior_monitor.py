import json
import requests
from datetime import datetime
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import LabelEncoder
import pandas as pd
from authenticator import Authenticator
import hashlib


class BehaviorMonitor:

    def __init__(self, behavior_file="user_behavior.json"):
        self.behavior_file = behavior_file
        self.behavior_data = self._load_data()
        self.model = self._train_anomaly_model()
        self.authenticator = Authenticator()
        self.encoder = LabelEncoder()

    def _load_data(self):

        try:
            with open(self.behavior_file, "r") as file:
                return json.load(file)
        except FileNotFoundError:
            return {}

    def _save_data(self):

        with open(self.behavior_file, "w") as file:
            json.dump(self.behavior_data, file)

    def _train_anomaly_model(self):

        if not self.behavior_data:
            return IsolationForest(n_estimators=100, contamination="auto", random_state=42)


        behavior_df = pd.DataFrame([
            {
                "login_hours": login["login_hour"],
                "day_of_week": login["day_of_week"],
                "failed_attempts": login["failed_attempts"],
                "hashed_ip": hashlib.sha256(login["ip_address"].encode()).hexdigest(),
                "country_encoded": self.encoder.fit_transform(login["country"]),
                "city_encoded": self.encoder.fit_transform(login["city"]),
            }
            for user_logins in self.behavior_data.values()
            for login in user_logins["logins"]
        ])
        model = IsolationForest(n_estimators=100, contamination="auto", random_state=42)
        model.fit(behavior_df)
        return model

    def get_geolocation(self):

        geo_loc = requests.get('http://ip-api.com/json')
        if geo_loc.status_code == 200:
            data = geo_loc.json()
            return data["query"], data["country"], data["city"]

        return None, None, None

    def track_login(self, username):
        login_time = datetime.now()
        failed_attempts = self.authenticator.failed_attempts.get(username, 0)
        ip_address, country, city = self.get_geolocation()

        login_data = {
            "login_time": login_time.isoformat(),
            "login_hour": login_time.hour,
            "day_of_week": login_time.weekday(),
            "ip_adress": ip_address,
            "country": country,
            "city": city,
            "failed_attempts": failed_attempts
        }

        if username not in self.behavior_data:
            self.behavior_data[username] = {"logins": []}

        self.behavior_data[username]["logins"].append(login_data)
        self._save_data()

    def is_suspicious(self, username):

        if username not in self.behavior_data:
            return False

        recent_logins = self.behavior_data[username]["logins"]
        behavior_df = pd.DataFrame(recent_logins)

        predictions = self.model.predict(behavior_df)

        if predictions == -1:
            return True