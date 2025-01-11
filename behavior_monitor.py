import json
import requests
from datetime import datetime
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import LabelEncoder
import pandas as pd
import hashlib
from email_services import EmailService


class BehaviorMonitor:

    def __init__(self, behavior_file="user_behavior.json"):
        self.behavior_file = behavior_file
        self.behavior_data = self._load_data()
        self.encoder = LabelEncoder()
        self.model = self._train_anomaly_model()
        self.email_service = EmailService()


    def _load_data(self):

        try:
            with open(self.behavior_file, "r") as file:
                return json.load(file)
        except FileNotFoundError:
            return {}

    def _save_data(self):

        with open(self.behavior_file, "w") as file:
            json.dump(self.behavior_data, file, indent=4)

    def _train_anomaly_model(self):

        if not self.behavior_data:
            return IsolationForest(n_estimators=100, contamination=0.1, random_state=42)

        behavior_df = pd.DataFrame([
            {
                "login_hours": login["login_hour"],
                "day_of_week": login["day_of_week"],
                "failed_attempts": login["failed_attempts"],
                "hashed_ip": int(hashlib.sha256(login["ip_adress"].encode()).hexdigest(), 16),
                "country_encoded": self.encoder.fit_transform([login["country"]]),
                "city_encoded": self.encoder.fit_transform([login["city"]]),
            }
            for user_logins in self.behavior_data.values()
            for login in user_logins["logins"]
        ])
        model = IsolationForest(n_estimators=100, contamination=0.1, random_state=42)
        model.fit(behavior_df)
        return model

    def get_geolocation(self):

        geo_loc = requests.get('http://ip-api.com/json')
        if geo_loc.status_code == 200:
            data = geo_loc.json()
            return data["query"], data["country"], data["city"]

        return "unknown", "unknown", "unknown"

    def track_login(self, email):
        from authenticator import Authenticator

        login_time = datetime.now()
        failed_attempts = Authenticator().failed_attempts.get(email, 0)
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

        if email not in self.behavior_data:
            self.behavior_data[email] = {"logins": []}

        self.behavior_data[email]["logins"].append(login_data)
        self._save_data()

        # If login is suspicious, send alert through email service
        if self.is_suspicious(email):
            self.email_service.send_suspicious_login_alert(email, login_data)
            return True
        return False

    def is_suspicious(self, email):

        if email not in self.behavior_data:
            return False

        recent_logins = self.behavior_data[email]["logins"]
        if not recent_logins:
            return False

        latest_login = recent_logins[-1]
        latest_features = pd.DataFrame([{
            "login_hours": latest_login["login_hour"],
            "day_of_week": latest_login["day_of_week"],
            "failed_attempts": latest_login["failed_attempts"],
            "hashed_ip": int(hashlib.sha256(latest_login["ip_adress"].encode()).hexdigest(), 16),
            "country_encoded": self.encoder.fit_transform([latest_login["country"]]),
            "city_encoded": self.encoder.fit_transform([latest_login["city"]]),
        }])

        return self.model.predict(latest_features)[0] == -1