import json
import requests
from datetime import datetime
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import LabelEncoder
import pandas as pd
import hashlib
from email_services import EmailService


class BehaviorMonitor:
    """
    A class to monitor user login behavior, detect anomalies using Isolation Forest, and trigger email alerts.

    Attributes:
        behavior_file (str): Path to the JSON file storing user behavior data.
        behavior_data (dict): Dictionary holding user behavior logs.
        encoder (LabelEncoder): Encoder for categorical data (e.g., location).
        model (IsolationForest): Model for detecting abnormal behavior.
        email_service (EmailService): Service for sending email alerts.

    """

    def __init__(self, behavior_file="user_behavior.json"):
        """
        Initializes the BehaviorMonitor instance.

        Args:
            behavior_file (str): File path for storing behavior logs.

        """

        self.behavior_file = behavior_file
        self.behavior_data = self._load_data() # Load existing user behavior data
        self.encoder = LabelEncoder()
        self.model = self._train_anomaly_model() # Train anomaly detection model
        self.email_service = EmailService() # Initialize email alert system


    def _load_data(self):
        """
        Loads user behavior data from a JSON file.

        Returns:
            dict: The loaded behavior data. Returns an empty dictionary if the file is missing.

        """

        try:
            with open(self.behavior_file, "r") as file:
                return json.load(file)
        except FileNotFoundError:
            return {}

    def _save_data(self):
        """
        Saves the current behavior data to a JSON file.

        """

        with open(self.behavior_file, "w") as file:
            json.dump(self.behavior_data, file, indent=4)

    def _train_anomaly_model(self):
        """
        Trains an Isolation Forest model using stored behavior data.

        The model learns normal patterns from existing user login data and can
        identify anomalies in future logins that deviate from these patterns.

        Returns:
            IsolationForest: Trained anomaly detection model.

        """

        if not self.behavior_data:
            return IsolationForest(n_estimators=100, contamination=0.1, random_state=42)

        # Create a DataFrame from all stored login data across all users
        # This list comprehension loops through each user's login entries
        behavior_df = pd.DataFrame([
            {
                # Extract relevant numerical and categorical features for anomaly detection
                "login_hours": login["login_hour"],
                "day_of_week": login["day_of_week"],
                "failed_attempts": login["failed_attempts"],
                "hashed_ip": int(hashlib.sha256(login["ip_adress"].encode()).hexdigest()[:8], 16),
                "country_encoded": self.encoder.fit_transform([login["country"]]),
                "city_encoded": self.encoder.fit_transform([login["city"]]),
            }
            for user_logins in self.behavior_data.values()
            for login in user_logins["logins"]
        ])

        # Initialize the Isolation Forest model with specified parameters:
        # - n_estimators: number of base estimators (trees) in the ensemble
        # - contamination: expected proportion of anomalies in the dataset (10%)
        # - random_state: for reproducibility of results
        model = IsolationForest(n_estimators=100, contamination=0.1, random_state=42)

        # Train the model on the processed behavior data
        model.fit(behavior_df)

        return model

    def get_geolocation(self):
        """
        Retrieves geolocation information based on the current IP address.

        Uses an external API (ip-api.com) to determine the origin of the request.

        Returns:
            tuple: A tuple containing (ip_address, country, city) information.
                    Returns ("unknown", "unknown", "unknown") if the API call fails.
        """

        # Make API request to get geolocation data
        geo_loc = requests.get('http://ip-api.com/json')
        if geo_loc.status_code == 200:
            data = geo_loc.json()
            return data["query"], data["country"], data["city"]

        # Return fallback values if API call fails
        return "unknown", "unknown", "unknown"

    def track_login(self, email, failed_attempts):
        """
        Records a user login attempt and checks if it's suspicious.

        This method captures the login time, geolocation, and failed attempts count,
        adds this information to the user's behavior history, and then evaluates
        whether the login appears suspicious based on previous patterns.

        Args:
            email (str): The email address of the user logging in.
            failed_attempts (int): Number of failed login attempts before success.

        Returns:
            bool: True if the login is deemed suspicious, False otherwise.

        """

        # Get current timestamp
        login_time = datetime.now()

        # Get geolocation information for this login
        ip_address, country, city = self.get_geolocation()

        # Create login data dictionary with all relevant information
        login_data = {
            "login_time": login_time.isoformat(),
            "login_hour": login_time.hour,
            "day_of_week": login_time.weekday(),
            "ip_adress": ip_address,
            "country": country,
            "city": city,
            "failed_attempts": failed_attempts
        }

        # Create new entry for user if this is their first login
        if email not in self.behavior_data:
            self.behavior_data[email] = {"logins": []}

        # Add the new login data to user's history
        self.behavior_data[email]["logins"].append(login_data)
        self._save_data()

        # If login is suspicious, send alert through email service
        if self.is_suspicious(email):
            self.email_service.send_suspicious_login_alert(email, login_data)
            return True
        return False

    def is_suspicious(self, email):
        """
        Determines if the latest login for a given user is suspicious.

        Uses the trained Isolation Forest model to detect anomalies in login patterns.
        The model evaluates factors like login time, day of week, location, and
        failed attempts to identify potentially unauthorized access.

        Args:
            email (str): The email address of the user to check.

        Returns:
            bool: True if the latest login is flagged as suspicious, False otherwise.
                    Always returns False for users with no login history.

        """

        # Return false if user has no login history
        if email not in self.behavior_data:
            return False

        # Get user's login history
        recent_logins = self.behavior_data[email]["logins"]
        if not recent_logins:
            return False

        # Extract features from the most recent login
        latest_login = recent_logins[-1]

        # Prepare features in the format expected by the model
        latest_features = pd.DataFrame([{
            "login_hours": latest_login["login_hour"],
            "day_of_week": latest_login["day_of_week"],
            "failed_attempts": latest_login["failed_attempts"],
            "hashed_ip": int(hashlib.sha256(latest_login["ip_adress"].encode()).hexdigest(), 16),
            "country_encoded": self.encoder.fit_transform([latest_login["country"]]),
            "city_encoded": self.encoder.fit_transform([latest_login["city"]]),
        }])

        # Use the model to predict if login is an anomaly
        # Isolation Forest returns -1 for anomalies and 1 for normal data
        return self.model.predict(latest_features)[0] == -1
