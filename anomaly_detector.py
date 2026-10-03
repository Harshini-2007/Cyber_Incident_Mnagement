from sklearn.ensemble import IsolationForest


def extract_features(logs):
    """
    Convert raw MySQL logs into numerical features
    for each user.
    """

    user_features = {}

    for log in logs:

        user_id = log["user_id"]
        username = log.get("username")

        # Create feature record for a new user
        if user_id not in user_features:

            user_features[user_id] = {
                "user_id": user_id,
                "username": username,
                "total_events": 0,
                "failed_logins": 0,
                "file_downloads": 0,
                "file_accesses": 0,
                "profile_views": 0,
                "password_changes": 0,
                "unique_ips": set()
            }

        features = user_features[user_id]

        # Count total activity
        features["total_events"] += 1

        # Count different event types
        if log["event_type"] == "Failed Login":
            features["failed_logins"] += 1

        elif log["event_type"] == "File Download":
            features["file_downloads"] += 1

        elif log["event_type"] == "File Access":
            features["file_accesses"] += 1

        elif log["event_type"] == "Profile View":
            features["profile_views"] += 1

        elif log["event_type"] == "Password Change":
            features["password_changes"] += 1

        # Store IP address
        if log["ip_address"]:
            features["unique_ips"].add(log["ip_address"])

    # Convert IP sets into numbers
    for user_id in user_features:

        user_features[user_id]["unique_ips"] = len(
            user_features[user_id]["unique_ips"]
        )

    return list(user_features.values())


def detect_anomalies(features):
    """
    Run Isolation Forest on extracted user features.
    """

    # Need at least 2 users for comparison
    if len(features) < 2:
        return features

    # Numerical features used by the model
    feature_matrix = []

    for user in features:

        feature_matrix.append([
            user["total_events"],
            user["failed_logins"],
            user["file_downloads"],
            user["file_accesses"],
            user["profile_views"],
            user["password_changes"],
            user["unique_ips"]
        ])

    # Create Isolation Forest
    model = IsolationForest(
        n_estimators=100,
        contamination="auto",
        random_state=42
    )

    # Train the model
    model.fit(feature_matrix)

    # Predict
    predictions = model.predict(feature_matrix)

    # Calculate anomaly scores
    scores = model.decision_function(feature_matrix)

    # Add results
    for i, user in enumerate(features):

        if predictions[i] == -1:
            user["status"] = "Anomaly"
        else:
            user["status"] = "Normal"

        user["anomaly_score"] = round(
            float(scores[i]),
            4
        )

    return features