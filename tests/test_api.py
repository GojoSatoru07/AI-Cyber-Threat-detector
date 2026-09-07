def test_home_page_renders(client):
    response = client.get("/")
    assert response.status_code == 200
    assert b"AI Cyber Threat Detector" in response.data


def test_health(client):
    assert client.get("/health").get_json() == {"status": "ok"}


def test_train_without_dataset_returns_400(client):
    response = client.post("/api/train")
    assert response.status_code == 400
    assert "not found" in response.get_json()["error"]


def test_anomalies_before_training_returns_409(client, dataset):
    response = client.get("/api/anomalies")
    assert response.status_code == 409
    assert "train" in response.get_json()["error"].lower()


def test_full_train_then_detect_flow(client, dataset):
    train = client.post("/api/train")
    assert train.status_code == 200
    assert train.get_json()["rows_trained"] == 200

    detect = client.get("/api/anomalies")
    assert detect.status_code == 200
    payload = detect.get_json()
    assert payload["count"] >= 1
    assert payload["total_packets"] == 200
    assert "anomaly_score" in payload["anomalies"][0]


def test_limit_must_be_positive(client, dataset):
    assert client.get("/api/anomalies?limit=0").status_code == 400


def test_legacy_endpoints_still_work(client, dataset):
    assert client.post("/train").status_code == 200
    assert client.get("/anomalies").status_code == 200


def test_status_endpoint(client, dataset):
    payload = client.get("/api/status").get_json()
    assert payload["dataset_present"] is True
    assert payload["model_trained"] is False


def test_unknown_route_returns_json_404(client):
    response = client.get("/does-not-exist")
    assert response.status_code == 404
    assert "error" in response.get_json()


def test_wrong_method_returns_405_not_500(client):
    assert client.get("/api/train").status_code == 405
    assert client.post("/api/anomalies").status_code == 405


def test_errors_do_not_leak_absolute_paths(client, dataset):
    """The API is unauthenticated; responses must not disclose host paths."""
    body = client.post("/api/train").get_data(as_text=True)
    assert "/Users/" not in body and "/home/" not in body

    status = client.get("/api/status").get_json()
    assert not status["model_path"].startswith("/")
    assert not status["dataset_path"].startswith("/")

    missing = client.get("/api/status")  # sanity: still well-formed
    assert missing.status_code == 200


def test_summary_endpoint(client, dataset):
    assert client.get("/api/summary").status_code == 409  # not trained yet
    client.post("/api/train")

    payload = client.get("/api/summary").get_json()
    assert payload["total_packets"] == 200
    assert len(payload["score_histogram"]) == 24
    assert payload["protocols"][0]["flagged"] >= payload["protocols"][-1]["flagged"]
    assert payload["unit"] == "packets"
    assert payload["breakdown_label"] == "protocol"
