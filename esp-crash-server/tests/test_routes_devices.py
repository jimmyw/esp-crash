import helpers


def test_show_device_not_found(client):
    resp = client.get("/device/999999")
    assert resp.status_code == 400


def test_show_device_renders(client, db_conn):
    device_id = helpers.create_device(db_conn, "dev-show", alias="my-device")
    resp = client.get(f"/device/{device_id}")
    assert resp.status_code == 200
    assert b"my-device" in resp.data


def test_update_device_alias(client, db_conn):
    device_id = helpers.create_device(db_conn, "dev-update")
    resp = client.post(f"/device/{device_id}", data={"alias": "renamed"})
    assert resp.status_code == 200
    assert b"renamed" in resp.data

    with db_conn.cursor() as cur:
        cur.execute("SELECT alias FROM device WHERE device_id = %s", (device_id,))
        assert cur.fetchone()[0] == "renamed"
