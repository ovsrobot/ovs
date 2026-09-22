import uuid

import pytest

import ovs.db.idl


# Every column is optional (n_min == 0), so a row at its defaults arrives
# with no columns at all and __add_default() has nothing to inject.
SCHEMA = {
    "name": "idltest",
    "version": "1.0.0",
    "tables": {
        "optional": {
            "columns": {
                "s": {"type": {"key": "string", "min": 0, "max": 1}},
            },
        },
    },
}


@pytest.fixture
def idl():
    helper = ovs.db.idl.SchemaHelper(schema_json=SCHEMA)
    helper.register_all()
    return ovs.db.idl.Idl("unix:/nonexistent.sock", helper)


@pytest.mark.parametrize("row_update", [{}, {"s": "x"}])
@pytest.mark.parametrize("alert", [True, False])
def test_update2_insert_always_notifies(idl, row_update, alert):
    table = idl.tables["optional"]
    table.columns["s"].alert = alert
    row_uuid = uuid.uuid4()

    result, notice = idl._process_update2(table, row_uuid,
                                          {"insert": row_update})

    assert result == ovs.db.idl.OVSDB_IDL_UPDATE_DB_CHANGED
    assert notice == ovs.db.idl.Notice(ovs.db.idl.ROW_CREATE,
                                       table.rows[row_uuid])
