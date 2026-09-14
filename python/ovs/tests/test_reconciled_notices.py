import collections
import uuid

import pytest

from ovs.db.idl import (
    Notice,
    ReconciledNotices,
    ROW_CREATE,
    ROW_DELETE,
    ROW_UPDATE,
    Row,
)


class FakeTable:
    def __init__(self, column_names):
        self.columns = {name: None for name in column_names}


class FakeDatum:
    """Minimal Datum-like object that supports equality comparison."""
    def __init__(self, value):
        self.value = value

    def __eq__(self, other):
        if isinstance(other, FakeDatum):
            return self.value == other.value
        return NotImplemented

    def __repr__(self):
        return "FakeDatum(%r)" % self.value


def make_row(table, row_uuid, data):
    return Row(None, table, row_uuid, data)


def make_notices(notice_list):
    """Build defaultdict(list) keyed by UUID from (uuid, Notice) pairs."""
    raw = collections.defaultdict(list)
    for row_uuid, notice in notice_list:
        raw[row_uuid].append(notice)
    return raw


TABLE = FakeTable(["name", "value", "tag"])


@pytest.mark.parametrize(
    "event",
    [ROW_CREATE, ROW_DELETE, ROW_UPDATE],
)
def test_single_event_passthrough(event):
    row_uuid = uuid.uuid4()
    row = make_row(TABLE, row_uuid, {"name": FakeDatum("r1")})
    if event == ROW_UPDATE:
        updates = make_row(TABLE, row_uuid, {"name": FakeDatum("old")})
        notice = Notice(event, row, updates)
    else:
        notice = Notice(event, row)
    raw = make_notices([(row_uuid, notice)])

    result = list(ReconciledNotices(raw))

    assert len(result) == 1
    assert result[0] is notice


@pytest.mark.parametrize(
    "old_data,new_data",
    [
        (
            {"name": FakeDatum("same")},
            {"name": FakeDatum("same")},
        ),
        (
            {"name": FakeDatum("n"), "value": FakeDatum(42),
             "tag": FakeDatum("t")},
            {"name": FakeDatum("n"), "value": FakeDatum(42),
             "tag": FakeDatum("t")},
        ),
    ],
)
def test_delete_create_unchanged_suppressed(old_data, new_data):
    row_uuid = uuid.uuid4()
    raw = make_notices([
        (row_uuid, Notice(ROW_DELETE,
                          make_row(TABLE, row_uuid, old_data))),
        (row_uuid, Notice(ROW_CREATE,
                          make_row(TABLE, row_uuid, new_data))),
    ])

    result = list(ReconciledNotices(raw))

    assert len(result) == 0


def test_delete_create_unchanged_getitem_returns_none():
    row_uuid = uuid.uuid4()
    data = {"name": FakeDatum("same")}
    raw = make_notices([
        (row_uuid, Notice(ROW_DELETE,
                          make_row(TABLE, row_uuid, dict(data)))),
        (row_uuid, Notice(ROW_CREATE,
                          make_row(TABLE, row_uuid, dict(data)))),
    ])

    assert ReconciledNotices(raw)[row_uuid] is None


@pytest.mark.parametrize(
    "old_data,new_data,expected_changed_cols",
    [
        (
            {"name": FakeDatum("old_val")},
            {"name": FakeDatum("new_val")},
            {"name"},
        ),
        (
            {"name": FakeDatum("n"), "value": FakeDatum(1),
             "tag": FakeDatum("t")},
            {"name": FakeDatum("n"), "value": FakeDatum(2),
             "tag": FakeDatum("t")},
            {"value"},
        ),
        (
            {"name": FakeDatum("a"), "value": FakeDatum(1)},
            {"name": FakeDatum("b"), "value": FakeDatum(2)},
            {"name", "value"},
        ),
    ],
)
def test_delete_create_changed_becomes_update(old_data, new_data,
                                              expected_changed_cols):
    row_uuid = uuid.uuid4()
    old_row = make_row(TABLE, row_uuid, old_data)
    new_row = make_row(TABLE, row_uuid, new_data)
    raw = make_notices([
        (row_uuid, Notice(ROW_DELETE, old_row)),
        (row_uuid, Notice(ROW_CREATE, new_row)),
    ])

    result = list(ReconciledNotices(raw))

    assert len(result) == 1
    notice = result[0]
    assert notice.event == ROW_UPDATE
    assert notice.row is new_row
    assert set(notice.updates._data.keys()) == expected_changed_cols
    for col in expected_changed_cols:
        assert notice.updates._data[col] == old_data[col]


def test_update_row_has_correct_uuid_and_table():
    row_uuid = uuid.uuid4()
    old_row = make_row(TABLE, row_uuid, {"name": FakeDatum("old")})
    new_row = make_row(TABLE, row_uuid, {"name": FakeDatum("new")})
    raw = make_notices([
        (row_uuid, Notice(ROW_DELETE, old_row)),
        (row_uuid, Notice(ROW_CREATE, new_row)),
    ])

    result = list(ReconciledNotices(raw))

    assert result[0].updates.uuid == row_uuid
    assert result[0].updates._table is TABLE


@pytest.mark.parametrize(
    "old_data,new_data",
    [
        (
            {"name": FakeDatum("n"), "value": FakeDatum("x")},
            {"name": FakeDatum("n")},
        ),
        (
            {"name": FakeDatum("n")},
            {"name": FakeDatum("n"), "value": FakeDatum("x")},
        ),
    ],
)
def test_column_only_in_one_row_not_compared(old_data, new_data):
    row_uuid = uuid.uuid4()
    raw = make_notices([
        (row_uuid, Notice(ROW_DELETE,
                          make_row(TABLE, row_uuid, old_data))),
        (row_uuid, Notice(ROW_CREATE,
                          make_row(TABLE, row_uuid, new_data))),
    ])

    result = list(ReconciledNotices(raw))

    assert len(result) == 0


def test_mixed_rows():
    uuid_new = uuid.uuid4()
    uuid_del = uuid.uuid4()
    uuid_unchanged = uuid.uuid4()
    uuid_changed = uuid.uuid4()

    row_new = make_row(TABLE, uuid_new, {"name": FakeDatum("new_row")})
    row_del = make_row(TABLE, uuid_del, {"name": FakeDatum("gone")})
    row_unch_old = make_row(TABLE, uuid_unchanged, {"name": FakeDatum("s")})
    row_unch_new = make_row(TABLE, uuid_unchanged, {"name": FakeDatum("s")})
    row_chg_old = make_row(TABLE, uuid_changed, {"name": FakeDatum("before")})
    row_chg_new = make_row(TABLE, uuid_changed, {"name": FakeDatum("after")})

    raw = make_notices([
        (uuid_new, Notice(ROW_CREATE, row_new)),
        (uuid_del, Notice(ROW_DELETE, row_del)),
        (uuid_unchanged, Notice(ROW_DELETE, row_unch_old)),
        (uuid_unchanged, Notice(ROW_CREATE, row_unch_new)),
        (uuid_changed, Notice(ROW_DELETE, row_chg_old)),
        (uuid_changed, Notice(ROW_CREATE, row_chg_new)),
    ])

    results = {n.row.uuid: n for n in ReconciledNotices(raw)}

    assert len(results) == 3
    assert results[uuid_new].event == ROW_CREATE
    assert results[uuid_del].event == ROW_DELETE
    assert results[uuid_changed].event == ROW_UPDATE
    assert uuid_unchanged not in results


def test_all_rows_suppressed():
    uuids = [uuid.uuid4() for _ in range(3)]
    raw = make_notices(
        [(u, Notice(ROW_DELETE, make_row(TABLE, u, {"name": FakeDatum("x")})))
         for u in uuids]
        + [(u, Notice(ROW_CREATE,
                      make_row(TABLE, u, {"name": FakeDatum("x")})))
           for u in uuids]
    )

    assert list(ReconciledNotices(raw)) == []


def test_empty_notices():
    assert list(ReconciledNotices(collections.defaultdict(list))) == []


def test_unexpected_event_count_asserts():
    row_uuid = uuid.uuid4()
    row = make_row(TABLE, row_uuid, {"name": FakeDatum("x")})
    raw = make_notices([
        (row_uuid, Notice(ROW_DELETE, row)),
        (row_uuid, Notice(ROW_CREATE, row)),
        (row_uuid, Notice(ROW_UPDATE, row)),
    ])

    with pytest.raises(AssertionError, match="unexpected number of events"):
        list(ReconciledNotices(raw))
