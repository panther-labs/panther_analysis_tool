from panther_analysis_tool.constants import AutoAcceptOption
from panther_analysis_tool.core import diff


def test_diff_dict_keys() -> None:
    dict1 = {"a": 1, "b": 2, "c": 3}
    dict2 = {"a": 1, "b": 3, "d": 4}
    diff_keys = diff.diff_dict_keys(dict1, dict2)
    assert diff_keys == ["b"]


def test_dict_diff() -> None:
    customer_dict = {"a": "customer", "b": "base", "new_customer": 3}
    latest_dict = {"a": "latest", "b": "base", "new_latest": 4}
    base_dict = {"a": "base", "b": "base", "did_exist_in_base": True}
    diff_items = diff.Dict(customer_dict=customer_dict).merge_dict(
        base_dict=base_dict, latest_dict=latest_dict
    )
    assert diff_items == [
        diff.DictMergeConflict("a", "customer", "latest", "base"),
    ]


def test_dict_diff_auto_accept_yours() -> None:
    customer_dict = {"a": "customer", "b": "base", "new_customer": 3}
    latest_dict = {"a": "latest", "b": "base", "new_latest": 4}
    base_dict = {"a": "base", "b": "base", "did_exist_in_base": True}
    diff_items = diff.Dict(
        customer_dict=customer_dict, auto_accept=AutoAcceptOption.YOURS
    ).merge_dict(base_dict=base_dict, latest_dict=latest_dict)
    assert diff_items == []


def test_dict_diff_auto_accept_panthers() -> None:
    customer_dict = {"a": "customer", "b": "base", "new_customer": 3}
    latest_dict = {"a": "latest", "b": "base", "new_latest": 4}
    base_dict = {"a": "base", "b": "base", "did_exist_in_base": True}
    diff_items = diff.Dict(
        customer_dict=customer_dict, auto_accept=AutoAcceptOption.PANTHERS
    ).merge_dict(base_dict=base_dict, latest_dict=latest_dict)
    assert diff_items == []


def test_dict_diff_customer_deleted_key_produces_conflict() -> None:
    """Keys in base and latest but removed by customer must be conflicts, not silently re-added."""
    base_dict = {"RemovedByCustomer": "base_val", "a": "base"}
    customer_dict = {"a": "customer"}  # customer removed RemovedByCustomer
    latest_dict = {"RemovedByCustomer": "latest_val", "a": "latest"}
    diff_items = diff.Dict(customer_dict=customer_dict).merge_dict(
        base_dict=base_dict, latest_dict=latest_dict
    )
    # Should have 2 conflicts: "a" (both changed) and "RemovedByCustomer" (customer deleted, latest has value)
    assert len(diff_items) == 2
    conflict_keys = {c.key for c in diff_items}
    assert "a" in conflict_keys
    assert "RemovedByCustomer" in conflict_keys
    removed_conflict = next(c for c in diff_items if c.key == "RemovedByCustomer")
    assert removed_conflict.cust_val is None
    assert removed_conflict.latest_val == "latest_val"
    assert removed_conflict.base_val == "base_val"
    # Customer dict must not have been silently updated with the removed key
    assert "RemovedByCustomer" not in customer_dict


def test_dict_diff_customer_deleted_key_auto_accept_yours_keeps_absent() -> None:
    """With auto_accept=YOURS, customer-deleted keys stay absent."""
    base_dict = {"RemovedByCustomer": "base_val"}
    customer_dict: dict = {}
    latest_dict = {"RemovedByCustomer": "latest_val"}
    diff.Dict(customer_dict=customer_dict, auto_accept=AutoAcceptOption.YOURS).merge_dict(
        base_dict=base_dict, latest_dict=latest_dict
    )
    assert "RemovedByCustomer" not in customer_dict


def test_dict_diff_customer_deleted_key_auto_accept_panthers_adds_key() -> None:
    """With auto_accept=PANTHERS, customer-deleted keys are re-added from latest."""
    base_dict = {"RemovedByCustomer": "base_val"}
    customer_dict: dict = {}
    latest_dict = {"RemovedByCustomer": "latest_val"}
    diff.Dict(customer_dict=customer_dict, auto_accept=AutoAcceptOption.PANTHERS).merge_dict(
        base_dict=base_dict, latest_dict=latest_dict
    )
    assert customer_dict["RemovedByCustomer"] == "latest_val"
