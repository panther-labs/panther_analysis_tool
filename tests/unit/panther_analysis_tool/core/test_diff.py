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
