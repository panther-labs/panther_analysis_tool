import dataclasses
from typing import Any


@dataclasses.dataclass
class DictMergeConflict:
    key: str
    cust_val: Any
    latest_val: Any
    base_val: Any


class Dict:
    """
    A class to merge two dictionaries with a 3-way merge.
    """

    def __init__(self, customer_dict: dict):
        self.customer_dict = customer_dict

    def merge_dict(self, base_dict: dict, latest_dict: dict) -> list[DictMergeConflict]:
        """
        Merge the latest dict into the customer dict, using the base dict for a 3-way merge.

        Args:
            base_dict: The base dictionary.
            latest_dict: The latest dictionary.

        Returns:
            A list of DictMergeConflict objects. Each object contains the key, customer value, latest value,
            and base value for each key that has a merge conflict.
        """
        diff_keys = diff_dict_keys(self.customer_dict, latest_dict)

        for k, v in latest_dict.items():
            if k not in self.customer_dict:
                # if the key is in the latest dict but not in the customer dict, add it to the customer dict
                # with the latest value
                self.customer_dict[k] = v.strip() if isinstance(v, str) else v

        diff_items: list[DictMergeConflict] = []
        for key in diff_keys:
            cust_val = self.customer_dict[key] if key in self.customer_dict else None
            latest_val = latest_dict[key] if key in latest_dict else None
            base_val = base_dict[key] if key in base_dict else None

            if base_val == latest_val and base_val != cust_val:
                # customer value changed but latest did not, use customer value
                self.customer_dict[key] = cust_val
                continue
            elif base_val == cust_val and base_val != latest_val:
                # latest value changed but customer did not, use latest value
                self.customer_dict[key] = latest_val
                continue

            # customer and latest values changed, add to diff items to be resolved by the user
            diff_items.append(DictMergeConflict(key, cust_val, latest_val, base_val))

        return diff_items


def diff_dict_keys(dict1: dict, dict2: dict) -> list[str]:
    """
    Diff the keys of two dictionaries. A key counts as different if the values are in both dicts and are different.

    Args:
        dict1: The first dictionary.
        dict2: The second dictionary.

    Returns:
        A list of keys that are different between the two dictionaries and are in both dicts.
    """
    diff = []
    for key in dict1:
        if key in dict2 and dict1[key] != dict2[key]:
            diff.append(key)
    return diff
