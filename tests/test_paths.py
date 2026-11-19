from cspm_collector.collectors.paths import extract, merge_pages


def test_extract_plain_nested_and_flatten():
    pages = [{"Buckets": [{"Name": "a"}], "Owner": {"ID": "o"}},
             {"Buckets": [{"Name": "b"}]}]
    assert extract(pages, "Buckets") == [{"Name": "a"}, {"Name": "b"}]
    assert extract(pages, "Owner") == [{"ID": "o"}]
    res = [{"Reservations": [{"Instances": [{"I": 1}, {"I": 2}]}, {"Instances": [{"I": 3}]}]}]
    assert extract(res, "Reservations[].Instances") == [{"I": 1}, {"I": 2}, {"I": 3}]


def test_extract_missing_key_is_empty():
    assert extract([{"A": 1}], "B") == []
    assert extract([{"A": None}], "A[].B") == []


def test_merge_pages():
    merged = merge_pages([{"Users": [1], "Marker": "m", "N": 1}, {"Users": [2], "N": 2}])
    assert merged == {"Users": [1, 2], "Marker": "m", "N": 1}
