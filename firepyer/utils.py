import csv
from itertools import zip_longest


def read_objects_csv(filename):
    """Takes a CSV with headings and converts each row to a dict. Useful for populating create_object()

    :param filename: Full filename of the CSV
    :type filename: str
    :return: A list of dicts, each dict is a row from the CSV, with the heading as key and column as value
    :rtype: list
    """
    objs = []
    with open(filename) as objects_csv:
        objects_dict = csv.DictReader(objects_csv)
        for obj in objects_dict:
            objs.append(obj)
    return objs


def read_groups_csv(filename):
    """Takes a CSV with headings in format: `name,objects,description` and converts each group to a dict.
    CSV file must be in hierarchical order if nested groups are to be created. Useful for populating create_group()

    :param filename: Full filename of the CSV
    :type filename: str
    :return: A list of dicts, each dict representing a group, with objects in the same group stored as list under the 'objects' key
    :rtype: list
    """
    with open(filename) as objects_csv:
        objects_dict = csv.DictReader(objects_csv)
        return dicts_to_groups(objects_dict)


def dicts_to_groups(objects_dict):
    groups = []
    for obj in objects_dict:

        group_exists = False
        for group in groups:
            if group['name'] == obj['name']:
                group['objects'].append(obj['objects'])
                group_exists = True
            else:
                continue

        if not group_exists:
            group = {'name': obj['name'],
                     'objects': [obj['objects']],
                     'description': obj['description']}
            groups.append(group)
    return groups


def expand_merged_csv(filename):
    """Takes a CSV that's had merged cells (to show a group in Excel) and fills the blanks with the previous row

    :param filename: Full filename of the CSV
    :type filename: str
    :return: A list of dicts, each dict is a row from the CSV, with the heading as key and column as value
    :rtype: list
    """
    groups = []
    with open(filename) as input_file:
        input_file = csv.reader(input_file)
        csv_headings = next(input_file)

        previous_row = []
        for row in input_file:
            if any(row):
                row = [a or b for a, b in zip_longest(row, previous_row, fillvalue='')]
            previous_row = row

            group = {}
            for i, heading in enumerate(csv_headings):
                group[heading] = row[i]
            groups.append(group)
    return groups
